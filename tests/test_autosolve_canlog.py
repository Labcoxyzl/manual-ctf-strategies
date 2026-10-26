import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from scripts.autosolve_lib.profiles.canlog import parse_can_log


ROOT = Path(__file__).resolve().parents[1]


class CanLogTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "capture.log"

    def parse(self, *, max_frames=100, max_bytes=4096):
        return parse_can_log(self.source, max_frames=max_frames, max_bytes=max_bytes)

    def test_authored_candump_preserves_frames_and_epoch(self):
        source = ROOT / "examples/core/can-capture.txt"
        original = source.read_bytes()
        frames, warnings = parse_can_log(source, max_frames=10, max_bytes=4096)
        self.assertEqual(warnings, [])
        self.assertEqual(len(frames), 5)
        self.assertEqual([(row["bus"], row["can_id"], row["dlc"],
                           row["payload_hex"], row["frame_type"])
                          for row in frames], [
            ("can0", "123", 8, "0102030405060708", "data"),
            ("can0", "123", 8, "0102030405060709", "data"),
            ("can1", "1ABCDEFF", 3, "00A5FF", "data"),
            ("can0", "321", 4, "", "remote"),
            ("can1", "456", 0, "", "data"),
        ])
        self.assertEqual([row["source_line"] for row in frames], [1, 2, 3, 4, 5])
        self.assertEqual({row["timestamp_basis"] for row in frames}, {"unix_epoch"})
        self.assertEqual([Decimal(row["timestamp"]) - Decimal(frames[0]["timestamp"])
                          for row in frames],
                         [Decimal(x) for x in ("0", ".010", ".025", ".040", ".050")])
        self.assertTrue(frames[2]["extended"])
        self.assertFalse(frames[0]["extended"])
        self.assertEqual(source.read_bytes(), original)

    def test_asc_header_basis_and_declared_length_mismatch(self):
        source = ROOT / "examples/core/can-malformed.asc"
        frames, warnings = parse_can_log(source, max_frames=10, max_bytes=4096)
        self.assertEqual(len(frames), 4)
        self.assertEqual([row["source_line"] for row in frames], [4, 6, 7, 8])
        self.assertEqual([row["can_id"] for row in frames],
                         ["123", "1ABCDEFF", "321", "456"])
        self.assertEqual(frames[1]["bus"], "2")
        self.assertEqual(frames[0]["timestamp_basis"], "local_date_offset")
        self.assertEqual(frames[0]["date_header"], "Tue Nov 14 22:13:20 2023")
        self.assertEqual(frames[1]["timestamp"], "0.025000")
        self.assertTrue(any("line 5" in note and "length" in note for note in warnings))

    def test_heldout_fd_compact_asc_and_long_format(self):
        self.source.write_text(
            "(1700000000.000000001) vcan0 00000123##1AABBCCDD0011223344556677\n"
            "(1700000000.100000001) vcan0 123#R8\n"
            "(1700000000.200000001) vcan1 456   [2]  0A F0  '..'\n"
            "date Tue Nov 14 22:13:20 2023\n"
            "base hex  timestamps relative\n"
            "no internal events logged\n"
            "0.010000 CANFD 1 Rx 1ABCDEFFx 1 0 9 12 00 01 02 03 04 05 06 07 08 09 0A 0B 0 0 2000 0 0 0 0 0\n"
            "0.020000 2 2A Tx d 0\n"
        )
        frames, warnings = self.parse()
        self.assertEqual(warnings, [])
        self.assertEqual(len(frames), 5)
        self.assertEqual((frames[0]["frame_type"], frames[0]["dlc"],
                          frames[0]["dlc_basis"], frames[0]["payload_length"]),
                         ("fd", 9, "inferred_from_length", 12))
        self.assertEqual((frames[0]["can_id"], frames[0]["fd_flags"]), ("00000123", 1))
        self.assertEqual(frames[2]["payload_hex"], "0AF0")
        self.assertEqual((frames[3]["frame_type"], frames[3]["dlc"],
                          frames[3]["payload_length"], frames[3]["fd_flags"]),
                         ("fd", 9, 12, 1))
        self.assertEqual(frames[3]["timestamp_basis"], "relative_delta")
        self.assertEqual(frames[4]["timestamp"], "0.020000")
        self.assertEqual(frames[4]["can_id"], "02A")

    def test_bad_rows_limits_and_unsafe_sources_are_reported(self):
        self.source.write_text(
            "(1.0) can0 123#01\n"
            "(1.1) can0 123#0G\n"
            "(1.2) can0 800#01\n"
            "(1.3) can0 123##1A\n"
            "(1.4) can0 123#0.1\n"
            "(1.5) can0 123#02\n"
        )
        frames, warnings = self.parse()
        self.assertEqual([row["payload_hex"] for row in frames], ["01", "02"])
        self.assertEqual(len(warnings), 4)
        self.assertTrue(all(f"line {line}" in warnings[index]
                            for index, line in enumerate((2, 3, 4, 5))))
        limited, warnings = self.parse(max_frames=1)
        self.assertEqual(len(limited), 1)
        self.assertTrue(any("frame limit" in note for note in warnings))
        self.assertEqual(self.parse(max_bytes=2)[0], [])
        self.assertTrue(any("byte limit" in note for note in self.parse(max_bytes=2)[1]))
        with self.assertRaisesRegex(ValueError, "nonnegative"):
            self.parse(max_frames=-1)
        symlink = self.root / "link.log"
        symlink.symlink_to(self.source)
        with self.assertRaises(OSError):
            parse_can_log(symlink, max_frames=10, max_bytes=4096)

    def test_decimal_asc_fd_length_and_unknown_timezone(self):
        self.source.write_text(
            "date Tue Nov 14 22:13:20 2023\n"
            "base dec timestamps absolute\n"
            "0.000001 1 291 Rx d 2 0 255\n"
            "0.000002 CANFD 1 Rx 291 0 0 9 12 0 1 2 3 4 5 6 7 8 9 10 11\n"
            "0.000003 CANFD 1 Rx 291 0 0 9 11 0 1 2 3 4 5 6 7 8 9 10\n"
            "0.000004 1 291 Rx d 2 0\n"
        )
        frames, warnings = self.parse()
        self.assertEqual([(row["can_id"], row["payload_hex"])
                          for row in frames], [("123", "00FF"),
                                               ("123", "000102030405060708090A0B")])
        self.assertEqual([row["source_line"] for row in frames], [3, 4])
        self.assertEqual([row["timestamp_basis"] for row in frames],
                         ["local_date_offset", "local_date_offset"])
        self.assertTrue(all(row["date_header"] == "Tue Nov 14 22:13:20 2023"
                            for row in frames))
        self.assertEqual(len(warnings), 2)
        self.assertIn("line 5", warnings[0])
        self.assertIn("line 6", warnings[1])

    def test_unstamped_candump_does_not_invent_time(self):
        self.source.write_text('vcan0 123#0102\nvcan1 1ABCDEFF [2] AA BB\n')
        frames, warnings = self.parse()
        self.assertEqual(warnings, [])
        self.assertEqual([row['payload_hex'] for row in frames], ['0102', 'AABB'])
        self.assertTrue(all(row['timestamp'] is None and row['timestamp_basis'] == 'unknown'
                            and row['format'] == 'candump_unstamped' for row in frames))


if __name__ == "__main__":
    unittest.main()
