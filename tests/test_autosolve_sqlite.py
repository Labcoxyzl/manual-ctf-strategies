import base64
import hashlib
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib.profiles.sqlite import inspect_sqlite


class SqliteInspectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "evidence.db"
        self.output = self.root / "staged"

    def inspect(self, max_rows=20, max_bytes=100_000):
        return inspect_sqlite(self.source, self.output, max_rows=max_rows,
                              max_bytes=max_bytes)

    @staticmethod
    def items(records, kind):
        return [json.loads(record["path"].read_bytes())
                for record in records if record["kind"] == kind]

    def test_committed_wal_only_row_and_originals_are_preserved(self):
        connection = sqlite3.connect(self.source)
        self.addCleanup(connection.close)
        self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE messages (message TEXT, payload BLOB)")
        connection.commit()
        connection.execute("INSERT INTO messages VALUES (?, ?)", ("café", b"\x00\xff"))
        connection.commit()
        self.assertTrue(Path(str(self.source) + "-wal").exists())
        originals = {item.name: hashlib.sha256(item.read_bytes()).hexdigest()
                     for item in self.root.iterdir() if item.is_file()}

        records, warnings = self.inspect()
        self.assertEqual(warnings, [])
        self.assertEqual([item["name"] for item in self.items(records, "schema")], ["messages"])
        self.assertEqual(self.items(records, "row"), [{
            "table": "messages", "rowid": 1, "primary_key": None,
            "values": {"message": "café", "payload": {
                "type": "blob", "base64": base64.b64encode(b"\x00\xff").decode()}}}])
        self.assertTrue(all(record["source_table"] == "messages" for record in records))
        for record in records:
            data = record["path"].read_bytes()
            self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(record["size"], len(data))
            self.assertEqual(record["path"].parent, self.output)
        self.assertEqual(originals, {item.name: hashlib.sha256(item.read_bytes()).hexdigest()
                                     for item in self.root.iterdir() if item.is_file()})
        self.assertEqual(set(self.output.iterdir()), {item["path"] for item in records})

    def test_held_out_page_size_without_rowid_and_unusual_identifiers(self):
        name = 'quotes"; DROP TABLE keep; --'
        with sqlite3.connect(self.source) as connection:
            connection.execute("PRAGMA page_size=8192")
            connection.execute("CREATE TABLE keep (value TEXT)")
            connection.execute("CREATE TABLE generated (n INTEGER, doubled INTEGER GENERATED ALWAYS AS (n * 2) STORED)")
            connection.execute(f'CREATE TABLE "{name.replace(chr(34), chr(34) * 2)}" '
                               '(key TEXT PRIMARY KEY, payload BLOB) WITHOUT ROWID')
            connection.execute(f'INSERT INTO "{name.replace(chr(34), chr(34) * 2)}" VALUES (?, ?)',
                               ("α", b"\x00\x01"))
            connection.execute("INSERT INTO keep VALUES ('intact')")
            connection.execute("INSERT INTO generated (n) VALUES (7)")
        records, warnings = self.inspect()
        self.assertEqual(warnings, [])
        self.assertEqual({item["name"] for item in self.items(records, "schema")},
                         {name, "keep", "generated"})
        rows = self.items(records, "row")
        self.assertEqual(next(item for item in rows if item["table"] == name), {
            "table": name, "rowid": None, "primary_key": {"key": "α"},
            "values": {"key": "α", "payload": {"type": "blob", "base64": "AAE="}}})
        self.assertEqual(next(item for item in rows if item["table"] == "keep")["values"],
                         {"value": "intact"})
        self.assertEqual(next(item for item in rows if item["table"] == "generated")["values"],
                         {"n": 7, "doubled": 14})

    def test_missing_wal_is_reported_without_inventing_rows(self):
        live = self.root / "live.db"
        connection = sqlite3.connect(live)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE hidden (value TEXT)")
        connection.commit()
        connection.execute("INSERT INTO hidden VALUES ('WAL only')")
        connection.commit()
        shutil.copyfile(live, self.source)
        records, warnings = self.inspect()
        self.assertTrue(any("no -wal companion" in warning for warning in warnings))
        self.assertEqual(self.items(records, "row"), [])

    def test_missing_shm_is_rebuilt_on_private_copy(self):
        live = self.root / "live.db"
        connection = sqlite3.connect(live)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE t (value TEXT)")
        connection.commit()
        connection.execute("INSERT INTO t VALUES ('committed')")
        connection.commit()
        shutil.copyfile(live, self.source)
        shutil.copyfile(Path(str(live) + "-wal"), Path(str(self.source) + "-wal"))
        records, warnings = self.inspect()
        self.assertEqual([item["values"] for item in self.items(records, "row")],
                         [{"value": "committed"}])
        self.assertTrue(any("-shm companion missing" in warning for warning in warnings))
        self.assertFalse(Path(str(self.source) + "-shm").exists())

    def test_invalid_text_and_locked_uncommitted_row(self):
        connection = sqlite3.connect(self.source)
        self.addCleanup(connection.close)
        connection.execute("CREATE TABLE t (value TEXT)")
        connection.execute("INSERT INTO t VALUES (CAST(X'FF' AS TEXT))")
        connection.commit()
        connection.execute("BEGIN EXCLUSIVE")
        connection.execute("INSERT INTO t VALUES ('uncommitted')")
        records, warnings = self.inspect()
        self.assertEqual(warnings, [])
        self.assertEqual(self.items(records, "row"), [{
            "table": "t", "rowid": 1, "primary_key": None,
            "values": {"value": {"type": "text", "base64": "/w=="}}}])
        connection.rollback()

    def test_changed_source_snapshot_is_rejected(self):
        with sqlite3.connect(self.source) as connection:
            connection.execute("CREATE TABLE t (value TEXT)")
        real_open = __import__("os").open
        source_opens = 0

        def change_before_validation(file, flags, *args, **kwargs):
            nonlocal source_opens
            if Path(file) == self.source:
                source_opens += 1
                if source_opens == 2:
                    with self.source.open("ab") as target:
                        target.write(b"changed")
            return real_open(file, flags, *args, **kwargs)

        with patch("scripts.autosolve_lib.profiles.sqlite.os.open",
                   side_effect=change_before_validation):
            records, warnings = self.inspect()
        self.assertEqual(records, [])
        self.assertTrue(any("changed during snapshot" in warning for warning in warnings))
        self.assertEqual(list(self.output.iterdir()), [])

    def test_evidence_byte_budget_is_reported_once(self):
        with sqlite3.connect(self.source) as connection:
            connection.execute("CREATE TABLE t (value TEXT)")
            connection.executemany("INSERT INTO t VALUES (?)", [(str(i),) for i in range(200)])
        records, warnings = self.inspect(max_rows=200, max_bytes=self.source.stat().st_size)
        self.assertTrue(any("evidence byte limit" in warning for warning in warnings))
        self.assertEqual(sum(record["size"] for record in records) <= self.source.stat().st_size, True)
        self.assertEqual(sum("evidence byte limit" in warning for warning in warnings), 1)

    def test_corrupt_input_limits_and_output_guard(self):
        self.source.write_bytes(b"not sqlite")
        records, warnings = self.inspect()
        self.assertEqual(records, [])
        self.assertTrue(any("parse failed" in warning for warning in warnings))
        self.source.unlink()
        with sqlite3.connect(self.source) as connection:
            connection.execute("CREATE TABLE t (value TEXT)")
            connection.executemany("INSERT INTO t VALUES (?)", [(str(i),) for i in range(3)])
        records, warnings = self.inspect(max_rows=1)
        self.assertEqual(len(self.items(records, "row")), 1)
        self.assertTrue(any("row limit" in warning for warning in warnings))
        for record in records:
            record["path"].unlink()
        records, warnings = self.inspect(max_bytes=self.source.stat().st_size - 1)
        self.assertEqual(records, [])
        self.assertTrue(any("input byte limit" in warning for warning in warnings))
        self.output.rmdir()
        self.output.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.inspect()
        with self.assertRaisesRegex(ValueError, "differ from source"):
            inspect_sqlite(self.source, self.root, max_rows=1, max_bytes=100_000)
        with self.assertRaisesRegex(ValueError, "nonnegative"):
            self.inspect(max_rows=-1)


if __name__ == "__main__":
    unittest.main()
