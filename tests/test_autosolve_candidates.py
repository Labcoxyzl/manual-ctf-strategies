"""Independent raw-byte candidate positions and bounded streaming checks."""

import tempfile
import time
import unittest
from pathlib import Path

from scripts.autosolve_lib.candidates import CHUNK, scan_candidates


class CandidateScanTests(unittest.TestCase):
    def scan(self, source, patterns, **kwargs):
        return scan_candidates(source, 'source-id', patterns, time.monotonic() + 8, **kwargs)

    def test_matches_across_chunk_boundary_without_duplicate_location(self):
        source = b'\x00' * (CHUNK - 2) + b'HELLO' + b'\x00' * CHUNK
        findings, warnings = self.scan(source, ['HELLO'])
        self.assertEqual(warnings, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['locations'], [CHUNK - 2])
        self.assertEqual(findings[0]['source_locator'], {'offset': CHUNK - 2})
        self.assertEqual(findings[0]['match_bytes'], 5)

    def test_repeated_value_keeps_distinct_locations(self):
        findings, warnings = self.scan(b'FLAG FLAG FLAG', ['FLAG'])
        self.assertEqual(warnings, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['locations'], [0, 5, 10])
        self.assertEqual(findings[0]['encoding'], 'raw bytes')

    def test_end_anchor_applies_to_file_not_chunk(self):
        source = b'\x00' * (CHUNK - 3) + b'END' + b'\x00' * CHUNK + b'END'
        findings, warnings = self.scan(source, ['END$'])
        self.assertEqual(warnings, [])
        self.assertEqual(findings[0]['locations'], [len(source) - 3])

    def test_fixed_width_lookbehind_crosses_boundary_with_limit_disclosed(self):
        source = b'x' * (CHUNK - 2) + b'ABC\x00'
        findings, warnings = self.scan(source, ['(?<=AB)C'])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['locations'], [CHUNK])
        self.assertTrue(any('lookbehind beyond 4095' in warning for warning in warnings))

    def test_large_file_limit_is_explicit_and_does_not_read_later_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'large.bin'
            path.write_bytes(b'\x00' * CHUNK + b'LATE_MARKER')
            findings, warnings = self.scan(path, ['LATE_MARKER'], max_scan=CHUNK)
            self.assertEqual(findings, [])
            self.assertTrue(any(f'first {CHUNK}' in warning for warning in warnings))

    def test_zero_width_patterns_never_become_candidates(self):
        for pattern in ('', '^', '(?=A)'):
            with self.subTest(pattern=pattern):
                findings, warnings = self.scan(b'ABC', [pattern])
                self.assertEqual(findings, [])
                self.assertIn('zero-width pattern matches were skipped', warnings)


if __name__ == '__main__':
    unittest.main()
