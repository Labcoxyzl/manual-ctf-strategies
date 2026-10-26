import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib.profiles.office import inspect_office


OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class OfficeInspectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "input.docm"
        self.output = self.root / "stage"

    def inspect(self, *, max_parts=16, max_total_bytes=4096):
        return inspect_office(self.source, self.output, max_parts=max_parts,
                              max_total_bytes=max_total_bytes)

    def make_ooxml(self, entries):
        with zipfile.ZipFile(self.source, "w") as archive:
            archive.writestr("[Content_Types].xml", b"<Types/>")
            for name, data in entries:
                archive.writestr(name, data)

    def test_embedded_part_is_exact_and_source_unchanged(self):
        payload = b"EMBEDDED\x00\xff"
        self.make_ooxml([("word/embeddings/object1.bin", payload),
                         ("word/media/image.png", b"not an embedded object")])
        original = self.source.read_bytes()
        records, found_warnings = self.inspect()
        self.assertEqual(found_warnings, [])
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["kind"], "embedded_object")
        self.assertEqual(record["member"], "word/embeddings/object1.bin")
        self.assertEqual(record["index"], 1)
        self.assertEqual(record["locator"], "member 1 ('word/embeddings/object1.bin')")
        self.assertEqual(record["path"].read_bytes(), payload)
        self.assertEqual(record["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(set(self.output.iterdir()), {record["path"]})

    def test_macro_free_and_non_office_zip_are_negative(self):
        self.make_ooxml([("word/document.xml", b"<document/>")])
        self.assertEqual(self.inspect(), ([], []))
        self.source.unlink()
        with zipfile.ZipFile(self.source, "w") as archive:
            archive.writestr("word/embeddings/object.bin", b"lookalike")
        self.assertEqual(self.inspect(), ([], []))

    def test_macro_source_locator_is_bound_to_project_member(self):
        self.make_ooxml([("word/vbaProject.bin", OLE_MAGIC + b"project")])
        class Parser:
            def __init__(self, filename, data):
                self.assertion = (filename, data)
            def extract_macros(self):
                yield ("VBA/Module1", "VBA/Module1", "Module1.bas", "Sub AutoOpen()\nEnd Sub\n")
            def close(self):
                pass
        with patch("oletools.olevba.VBA_Parser", Parser):
            records, found_warnings = self.inspect()
        self.assertEqual(found_warnings, [])
        self.assertEqual([record["kind"] for record in records],
                         ["vba_project", "macro_source"])
        self.assertEqual(records[1]["path"].read_bytes(), b"Sub AutoOpen()\nEnd Sub\n")
        self.assertEqual(records[1]["stream"], "VBA/Module1")
        self.assertEqual(records[1]["module"], "Module1.bas")
        self.assertIn("member 1 ('word/vbaProject.bin')", records[1]["locator"])
        self.assertIn("stream VBA/Module1 module Module1.bas", records[1]["locator"])

    def test_invalid_vba_project_is_not_falsely_reported_as_macro_source(self):
        self.make_ooxml([("word/vbaProject.bin", b"Sub Fake()")])
        records, found_warnings = self.inspect()
        self.assertEqual([record["kind"] for record in records], ["vba_project"])
        self.assertIn("not an OLE container", found_warnings[0])

    def test_unsafe_paths_and_limits_skip_without_partial_evidence(self):
        self.make_ooxml([("word/embeddings/../escape.bin", b"bad"),
                         ("word/embeddings/huge.bin", b"A" * 128),
                         ("word/embeddings/small.bin", b"ok")])
        records, found_warnings = self.inspect(max_total_bytes=8)
        self.assertEqual([record["member"] for record in records],
                         ["word/embeddings/small.bin"])
        self.assertTrue(any("unsafe path" in item for item in found_warnings))
        self.assertTrue(any("decoded byte limit" in item for item in found_warnings))
        self.assertFalse((self.root / "escape.bin").exists())
        self.assertEqual(set(self.output.iterdir()), {records[0]["path"]})
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.output.rename(self.root / "old-stage")
            self.output.symlink_to(self.root, target_is_directory=True)
            self.inspect()

    def test_duplicate_member_names_keep_distinct_indices(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            self.make_ooxml([("xl/embeddings/same.bin", b"first"),
                             ("xl/embeddings/same.bin", b"second")])
        records, found_warnings = self.inspect()
        self.assertEqual(found_warnings, [])
        self.assertEqual([(record["index"], record["path"].read_bytes())
                          for record in records], [(1, b"first"), (2, b"second")])

    def test_repository_rtf_package_recovers_exact_object_bytes(self):
        example = (Path(__file__).resolve().parents[1] / "research" / "learning" /
                   "video-coverage" / "practice" / "embedded-note.rtf")
        self.source.write_bytes(example.read_bytes())
        records, found_warnings = self.inspect()
        self.assertEqual(found_warnings, [])
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["kind"], "embedded_object")
        self.assertEqual(record["path"].read_bytes(), b"hello from study\n")
        self.assertEqual(record["sha256"],
                         hashlib.sha256(b"hello from study\n").hexdigest())
        self.assertEqual((record["offset"], record["end"]), (58, 239))

    def test_public_cli_ooxml_and_rtf_preserve_lineage_on_resume(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "autosolve.py"
        self.make_ooxml([("word/embeddings/object.bin", b"OFFICE{OBJECT}")])
        rtf = self.root / "object.rtf"
        example = (Path(__file__).resolve().parents[1] / "research" / "learning" /
                   "video-coverage" / "practice" / "embedded-note.rtf")
        rtf.write_bytes(example.read_bytes())
        for source, payload in ((self.source, b"OFFICE{OBJECT}"),
                                (rtf, b"hello from study\n")):
            with self.subTest(source=source.name):
                before = source.read_bytes()
                result = subprocess.run(
                    [sys.executable, '-B', str(script), '--json', 'analyze', str(source),
                     '--category', 'documents', '--runs-root', str(self.root / 'runs')],
                    capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
                run = Path(json.loads(result.stdout)['run'])
                manifest = json.loads((run / 'manifest.json').read_text())
                self.assertEqual(manifest['coverage']['DOC05']['status'], 'ran')
                children = [item for item in manifest['artifacts'] if item['depth'] > 0
                            and item['current'] and Path(item['path']).read_bytes() == payload]
                self.assertTrue(children)
                office_jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'office']
                self.assertTrue(any(job['status'] == 'complete' for job in office_jobs))
                self.assertTrue(any(edge.get('job_key') == office_jobs[0]['key']
                                    for item in children for edge in item['parents']))
                self.assertEqual(source.read_bytes(), before)
                resume = subprocess.run(
                    [sys.executable, '-B', str(script), '--json', 'resume', str(run)],
                    capture_output=True, timeout=20)
                self.assertEqual(resume.returncode, 3, resume.stderr + resume.stdout)
                resumed = json.loads((run / 'manifest.json').read_text())
                self.assertEqual(len([job for job in resumed['jobs']
                                      if job['adapter_id'] == 'office']), len(office_jobs))
                self.assertEqual(resumed['coverage']['DOC05']['status'], 'ran')
                source.write_bytes(b'changed source')
                changed = subprocess.run(
                    [sys.executable, '-B', str(script), '--json', 'resume', str(run)],
                    capture_output=True, timeout=20)
                self.assertEqual(changed.returncode, 3, changed.stderr + changed.stdout)
                retired = json.loads((run / 'manifest.json').read_text())
                self.assertTrue(all(not item['current'] for item in retired['artifacts']
                                    if item['id'] in {child['id'] for child in children}))


if __name__ == "__main__":
    unittest.main()
