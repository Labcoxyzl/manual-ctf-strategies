"""Exercise published command steps on disposable benign fixtures; never challenge files."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]


def fixtures(directory):
    (directory / "data.json").write_text('{"key":"fixture_value","nested":{"number":7}}')
    (directory / "record.bin").write_bytes(struct.pack("<I", 305419896))
    (directory / "invalid.json").write_text('{invalid')
    (directory / "invalid.bin").write_bytes(b"not an archive")
    evidence = directory / "evidence-dir"
    evidence.mkdir()
    (evidence / "notes.txt").write_text("irrelevant\na needle clue\n")
    with zipfile.ZipFile(directory / "artifact.bin", "w") as archive:
        archive.writestr("note.txt", "benign archive fixture\n")
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    png += chunk(b"tEXt", b"Comment\x00benign_metadata_marker")
    png += chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b"")
    (directory / "image.png").write_bytes(png)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="Refresh recipe-validation.md after success")
    args = parser.parse_args()
    route_path = ROOT / "research/routes.json"
    route_bytes = route_path.read_bytes()
    data = json.loads(route_bytes)
    routes = {route["id"]: route for route in data}
    results = []
    with tempfile.TemporaryDirectory(prefix="guide-recipes-") as temporary:
        directory = Path(temporary)
        fixtures(directory)

        def check(route_id, command, version_args, expected, *, published=True, success=True):
            route = routes[route_id]
            if published:
                assert command in "\n".join(route["steps"]), f"Published command changed: {route_id}: {command}"
            argv = shlex.split(command)
            executable = shutil.which(argv[0])
            if not executable:
                results.append((route_id, command, "SKIP: executable unavailable", ""))
                return
            result = subprocess.run(argv, cwd=directory, text=True, capture_output=True, timeout=20)
            assert (result.returncode == 0) == success, (command, result.returncode, result.stderr)
            assert expected(result), (command, result.stdout, result.stderr)
            version = subprocess.run([executable, *version_args], text=True, capture_output=True, timeout=10)
            assert version.returncode == 0, (argv[0], "version query failed", version.stderr)
            version_text = (version.stdout or version.stderr).strip().splitlines()[0]
            results.append((route_id, command, "PASS" if published else "PASS (failure control)", version_text))

        # Checks below must retain exact command text from the published route.
        run_checks(check, directory)

    lines = ["# Recipe fixture validation", "", f"Run: {datetime.now(timezone.utc).isoformat()}",
             f"Routes SHA-256: `{hashlib.sha256(route_bytes).hexdigest()}`", "",
             "Commands ran in a temporary directory on generated benign files, without network requests or package installation.",
             "Only the listed command steps were exercised; this is not validation of whole routes or organiser machines.", "",
             "| Route | Exact command | Result | Local version |", "|---|---|---|---|"]
    for route, command, status, version in results:
        lines.append(f"| {route} | `{command}` | {status} | {version} |")
        print(f"{status}: {route}: {command}")
    tested = {row[0] for row in results if row[2] == "PASS"}
    lines += ["", "Untested routes: " + ", ".join(sorted(set(routes) - tested)) + ".", "",
              "Skipped: GUI workflows, exploit execution, real challenge inputs, online services, and platform/version parity. "
              "Source-reviewed labels remain appropriate; local fixture success does not establish competition-host availability.", ""]
    if args.report:
        (ROOT / "research/resources/recipe-validation.md").write_text("\n".join(lines))
    print(f"{sum(row[2].startswith('PASS') for row in results)} passed; "
          f"{sum(row[2].startswith('SKIP') for row in results)} skipped")


def run_checks(check, directory):
    check("artifact-identification", "file artifact.bin", ["--version"],
          lambda r: "Zip archive data" in r.stdout)
    check("artifact-identification", "7z l artifact.bin", ["i"],
          lambda r: "note.txt" in r.stdout and "1 files" in r.stdout)
    check("artifact-identification", "7z x artifact.bin -oextracted-artifact", ["i"],
          lambda r: (directory / "extracted-artifact/note.txt").read_bytes() == b"benign archive fixture\n")
    check("artifact-identification", "7z l invalid.bin", ["i"],
          lambda r: "Cannot open the file as archive" in r.stderr, published=False, success=False)
    check("focused-extraction", 'rg -n -F "needle" evidence-dir', ["--version"],
          lambda r: r.stdout.strip() == "evidence-dir/notes.txt:2:a needle clue")
    check("focused-extraction", "jq . data.json", ["--version"],
          lambda r: json.loads(r.stdout) == {"key": "fixture_value", "nested": {"number": 7}})
    check("focused-extraction", "jq -r .key data.json", ["--version"],
          lambda r: r.stdout == "fixture_value\n")
    check("focused-extraction", "jq . invalid.json", ["--version"],
          lambda r: "parse error" in r.stderr, published=False, success=False)
    check("focused-extraction", "python3 -c 'import struct; data = open(\"record.bin\", \"rb\").read(4); print(struct.unpack(\"<I\", data)[0])'", ["--version"],
          lambda r: r.stdout == "305419896\n")
    check("media-inspection", "exiftool -a -u -g1 image.png", ["-ver"],
          lambda r: "benign_metadata_marker" in r.stdout and "Image Width" in r.stdout and "---- PNG ----" in r.stdout)
    check("media-inspection", "pngcheck -v image.png", ["-h"],
          lambda r: "No errors detected" in r.stdout)


if __name__ == "__main__":
    main()
