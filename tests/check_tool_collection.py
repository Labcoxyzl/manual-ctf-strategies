"""Check the complete tool matrix, caption/runtime evidence and local practice inputs."""
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
import struct
import wave

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "research/learning/video-coverage"
data = json.loads((BASE / "collection.json").read_text())
inventory = json.loads((ROOT / "research/inventory.json").read_text())
original = json.loads((ROOT / "research/learning-resources.json").read_text())
tools = {r["id"]: r for r in inventory["tools"]}
old_refs = {r["tool_id"]: r["reference_url"] for r in original["coverage"]}
resources = {r["id"]: r for r in data["resources"]}
assert len(resources) == len(data["resources"])
assert len({r["url"].rstrip("/") for r in resources.values()}) == len(resources)
assert all(target in resources for target in data["resource_aliases"].values())
assert Counter(r["tool_id"] for r in data["rows"]) == Counter(tools.keys())
assert data["source_sha256"] == inventory["source_sha256"]
for row in data["rows"]:
    for key in ("name", "platform", "version", "location", "remarks"):
        assert row[key] == tools[row["tool_id"]][key], (row["tool_id"], key)
    assert row["original_reference_url"] == old_refs[row["tool_id"]]
    assert row["coverage_disposition"] and row["learning_resource_ids"]
    for rid in row["learning_resource_ids"]:
        assert row["tool_id"] in resources[rid]["tool_ids"], (row["tool_id"], rid)
    if row["priority"] == "essential":
        assert any(resources[rid]["depth"] != "reference" for rid in row["learning_resource_ids"])
for r in resources.values():
    assert set(r["tool_ids"]) <= tools.keys()
    assert r["skills"] and r["prerequisites"] and r["limitations"] and r["evidence"]
    assert r["access"].get("cost") and r["access"].get("offline")

# The organiser names these bundled capabilities separately; a suite label is insufficient.
by_row = {r["tool_id"]: r for r in data["rows"]}
for tid, expected in {
    "kali-94": {"Nmap", "Ncat", "Nping"},
    "kali-98": {"olevba", "oleid", "oleobj", "rtfobj", "mraptor", "msodde", "olemeta", "oletimes", "pyxswf"},
}.items():
    components = by_row[tid]["components"]
    assert {c["name"] for c in components} == expected
    for component in components:
        assert component["disposition"] and component["resource_ids"]
        assert all(tid in resources[rid]["tool_ids"] for rid in component["resource_ids"])
assert "forensics-autopsy-workflow" not in resources
assert data["resource_aliases"]["forensics-autopsy-workflow"] == "forensics-2"
assert by_row["windows-34"]["learning_resource_ids"].count("forensics-2") == 1

access = json.loads((BASE / "access-audit.json").read_text())
assert access["collection_sha256"] == hashlib.sha256((BASE / "collection.json").read_bytes()).hexdigest()
access_rows = {r["resource_id"]: r for r in access["resources"]}
assert len(access_rows) == len(access["resources"]) == len(resources)
assert set(access_rows) == set(resources)
for rid, r in resources.items():
    audit = access_rows[rid]
    assert audit["resource_sha256"] == hashlib.sha256(json.dumps(r, sort_keys=True).encode()).hexdigest()
    assert audit["disposition"] in {"fresh_verified", "reused_evidence"}

videos = {v["id"]: v for v in data["videos"]}
assert len(videos) == len(data["videos"]) == 17
existing = {v["video_id"] for v in json.loads((ROOT / "research/learning/video-pack/video-review.json").read_text())["videos"]}
assert len(existing) == 8
for row in data["rows"]:
    assert set(row["current_video_ids"]) <= existing
for vid, v in videos.items():
    meta_path = ROOT / v["metadata_path"]
    cap_path = ROOT / v["caption_path"]
    assert hashlib.sha256(meta_path.read_bytes()).hexdigest() == v["metadata_sha256"]
    assert hashlib.sha256(cap_path.read_bytes()).hexdigest() == v["caption_sha256"]
    meta = json.loads(meta_path.read_text())
    assert meta["id"] == vid and meta["duration"] == v["full_runtime_seconds"]
    cues = [int(h) * 3600 + int(m) * 60 + int(s)
            for h, m, s in re.findall(r"(\d\d):(\d\d):(\d\d)\.\d+ -->", cap_path.read_text())]
    assert cues and max(cues) <= meta["duration"] + 2
    segments = v["selected_sections_seconds"]
    assert all(0 <= a < b <= meta["duration"] for a, b in segments)
    assert all(segments[i][1] <= segments[i + 1][0] for i in range(len(segments) - 1))
    assert all(any(a <= cue < b for cue in cues) for a, b in segments)
    assert sum(b - a for a, b in segments) == v["selected_runtime_seconds"]
    r = resources[v["resource_id"]]
    assert r["selected_sections_seconds"] == segments
    assert r["access"].get("free_reading_alternative")
    assert "Premium" in r["access"]["offline_video_policy"]
rt = data["runtime"]
assert rt["existing_full_seconds"] == sum(v["full_runtime_seconds"] for vid, v in videos.items() if vid in existing) == 6214
assert rt["new_full_seconds"] == sum(v["full_runtime_seconds"] for vid, v in videos.items() if vid not in existing) == 25040
assert rt["all_full_seconds"] == sum(v["full_runtime_seconds"] for v in videos.values()) == 31254
assert rt["new_selected_seconds"] == sum(v["selected_runtime_seconds"] for v in videos.values() if v["role"] == "deeper_selected_sections")
assert rt["retained_workflow_selected_seconds"] == sum(v["selected_runtime_seconds"] for v in videos.values() if v["role"] == "retained_narrow_workflow")
# Caption-confirmed FTK instructions and unapproved continuations stay outside selection.
for a, b in videos["VYROU-ZwZX8"]["selected_sections_seconds"]:
    assert not (a < 220 and b > 210)
    assert not (a < 1408 and b > 1366)
    assert b <= 3209
assert videos["dLIbkg_8O68"]["selected_sections_seconds"] == [[780, 990]]

docs = [ROOT / name for name in ("TOOL_LEARNING_COLLECTION.md", "TOOL_RESOURCE_CATALOG.md", "TOOL_COVERAGE_MATRIX.md")]
docs += list((BASE / "practice").glob("*.md"))
for doc in docs:
    contents = doc.read_text()
    ids = re.findall(r'<a id="([^"]+)"', contents)
    assert len(ids) == len(set(ids)), doc.name
    for url in re.findall(r"\]\(([^)]+)\)", contents):
        if url.startswith(("https://", "http://")):
            continue
        file, _, fragment = url.partition("#")
        path = doc.parent / file if file else doc
        assert path.is_file(), (doc.name, url)
        if fragment:
            assert f'<a id="{fragment}">' in path.read_text(), (doc.name, url)
matrix = (ROOT / "TOOL_COVERAGE_MATRIX.md").read_text()
assert len(re.findall(r"^\| (?:windows|kali)-\d+:", matrix, re.M)) == 200
with (BASE / "coverage.csv").open(newline="") as f:
    csv_rows = list(csv.DictReader(f))
assert Counter(r["tool_id"] for r in csv_rows) == Counter(tools.keys())
assert all(r["original_reference_url"] == old_refs[r["tool_id"]] for r in csv_rows)

practice = BASE / "practice"
binary = (practice / "triage.bin").read_bytes()
assert binary[16:31] == b"route=/clue.txt"
assert binary[64:-2].decode("utf-16le") == "destination=harbor"
pdf_check = json.loads((practice / "triage-pdf-check.json").read_text())
for name, expected in pdf_check["sha256"].items():
    assert hashlib.sha256((practice / name).read_bytes()).hexdigest() == expected
audio_check = json.loads((practice / "audio-check.json").read_text())
assert hashlib.sha256((practice / "audio-tones.wav").read_bytes()).hexdigest() == audio_check["sha256"]
with wave.open(str(practice / "audio-tones.wav"), "rb") as w:
    assert (w.getnframes(), w.getframerate(), w.getnchannels(), w.getsampwidth()) == (64000, 8000, 1, 2)
    samples = struct.unpack("<64000h", w.readframes(64000))
    assert all(v == 0 for v in samples[48000:])
extraction = json.loads((practice / "bundle-extraction-check.json").read_text())
for name, expected in extraction["input_sha256"].items():
    assert hashlib.sha256((practice / name).read_bytes()).hexdigest() == expected
assert {r["module"] for r in extraction["results"]} == {"oleobj", "rtfobj"}
for result in extraction["results"]:
    assert result["extracted_payload_bytes"] == len(b"hello from study\n") == 17
    assert result["payload_sha256"] == hashlib.sha256(b"hello from study\n").hexdigest()
assert json.loads((practice / "ncat-check.json").read_text())["received_exact_payload"]
print(json.dumps({"result": "passed", "rows": 200, "resources": len(resources), "videos": len(videos),
                  "original_video_depth": dict(Counter(r["video_depth"] for r in data["rows"])),
                  "runtime": rt, "checks": ["exact inventory/reference preservation", "resource mappings and evidence fields",
                  "caption/metadata hashes and selected intervals", "unique runtime arithmetic", "approval exclusion intervals",
                  "local links/anchors and CSV", "known binary/PDF/audio input integrity",
                  "named bundled-capability dispositions", "current per-resource access-audit identity",
                  "recorded benign OLE/RTF extraction inputs and loopback result"],
                  "limits": "Structural checks do not establish teaching quality; independent reviews cover that. This checker does not add playback, GUI, qpdf or memory-image execution. Benign Ncat/oleobj/rtfobj checks were executed separately in this review pass."}, indent=2))
