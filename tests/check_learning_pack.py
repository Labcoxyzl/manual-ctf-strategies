"""Focused checks for the Markdown learning pack and its benign local fixtures."""
from collections import Counter
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
data = json.loads((ROOT / "research/learning-resources.json").read_text())
inventory = json.loads((ROOT / "research/inventory.json").read_text())["tools"]
prior = json.loads((ROOT / "research/learning/previous/learning-resources.json").read_text())
tools = {t["id"]: t for t in inventory}
resources = {r["id"]: r for r in data["resources"]}
assert len(resources) == len(data["resources"])
assert len({r["url"] for r in resources.values()}) == len(resources)
assert Counter(c["tool_id"] for c in data["coverage"]) == Counter(tools.keys())
prior_coverage = {c["tool_id"]: c for c in prior["coverage"]}
for c in data["coverage"]:
    assert c["reference_url"] == prior_coverage[c["tool_id"]]["reference_url"]
    for field in ("name", "platform", "version", "location", "remarks"):
        assert c[field] == tools[c["tool_id"]][field], (c["tool_id"], field)
    for rid in c["resource_ids"]:
        assert c["tool_id"] in resources[rid]["tool_ids"]
evaluations = {e["id"]: e for e in data["evaluations"]}
assert set(evaluations) == {r["id"] for r in prior["resources"]}
for r in resources.values():
    assert set(r["tool_ids"]) <= tools.keys()
    e = evaluations[r["id"]]
    assert e["decision"] != "remove" and e["rationale"] and e["evidence"]
    assert all(item["url"] and item["inspected"] for item in e["evidence"])
    assert r["focus"] and r["prerequisites"]
    assert all(r["access"][key] for key in ("viewing", "cost", "registration", "offline"))
    if r["type"] == "watch":
        assert r["access"]["free_alternative_url"] != r["url"]
assert [b["id"] for b in data["schedule"]] == list(range(1, 11))
assert sum(b["minutes"] for b in data["schedule"]) == 1440
for b in data["schedule"]:
    assert sum(b["allocation"].values()) == b["minutes"]
    assert set(b["resource_ids"]) <= resources.keys()
    assert all(b[key] for key in ("diagnostic", "outcome", "selection", "preparation", "exercise", "assessment"))

documents = ["LEARNING_RESOURCES.md", "APPROVED_TOOL_REFERENCES.md",
             "PRACTICE_WORKSHEETS.md", "RESOURCE_EVALUATION.md",
             "research/learning/practice/README.md"]
for name in documents:
    path = ROOT / name
    text = path.read_text()
    ids = re.findall(r'<a id="([^"]+)"', text)
    assert len(ids) == len(set(ids)), name
    for target in re.findall(r'\]\(([^)]+)\)', text):
        if target.startswith(("https://", "http://")):
            continue
        file, _, fragment = target.partition("#")
        dest = path.parent / file if file else path
        assert dest.is_file(), (name, target)
        if fragment:
            assert f'<a id="{fragment}">' in dest.read_text(), (name, target)
guide = (ROOT / documents[0]).read_text()
assert all(f'<a id="{rid}">' in guide for rid in resources)
index = (ROOT / documents[1]).read_text()
assert Counter(re.findall(r'^\| <a id="((?:windows|kali)-\d+)"></a>', index, re.M)) == Counter(tools.keys())
assert not re.search(r'^\| (?:windows|kali)-\d+:', index, re.M)

# Known answers are independently recomputed, not read back from the guide.
assert base64.b64decode("Q1RGLXJlZnJlc2hlcg==") == b"CTF-refresher"
assert 2048 * 512 + 3 * 4096 == 1060864
assert pow(17, -1, 3120) == 2753
assert pow(42, 17, 3233) == 2557 and pow(2557, 2753, 3233) == 42
assert hashlib.md5(b"cat").hexdigest() == "d077f244def8a70e5ea758bd8352fcd8"
with sqlite3.connect(":memory:") as db:
    db.executescript("CREATE TABLE visits(url TEXT, ts INTEGER); INSERT INTO visits VALUES('a',10),('b',20);")
    assert db.execute("SELECT url, ts FROM visits ORDER BY ts DESC").fetchall() == [("b", 20), ("a", 10)]

# Read the supplied paper rows, then derive their keys without forensic tools.
worksheets = (ROOT / "PRACTICE_WORKSHEETS.md").read_text()
disk = worksheets.split('<a id="block-3"></a>')[1].split('<a id="block-4"></a>')[0]
journal = re.findall(r'^\| (\d+) \| (\d+) \| (\d+) \| (\w+) \| ([^|]+) \|$', disk, re.M)
assert len(journal) == 7
groups = {}
for event, entry, sequence, reason, name in journal:
    groups.setdefault((int(entry), int(sequence)), []).append((int(event), reason, name.strip()))
assert sorted(groups[(42, 7)]) == [(101, "Create", "draft.txt"), (103, "RenameOldName", "draft.txt"),
                                    (104, "RenameNewName", "final.txt"), (106, "Delete", "final.txt")]
assert sorted(e[0] for e in groups[(43, 2)]) == [102, 105]
assert groups[(42, 8)] == [(108, "Create", "unrelated.txt")]
assert 4096 * 512 == 2097152
memory = worksheets.split('<a id="block-4"></a>')[1].split('<a id="block-5"></a>')[0]
rows = re.findall(r'^\| (\d+) \| (\d+) \| ([^|]+) \|$', memory, re.M)
parents = {int(pid): int(ppid) for pid, ppid, _ in rows}
assert len(rows) == len(parents) == 5
assert set(parents.values()) - set(parents) == {4, 799}
assert (parents[910], parents[850]) == (850, 799)
assert (parents[710], parents[620], parents[500]) == (620, 500, 4)
assert "training-marker harbors" in worksheets
assert re.search(r"\bharbor\b", "training-marker harbor")
assert not re.search(r"\bharbor\b", "training-marker harbors")

executed, skipped = ["base64, offsets, RSA, MD5, SQLite, synthetic journal/process and ASCII paper-match checks"], []
fixtures = ROOT / "research/learning/practice"
if shutil.which("tshark"):
    result = subprocess.check_output(["tshark", "-r", str(fixtures / "http-demo.pcap"),
        "-Y", "http.request", "-T", "fields", "-e", "ip.src", "-e", "ip.dst",
        "-e", "http.request.method", "-e", "http.request.uri", "-e", "tcp.stream"], text=True)
    assert result.strip() == "192.0.2.10\t192.0.2.20\tGET\t/clue.txt\t0"
    stream = subprocess.check_output(["tshark", "-r", str(fixtures / "http-demo.pcap"),
        "-q", "-z", "follow,tcp,ascii,0"], text=True)
    assert "HTTP/1.1 200 OK" in stream and "CTF-refresher" in stream
    executed.append("TShark request fields and TCP stream")
else:
    skipped.append("TShark unavailable")
gcc = "/usr/bin/gcc" if Path("/usr/bin/gcc").exists() else shutil.which("gcc")
if gcc:
    with tempfile.TemporaryDirectory() as tmp:
        exe = str(Path(tmp) / "check")
        subprocess.run([gcc, "-O0", "-g", str(fixtures / "check_input.c"), "-o", exe], check=True)
        for args, code, output in [([], 2, "usage: check_input WORD"), (["wrong"], 1, "rejected"), (["harbor"], 0, "accepted")]:
            result = subprocess.run([exe, *args], capture_output=True, text=True)
            assert (result.returncode, result.stdout.strip()) == (code, output)
        executed.append("GCC program: all three output/exit cases")
        if shutil.which("gdb"):
            result = subprocess.run(["gdb", "-q", "-batch", "-ex", "break main", "-ex", "run wrong",
                "-ex", "print argc", "-ex", "disassemble main", "-ex", "continue", exe], capture_output=True, text=True, timeout=20)
            assert result.returncode == 0 and "$1 = 2" in result.stdout and "rejected" in result.stdout
            executed.append("GDB breakpoint, argc, disassembly and rejected branch")
        else:
            skipped.append("GDB unavailable")
else:
    skipped.append("GCC unavailable")
if shutil.which("curl"):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = subprocess.Popen([sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1",
        "--directory", str(fixtures / "http")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for attempt in range(40):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/clue.txt", timeout=1) as response:
                    assert response.status == 200 and response.read() == b"CTF-refresher\n"
                break
            except OSError:
                time.sleep(.05)
        else:
            raise AssertionError("local HTTP server did not start")
        for path, status in [("clue.txt", "200"), ("missing.txt", "404")]:
            result = subprocess.check_output(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                f"http://127.0.0.1:{port}/{path}"], text=True)
            assert result == status
        executed.append("Python loopback server/curl: 200 body and 404")
    finally:
        server.terminate()
        server.wait(timeout=5)
else:
    skipped.append("curl unavailable")
report = {"result": "passed", "resources": len(resources), "evaluated_original_resources": len(evaluations),
          "approved_rows": len(tools), "schedule_minutes": 1440, "executed": executed, "skipped": skipped}
print(json.dumps(report, indent=2))
