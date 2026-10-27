"""Build the standalone field guide from approved inventory and reviewed resources."""
import csv
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
CATEGORIES = {
    "forensics": "Digital Forensics", "malware": "Malware Analysis",
    "web": "Web Security", "reversing": "Reverse Engineering",
    "osint": "OSINT", "crypto": "Cryptography", "misc": "Miscellaneous",
}
RESOURCE_FILES = ("forensics", "web-network", "reverse", "media", "crypto-foundations")
LOCAL_ROUTE_HELP = {
    "pcap-stream": (("PCAP workflow", "CORE_WORKFLOWS.html#pcap"),),
    "wireless-auth": (("Wireless capture workflow", "SPECIALIST_WORKFLOWS.html#wireless-auth"),),
    "evtx-timeline": (("EVTX workflow", "SPECIALIST_WORKFLOWS.html#evtx-timeline"),),
    "registry-hive": (("Registry workflow", "SPECIALIST_WORKFLOWS.html#registry-hive"),),
    "sqlite-artifact": (("SQLite workflow", "SPECIALIST_WORKFLOWS.html#sqlite-artifact"),),
    "browser-profile-timeline": (("Browser profile workflow", "SPECIALIST_WORKFLOWS.html#browser-profile-timeline"),),
    "android-preferences": (("Android preference workflow", "SPECIALIST_WORKFLOWS.html#android-preferences"),),
    "android-datastore-preferences": (("Android DataStore workflow", "SPECIALIST_WORKFLOWS.html#android-datastore-preferences"),
                                      ("One-key DataStore reader", "scripts/templates/datastore_pref.py")),
    "ios-plist": (("iOS plist workflow", "SPECIALIST_WORKFLOWS.html#ios-plist"),),
    "git-history": (("Git history workflow", "SPECIALIST_WORKFLOWS.html#git-history"),),
    "disk-file": (("Disk workflow", "CORE_WORKFLOWS.html#disk"),),
    "memory-process": (("Memory workflow", "CORE_WORKFLOWS.html#memory"),),
    "media-inspection": (("Image workflow", "CORE_WORKFLOWS.html#media"),
                         ("Audio practice", "research/learning/video-coverage/practice/AUDIO_PRACTICE.html"),
                         ("PDF workflow", "CORE_WORKFLOWS.html#pdf")),
    "executable-triage": (("Executable workflow", "SPECIALIST_WORKFLOWS.html#malware-executable"),
                          ("File preview script", "scripts/templates/file_intel.py")),
    "document-code": (("Document workflow", "SPECIALIST_WORKFLOWS.html#malware-document"),
                      ("PDF workflow", "CORE_WORKFLOWS.html#pdf")),
    "bundle-extraction": (("Bundle workflow", "SPECIALIST_WORKFLOWS.html#malware-bundle"),
                          ("File preview script", "scripts/templates/file_intel.py")),
    "http-baseline": (("HTTP workflow", "CORE_WORKFLOWS.html#web"),
                      ("Stateless HTTP probe", "scripts/templates/http_probe.py")),
    "endpoint-discovery": (("Endpoint workflow", "SPECIALIST_WORKFLOWS.html#web-endpoints"),
                           ("Stateless HTTP probe", "scripts/templates/http_probe.py")),
    "targeted-web-test": (("Targeted test workflow", "SPECIALIST_WORKFLOWS.html#web-targeted"),
                          ("Selected web lead helper", "TOOLKIT.html#web-leads")),
    "web-output-context": (("Output context workflow", "SPECIALIST_WORKFLOWS.html#web-output-context"),
                           ("Stateless HTTP probe", "scripts/templates/http_probe.py")),
    "sqli-differential": (("SQL condition workflow", "SPECIALIST_WORKFLOWS.html#sqli-differential"),
                          ("Bounded SQL comparison helper", "TOOLKIT.html#web-sql")),
    "server-fetch": (("Server fetch workflow", "SPECIALIST_WORKFLOWS.html#server-fetch"),),
    "object-authorization": (("Authorization workflow", "SPECIALIST_WORKFLOWS.html#object-authorization"),
                              ("Two-role workflow helper", "TOOLKIT.html#web-workflows")),
    "path-traversal-read": (("Outside-root file workflow", "SPECIALIST_WORKFLOWS.html#path-traversal-read"),
                            ("Selected web lead helper", "TOOLKIT.html#web-leads")),
    "web-cross-site-state": (("Cross-site state workflow", "SPECIALIST_WORKFLOWS.html#web-cross-site-state"),
                             ("One-click form template", "scripts/templates/cross_site_form.html")),
    "jwt-verification": (("JWT workflow", "SPECIALIST_WORKFLOWS.html#web-jwt"),
                         ("JWT inspection script", "scripts/templates/jwt_inspect.py")),
    "native-checker": (("Native checker workflow", "CORE_WORKFLOWS.html#native"),),
    "symbolic-elf-checker": (("Symbolic checker workflow", "SPECIALIST_WORKFLOWS.html#symbolic-elf-checker"),
                             ("Bounded checker helper", "TOOLKIT.html#checker")),
    "native-exploit-triage": (("Native crash workflow", "SPECIALIST_WORKFLOWS.html#native-exploit"),
                              ("Plain TCP starter", "scripts/templates/pwntools_starter.py")),
    "android-validation": (("APK/DEX workflow", "SPECIALIST_WORKFLOWS.html#reverse-android"),),
    "dotnet-validation": ((".NET workflow", "SPECIALIST_WORKFLOWS.html#reverse-dotnet"),),
    "source-view": (("Source-view workflow", "SPECIALIST_WORKFLOWS.html#reverse-source"),),
    "metadata-corroboration": (("Image workflow", "CORE_WORKFLOWS.html#media"),
                               ("Source/date workflow", "SPECIALIST_WORKFLOWS.html#osint-source")),
    "visual-landmark": (("Visual landmark workflow", "SPECIALIST_WORKFLOWS.html#osint-landmark"),),
    "public-source": (("Public-source workflow", "SPECIALIST_WORKFLOWS.html#osint-source"),),
    "public-domain": (("Public-domain workflow", "SPECIALIST_WORKFLOWS.html#osint-domain"),),
    "decode-bytes": (("Decoding workflow", "CORE_WORKFLOWS.html#decode"),),
    "xor-keystream-reuse": (("XOR/stream workflow", "SPECIALIST_WORKFLOWS.html#xor-keystream-reuse"),
                            ("Known-key XOR helper", "TOOLKIT.html#xor")),
    "aes-declared-parameters": (("AES mode workflow", "SPECIALIST_WORKFLOWS.html#aes-declared-parameters"),
                                ("Declared-parameter helper", "TOOLKIT.html#setup")),
    "cbc-padding-oracle": (("CBC oracle workflow", "SPECIALIST_WORKFLOWS.html#cbc-padding-oracle"),),
    "hash-length-extension": (("Hash extension workflow", "SPECIALIST_WORKFLOWS.html#hash-length-extension"),),
    "rsa-weakness": (("RSA workflow", "CORE_WORKFLOWS.html#crypto"),),
    "zip-known-plaintext": (("ZipCrypto workflow", "SPECIALIST_WORKFLOWS.html#zip-known-plaintext"),),
    "artifact-identification": (("File preview guide", "TEMPLATES.html#file-intel"),
                                ("File preview script", "scripts/templates/file_intel.py")),
    "focused-extraction": (("Binary parser guide", "TEMPLATES.html#binary"),
                           ("Binary parser script", "scripts/templates/binary_parser.py")),
    "service-interaction": (("Plain TCP client guide", "TEMPLATES.html#transport"),
                            ("Plain TCP starter", "scripts/templates/pwntools_starter.py"),
                            ("Timed arithmetic guide", "TEMPLATES.html#timed-math")),
    "can-log-evidence": (("CAN log workflow", "CORE_WORKFLOWS.html#can"),),
}
TOOL_ORIGINS = json.loads((ROOT / "research/tool-origins.json").read_text())["tools"]
esc = html.escape


def inline(text):
    return re.sub(r'`([^`]+)`', r'<code>\1</code>', esc(text))


def validate_reference(reference):
    url = urlsplit(reference["url"])
    from build_notes import NOTE_OUTPUTS
    local = not url.scheme and not url.netloc and url.path in NOTE_OUTPUTS.values()
    assert local or (url.scheme in {"http", "https"} and url.netloc), reference
    assert reference["title"].strip(), reference


def load_data():
    inventory = json.loads((ROOT / "research/inventory.json").read_text())["tools"]
    resources = []
    for name in RESOURCE_FILES:
        resources.extend(json.loads((ROOT / f"research/resources/{name}.json").read_text()))
    routes = json.loads((ROOT / "research/routes.json").read_text())
    by_id = {record["id"]: record for record in resources}
    approved = {tool["id"] for tool in inventory}
    assert len(inventory) == len(approved) == len(resources) == len(by_id) == 200
    assert set(TOOL_ORIGINS) == approved
    assert set(TOOL_ORIGINS.values()) == {"TrendMicro proposal", "participant request"}
    assert sum(origin == "TrendMicro proposal" for origin in TOOL_ORIGINS.values()) == 32
    assert set(by_id) == approved
    assert all(re.fullmatch(r'(windows|kali)-\d+', tool_id) for tool_id in approved)
    for record in resources:
        assert record["categories"] and set(record["categories"]) <= set(CATEGORIES.values()), record["id"]
        assert record["challenge_use"].strip(), record["id"]
        assert 1 <= len(record["resources"]) <= 3, record["id"]
        for reference in record["resources"]:
            validate_reference(reference)
            assert reference["verification"].strip(), record["id"]
    assert len(routes) == len({route["id"] for route in routes}) == 48
    assert {route["category"] for route in routes} == set(CATEGORIES)
    for route in routes:
        assert re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', route["id"]), route["id"]
        for field in ("title", "input", "expected", "fallback", "caveat", "verification"):
            assert isinstance(route[field], str) and route[field].strip(), (route["id"], field)
        assert route["tool_ids"] and set(route["tool_ids"]) <= approved, route["id"]
        assert route["steps"] and all(isinstance(step, str) and step.strip() for step in route["steps"])
        if "toolkit" in route:
            assert route["toolkit"]["anchor"] in {"inspect", "bits", "xor"}, route["id"]
            assert route["toolkit"]["text"].strip(), route["id"]
        assert route["references"], route["id"]
        for reference in route["references"]:
            validate_reference(reference)
    assert set(LOCAL_ROUTE_HELP) <= {route["id"] for route in routes}
    from build_notes import NOTE_OUTPUTS
    notes = set(NOTE_OUTPUTS.values())
    bundled = notes | {str(path.relative_to(ROOT)) for path in (ROOT / "scripts/templates").glob("*.py")} | {"scripts/templates/cross_site_form.html"}
    for links in LOCAL_ROUTE_HELP.values():
        assert all(urlsplit(url).path in bundled and title.strip() for title, url in links)
    assert all(any(urlsplit(url).path in notes for _, url in LOCAL_ROUTE_HELP.get(route["id"], ())) or
               any(urlsplit(ref["url"]).path in notes for ref in route["references"])
               for route in routes), "Every task route needs a bundled local guide"
    return inventory, by_id, routes


def references(items):
    return '<ul class="references">' + ''.join(
        f'<li><a href="{esc(item["url"])}">{esc(item["title"])}</a></li>'
        for item in items) + '</ul>'


def platform_label(tool):
    return "Windows / WSL" if tool["location"] == "installed in WSL" else tool["platform"].title()


def is_proposed(tool):
    return TOOL_ORIGINS[tool["id"]] == "TrendMicro proposal"


def tool_order(tool):
    return (not is_proposed(tool), tool["name"].casefold(), tool["id"])


def render_route(route, inventory):
    tools = ' · '.join(f'<a href="#tool-{tool_id}">{esc(inventory[tool_id]["name"])} '
                       f'({esc(platform_label(inventory[tool_id]))})</a>' for tool_id in route["tool_ids"])
    steps = ''.join(f'<li>{inline(step)}</li>' for step in route["steps"])
    body = ''.join(f'<p class="{field}"><strong>{label}:</strong> {inline(route[field])}</p>'
                   for field, label in (("expected", "Expected"), ("fallback", "If stuck"),
                                        ("caveat", "Note")))
    if "toolkit" in route:
        helper = route["toolkit"]
        body += (f'<p class="toolkit"><strong>Optional helper:</strong> {inline(helper["text"])} '
                 f'<a href="TOOLKIT.html#{helper["anchor"]}">Setup, example and manual alternative</a>.</p>')
    local = LOCAL_ROUTE_HELP.get(route["id"], ())
    if local:
        links = ' · '.join(f'<a href="{esc(url)}">{esc(title)}</a>' for title, url in local)
        body += f'<p class="offline"><strong>Offline next step:</strong> {links}</p>'
    return (f'<details class="task-route" id="route-{route["id"]}">'
            f'<summary><span>{esc(route["title"])}</span><small>{inline(route["input"])}</small></summary>'
            f'<div class="route-body"><p class="route-tools">{tools}</p><ol class="steps">{steps}</ol>'
            f'{body}{references(route["references"])}</div></details>')


def render(tool, record):
    metadata = ''.join(f'<dt>{label}</dt><dd>{esc(str(tool[field])) or "Not specified"}</dd>'
                       for field, label in (("platform", "Platform"), ("version", "Version"),
                                            ("location", "Location"), ("remarks", "Remarks")))
    caveats = ''.join(f'<li>{inline(caveat)}</li>' for caveat in record["caveats"])
    platform = platform_label(tool)
    proposal = '<small class="proposal">Trend Micro proposal</small>' if is_proposed(tool) else ''
    search_text = ' '.join([tool["name"], tool["id"], platform, "Trend Micro proposal" if is_proposed(tool) else "Participant request", record["challenge_use"], *record["categories"]])
    return (f'<article class="catalog-tool" id="tool-{tool["id"]}" data-source-ids="{tool["id"]}" '
            f'data-search="{esc(search_text)}" data-origin="{esc(TOOL_ORIGINS[tool["id"]])}"><h3>{esc(tool["name"])}{proposal}'
            f'</h3><p class="platform">{esc(platform)}</p>'
            f'<p>{esc(record["challenge_use"])}</p>'
            f'<ul class="caveats">{caveats}</ul>{references(record["resources"])}'
            f'<details class="metadata"><summary>Version and installation</summary>'
            f'<dl>{metadata}</dl></details></article>')


class PageLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.fragments = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if attrs.get("href", "").startswith("#"):
            self.fragments.append(attrs["href"][1:])


def render_page(template, inventory, resources, routes):
    by_id = {tool["id"]: tool for tool in inventory}
    route_sections, catalogs = [], []
    for slug, name in CATEGORIES.items():
        category_routes = '\n'.join(render_route(route, by_id) for route in routes if route["category"] == slug)
        route_sections.append(f'<section id="{slug}" aria-labelledby="{slug}-title">'
                              f'<h2 id="{slug}-title">{name}</h2>{category_routes}</section>')
        tools = sorted((tool for tool in inventory if resources[tool["id"]]["categories"][0] == name),
                       key=tool_order)
        entries = '\n'.join(render(tool, resources[tool["id"]]) for tool in tools)
        catalogs.append(f'<details class="catalog" data-category="{slug}">'
                        f'<summary>{name} ({len(tools)})</summary>{entries}</details>')
    for marker, blocks in (("routes", route_sections), ("catalog", catalogs)):
        marker = f'<!-- guide:{marker} -->'
        assert template.count(marker) == 1, marker
        template = template.replace(marker, '\n'.join(blocks))
    links = PageLinks()
    links.feed(template)
    assert len(links.ids) == len(set(links.ids)), "Duplicate HTML ids"
    assert set(links.fragments) <= set(links.ids), set(links.fragments) - set(links.ids)
    assert {item for item in links.ids if re.fullmatch(r"tool-(windows|kali)-\d+", item)} == {f'tool-{tool_id}' for tool_id in by_id}
    return template


def render_readme_catalog(inventory, resources):
    with (ROOT / "research/validation/round2/authority/priority-authority.csv").open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    by_id = {tool["id"]: tool for tool in inventory}
    assert len(rows) == len(by_id) == 200
    assert {row["id"] for row in rows} == set(by_id)
    assert all(row["name"] == by_id[row["id"]]["name"] and
               row["origin"] == TOOL_ORIGINS[row["id"]] and row["approval"] == "approved"
               for row in rows), "Workbook CSV differs from the approved inventory"
    core = {
        "windows-1": "decode", "windows-2": "pcap", "windows-3": "pdf",
        "windows-9": "native", "windows-12": "media", "windows-13": "media",
        "windows-14": "media", "windows-15": "pdf", "windows-16": "can",
        "windows-18": "pcap", "windows-20": "web", "windows-22": "native",
        "windows-23": "disk", "windows-26": "pdf", "windows-30": "crypto",
        "windows-31": "memory",
    }
    lines = []
    for category in CATEGORIES.values():
        tools = sorted((tool for tool in inventory if category in resources[tool["id"]]["categories"]),
                       key=tool_order)
        lines += [f"## {category}", "", "| Tool and origin | What it does and where to read more |", "| --- | --- |"]
        for tool in tools:
            tool_id = tool["id"]
            origin = "Trend Micro proposal" if is_proposed(tool) else "Participant request"
            name = esc(tool["name"]).replace("|", "\\|")
            purpose = esc(resources[tool_id]["challenge_use"]).replace("|", "\\|")
            links = [f"[Web](https://labcoxyzl.github.io/manual-ctf-strategies/#tool-{tool_id})"]
            if tool_id in core:
                links.append(f"[Core workflow](CORE_WORKFLOWS.md#{core[tool_id]})")
            if tool_id == "kali-59":
                links.append("[Hashcat commands](HASHCAT.md)")
            if tool_id in {"windows-7", "kali-114"}:
                links.append("[Python templates](scripts/templates/README.md)")
            lines.append(
                f"| [{name}](CTF_CHEATSHEET.md#approved-{tool_id}) · {esc(platform_label(tool))}"
                f"<br>**{origin}** | {purpose} · {' · '.join(links)} |"
            )
        lines.append("")
    assert sum(line.startswith("| [") for line in lines) == sum(len(row["categories"]) for row in resources.values())
    return "\n".join(lines).rstrip() + "\n"


def main():
    from build_notes import render_notes

    inventory, resources, routes = load_data()
    page = render_page((ROOT / "guide-template.html").read_text(), inventory, resources, routes)
    from build_cheatsheet import render_cheatsheet
    (ROOT / "CTF_CHEATSHEET.md").write_text(render_cheatsheet())
    notes = render_notes()
    for filename, content in notes.items():
        (ROOT / filename).write_text(content)
    for filename in ("index.html", "keyword-preview.html"):
        (ROOT / filename).write_text(page)
    readme = (ROOT / "README.md").read_text()
    start, end = "<!-- approved-tools:start -->", "<!-- approved-tools:end -->"
    assert readme.count(start) == readme.count(end) == 1
    before, rest = readme.split(start)
    _, after = rest.split(end)
    (ROOT / "README.md").write_text(before + start + "\n" + render_readme_catalog(inventory, resources) + end + after)
    print(f"Rendered {len(inventory)} approved entries and {len(routes)} task routes in {len(CATEGORIES)} categories")


if __name__ == "__main__":
    main()
