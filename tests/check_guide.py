"""Check the static guide; optionally record bounded external link probes."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
import hashlib
import json
import re
import sys
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class Guide(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.ids, self.links, self.labels, self.source_ids = [], [], [], []
        self.nodes, self.stack = [], []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        node = {"tag": tag, "attrs": attrs, "text": "", "links": []}
        self.nodes.append(node)
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append(node)
        if tag == "a":
            for parent in self.stack:
                parent["links"].append(attrs.get("href", ""))
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if "aria-labelledby" in attrs:
            self.labels.extend(attrs["aria-labelledby"].split())
        if "data-source-ids" in attrs:
            self.source_ids.extend(attrs["data-source-ids"].replace(",", " ").split())
        if tag == "a":
            self.links.append(attrs.get("href", ""))

    def handle_data(self, data):
        for node in self.stack:
            node["text"] += data

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i]["tag"] == tag:
                del self.stack[i:]
                break


def check(html):
    guide = Guide(html)
    errors = [f"Duplicate id: {key}" for key, n in Counter(guide.ids).items() if n > 1]
    for label in guide.labels:
        if label not in guide.ids:
            errors.append(f"Missing accessible label: {label}")
    for href in guide.links:
        try:
            url = urllib.parse.urlsplit(href)
        except ValueError:
            errors.append(f"Malformed anchor URL: {href}")
            continue
        if url.scheme and url.scheme not in {"http", "https", "mailto"}:
            errors.append(f"Unsafe anchor scheme: {href}")
        if url.scheme in {"http", "https"} and (not url.hostname or any(c.isspace() for c in href)):
            if url.hostname != "www.google.com":
                errors.append(f"Invalid external URL: {href}")
        if not href:
            errors.append("Empty anchor href")
        elif href.startswith("#") and href[1:] not in guide.ids:
            errors.append(f"Missing fragment: {href}")
        elif not url.scheme and url.path and not (ROOT / url.path).is_file():
            errors.append(f"Missing local file: {href}")
        if url.hostname == "www.google.com" and url.path == "/search":
            query = urllib.parse.parse_qs(url.query)
            if set(query) != {"q"} or len(query.get("q", [])) != 1:
                errors.append(f"Invalid Google query parameters: {href}")
            if any(c.isspace() for c in href):
                errors.append(f"Unencoded query whitespace: {href}")
    return guide, errors


def check_archive(guide, rendered=False):
    inventory = json.loads((ROOT / "research/inventory.json").read_text())["tools"]
    expected = {row["id"] for row in inventory}
    records = []
    for path in sorted((ROOT / "research").glob("queries-*.json")):
        records.extend(json.loads(path.read_text()))
    errors = []
    actual = [row["id"] for row in records]
    sets = [("research", actual)]
    if rendered:
        sets.append(("HTML", guide.source_ids))
    for label, ids in sets:
        if set(ids) != expected:
            errors.append(f"{label} coverage missing={sorted(expected-set(ids))}, extra={sorted(set(ids)-expected)}")
        duplicates = [key for key, count in Counter(ids).items() if count > 1]
        if duplicates:
            errors.append(f"{label} duplicate source IDs: {duplicates}")
    google_queries = {urllib.parse.parse_qs(urllib.parse.urlsplit(href).query).get("q", [""])[0] for href in guide.links if urllib.parse.urlsplit(href).hostname == "www.google.com"}
    for row in records:
        for key in ("category", "query", "alternate_query", "docs_url", "purpose", "evidence_note"):
            if not row.get(key, "").strip():
                errors.append(f"Missing {key}: {row['id']}")
        if rendered and row["query"] not in google_queries:
            errors.append(f"Missing rendered query: {row['id']}")
        if rendered and row["docs_url"] not in guide.links:
            errors.append(f"Missing rendered documentation: {row['id']}")
    categories = json.loads((ROOT / "research/categories.json").read_text())
    expected_categories = {"osint", "reversing", "forensics", "crypto", "misc", "web", "malware"}
    if {row["id"] for row in categories} != expected_categories or len(categories) != 7:
        errors.append("Expected exactly seven distinct category records")
    for row in records:
        if row["category"] not in expected_categories:
            errors.append(f"Unknown category: {row['id']}: {row['category']}")
    for row in records + categories:
        url = urllib.parse.urlsplit(row["docs_url"])
        if url.scheme not in ("http", "https") or not url.hostname:
            errors.append(f"Invalid documentation URL: {row['id']}")
    for row in categories:
        for key in ("query", "alternate", "docs_url", "purpose", "evidence_note"):
            if not row.get(key, "").strip():
                errors.append(f"Missing category {key}: {row['id']}")
        if rendered and row["query"] not in google_queries:
            errors.append(f"Missing rendered category query: {row['id']}")
    return errors, {"inventory_rows": len(inventory), "query_rows": len(records), "category_rows": len(categories), "html_source_ids": len(guide.source_ids)}


RESOURCE_FILES = [ROOT / "research/resources" / name for name in
                  ("forensics.json", "web-network.json", "reverse.json", "media.json", "crypto-foundations.json")]
ROUTE_COUNTS = {"forensics": 14, "malware": 4, "web": 10, "reversing": 6, "osint": 4, "crypto": 8, "misc": 4}


def check_catalog(guide, records=None, routes=None):
    inventory = json.loads((ROOT / "research/inventory.json").read_text())["tools"]
    records = records if records is not None else [row for path in RESOURCE_FILES for row in json.loads(path.read_text())]
    routes = routes if routes is not None else json.loads((ROOT / "research/routes.json").read_text())
    expected = {row["id"] for row in inventory}
    errors = []
    if len(inventory) != 200 or len(expected) != 200:
        errors.append("Expected exactly 200 distinct inventory IDs")
    for label, ids in [("research", [row["id"] for row in records]), ("HTML", guide.source_ids)]:
        if set(ids) != expected or len(ids) != 200:
            errors.append(f"{label} coverage mismatch or duplicate IDs")
    nodes = {node["attrs"].get("id"): node for node in guide.nodes if node["attrs"].get("id")}
    normalize = lambda value: " ".join(str(value).replace("`", "").split())
    def contains(node, text, label):
        if text and normalize(text) not in normalize(node["text"]):
            errors.append(f"Missing rendered {label}")
    def valid_url(url):
        parsed = urllib.parse.urlsplit(url)
        from build_notes import NOTE_OUTPUTS
        local = not parsed.scheme and not parsed.netloc and parsed.path in NOTE_OUTPUTS.values()
        return (local or (parsed.scheme in ("http", "https") and bool(parsed.hostname))) and not any(c.isspace() for c in url)
    by_id = {row["id"]: row for row in inventory}
    for row in records:
        node = nodes.get("tool-" + row["id"])
        if node is None:
            errors.append(f"Missing canonical tool anchor: {row['id']}")
            continue
        if node["attrs"].get("data-source-ids") != row["id"]:
            errors.append(f"Wrong canonical source identity: {row['id']}")
        contains(node, row.get("challenge_use"), f"purpose: {row['id']}")
        if by_id[row["id"]]["location"] == "installed in WSL":
            contains(node, "Windows / WSL", f"WSL platform: {row['id']}")
        for caveat in row.get("caveats", []):
            contains(node, caveat, f"caveat: {row['id']}")
        for key in ("name", "version", "location", "remarks"):
            contains(node, by_id.get(row["id"], {}).get(key), f"{key}: {row['id']}")
        for resource in row.get("resources", []):
            if not valid_url(resource["url"]):
                errors.append(f"Invalid resource URL: {row['id']}")
            if resource["url"] not in node["links"]:
                errors.append(f"Missing selected resource: {row['id']}")
    if Counter(row["category"] for row in routes) != Counter(ROUTE_COUNTS):
        errors.append("Wrong route category counts")
    if len({row["id"] for row in routes}) != 50:
        errors.append("Expected 50 distinct route IDs")
    route_nodes = [node for node in guide.nodes if "task-route" in node["attrs"].get("class", "").split()]
    if len(route_nodes) != 50 or any(node["tag"] != "details" for node in route_nodes):
        errors.append("Expected 50 rendered route details")
    for row in routes:
        node = nodes.get("route-" + row["id"])
        if node is None:
            errors.append(f"Missing route: {row['id']}")
            continue
        for key in ("title", "input", "expected", "fallback", "caveat", "verification"):
            if not isinstance(row.get(key), str) or not row[key].strip():
                errors.append(f"Missing route {key}: {row['id']}")
            if key != "verification":
                contains(node, row.get(key), f"route {key}: {row['id']}")
        if not row.get("steps") or not all(isinstance(step, str) and step.strip() for step in row["steps"]):
            errors.append(f"Missing route steps: {row['id']}")
        for step in row.get("steps", []):
            contains(node, step, f"route step: {row['id']}")
        if not row.get("tool_ids") or not set(row["tool_ids"]) <= expected:
            errors.append(f"Unknown or absent route tool: {row['id']}")
        for tool in row.get("tool_ids", []):
            if "#tool-" + tool not in node["links"]:
                errors.append(f"Missing route tool link: {row['id']}")
        if not row.get("references"):
            errors.append(f"Missing route references: {row['id']}")
        for ref in row.get("references", []):
            if not valid_url(ref["url"]) or ref["url"] not in node["links"]:
                errors.append(f"Invalid or missing route reference: {row['id']}")
    proposed = {node["attrs"]["data-source-ids"] for node in guide.nodes
                if node["attrs"].get("data-origin") == "TrendMicro proposal"}
    if proposed != {f"windows-{i}" for i in range(1, 33)}:
        errors.append("Wrong Trend Micro proposal grouping")
    for category in ROUTE_COUNTS:
        if category not in nodes or "#" + category not in guide.links:
            errors.append(f"Missing category/navigation: {category}")
    if re.search(r'\b(?:kali|windows)-\d+\b', nodes["main"]["text"]):
        errors.append("Internal approval IDs are visible in the guide")
    return errors, {"inventory_rows": len(inventory), "resource_rows": len(records), "route_rows": len(routes), "html_source_ids": len(guide.source_ids)}


def probe(url):
    result = {"url": url}
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; field-guide-link-check/1.0)"})
    try:
        with urllib.request.urlopen(request, timeout=18) as response:
            response.read(1024)
            result.update(status=response.status, final_url=response.url, outcome="reachable")
    except urllib.error.HTTPError as exc:
        outcome = "broken" if exc.code in (404, 410) else "blocked" if exc.code in (401, 403, 429) else "http-error"
        result.update(status=exc.code, final_url=exc.url, outcome=outcome)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        result.update(outcome="unverified", error=str(exc))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--html", default="index.html")
    parser.add_argument("--catalog", action="store_true", help="Require complete resource catalog and task-route integration")
    parser.add_argument("--catalog-data", action="store_true", help="Check complete query research without requiring HTML integration")
    parser.add_argument("--query-network", action="store_true", help="Probe research documentation URLs independently of HTML")
    args = parser.parse_args()
    if args.query_network:
        inputs = [ROOT / "research/categories.json", *sorted((ROOT / "research").glob("queries-*.json"))]
        snapshots = {str(p.relative_to(ROOT)): p.read_bytes() for p in inputs}
        rows = [row for content in snapshots.values() for row in json.loads(content)]
        cache = {}
        for filename in ("testing-links.json", "testing-query-links.json"):
            path = ROOT / "research" / filename
            if path.exists():
                previous = json.loads(path.read_text())
                for row in previous.get("external_links", []):
                    if row["outcome"] == "reachable":
                        cache[row["url"]] = dict(row, checked_at=row.get("checked_at", previous["checked_at"]), reused=True)
        urls = sorted({row["docs_url"] for row in rows})
        now = datetime.now(timezone.utc).isoformat()
        with ThreadPoolExecutor(max_workers=5) as pool:
            fresh = list(pool.map(probe, [url for url in urls if url not in cache]))
        results = [cache[url] for url in urls if url in cache] + [dict(row, checked_at=now) for row in fresh]
        report = {"checked_at": now, "input_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in snapshots.items()}, "external_links": results}
        (ROOT / "research/testing-query-links.json").write_text(json.dumps(report, indent=2) + "\n")
        print(dict(Counter(row["outcome"] for row in results)))
        print(json.dumps([row for row in results if row["outcome"] != "reachable"], indent=2))
        return
    # Exercise malformed cases so this check cannot silently accept common defects.
    _, bad = check('<p id="x"></p><p id="x"></p><a href="#missing">x</a><a href="https://www.google.com/search?q=a b&x=1">x</a>')
    assert len(bad) == 4, bad
    _, bad_urls = check('<a href="javascript:alert(1)">x</a><a href="https://">x</a><a href="http://[">x</a>')
    assert len(bad_urls) == 3, bad_urls
    html = (ROOT / args.html).read_text()
    guide, errors = check(html)
    report = {"checked_at": datetime.now(timezone.utc).isoformat(), "html_file": args.html, "html_sha256": hashlib.sha256(html.encode()).hexdigest(), "anchors": len(guide.links), "ids": len(guide.ids), "errors": errors}
    if args.catalog or args.catalog_data:
        catalog_errors, counts = check_catalog(guide) if args.catalog else check_archive(guide)
        errors.extend(catalog_errors)
        report.update(counts)
        inputs = [ROOT / "research/inventory.json", ROOT / "research/tool-origins.json", ROOT / "research/routes.json", *RESOURCE_FILES] if args.catalog else [ROOT / "research/inventory.json", ROOT / "research/categories.json", *sorted((ROOT / "research").glob("queries-*.json"))]
        report["input_sha256"] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    if args.catalog:
        import copy
        import sys
        sys.path.insert(0, str(ROOT))
        import build_catalog
        escaped = build_catalog.inline('`<script>alert(1)</script>` & "quoted"')
        assert "<script>" not in escaped and "&lt;script&gt;" in escaped
        inv, resource_map, authored_routes = build_catalog.load_data()
        if build_catalog.render_page((ROOT / "guide-template.html").read_text(), inv, resource_map, authored_routes) != html:
            errors.append("Stale generated guide")
        try:
            build_catalog.render_page((ROOT / "guide-template.html").read_text() + '<a href="#missing-negative-control">broken</a>', inv, resource_map, authored_routes)
        except AssertionError:
            pass
        else:
            raise AssertionError("Renderer accepted a missing local fragment")
        records = [row for path in RESOURCE_FILES for row in json.loads(path.read_text())]
        routes = json.loads((ROOT / "research/routes.json").read_text())
        broken_records = copy.deepcopy(records)
        broken_records[0]["id"] = "unapproved-tool"
        assert any("coverage" in error for error in check_catalog(guide, broken_records, routes)[0])
        broken_routes = copy.deepcopy(routes)
        broken_routes[0]["tool_ids"] = ["unapproved-tool"]
        assert any("Unknown or absent route tool" in error for error in check_catalog(guide, records, broken_routes)[0])
        broken_routes[0]["category"] = "unknown"
        assert "Wrong route category counts" in check_catalog(guide, records, broken_routes)[0]
        alias = ROOT / "keyword-preview.html"
        if args.html == "index.html" and (not alias.exists() or alias.read_bytes() != (ROOT / args.html).read_bytes()):
            errors.append("Generated HTML aliases differ")
    if args.network:
        urls = sorted({href for href in guide.links if href.startswith("https://") and urllib.parse.urlsplit(href).hostname != "www.google.com"})
        with ThreadPoolExecutor(max_workers=5) as pool:
            report["external_links"] = list(pool.map(probe, urls))
    path = ROOT / "research" / ("testing-links.json" if args.network else "testing-data.json" if args.catalog_data else "testing-static.json")
    if args.html != "index.html":
        path = path.with_name(path.name.replace("testing-", "testing-preview-"))
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "external_links"}))
    if args.network:
        print(dict(Counter(row["outcome"] for row in report["external_links"])))
    raise SystemExit(bool(errors))


if __name__ == "__main__":
    main()
