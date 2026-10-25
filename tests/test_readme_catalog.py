"""Keep the README tool index aligned with the approved workbook and guide."""
from collections import Counter
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import build_catalog as catalog


class ReadmeCatalogTests(unittest.TestCase):
    def test_index_matches_sources_and_targets(self):
        inventory, resources, _ = catalog.load_data()
        readme = (ROOT / "README.md").read_text()
        start, end = "<!-- approved-tools:start -->", "<!-- approved-tools:end -->"
        self.assertEqual(readme.count(start), 1)
        self.assertEqual(readme.count(end), 1)
        block = readme.split(start, 1)[1].split(end, 1)[0].lstrip("\n")
        self.assertEqual(block, catalog.render_readme_catalog(inventory, resources))
        ids = re.findall(r"CTF_CHEATSHEET\.md#approved-((?:windows|kali)-\d+)", block)
        self.assertEqual(len(ids), sum(len(row["categories"]) for row in resources.values()))
        self.assertEqual(set(ids), {tool["id"] for tool in inventory})
        self.assertEqual(Counter(ids), {tool_id: len(row["categories"]) for tool_id, row in resources.items()})
        self.assertEqual(block.count("**Trend Micro proposal**"),
                         sum(len(resources[tool["id"]]["categories"]) for tool in inventory if catalog.is_proposed(tool)))
        self.assertEqual(block.count("**Participant request**"),
                         sum(len(resources[tool["id"]]["categories"]) for tool in inventory if not catalog.is_proposed(tool)))
        self.assertEqual(block.count("| Tool and origin |"), len(catalog.CATEGORIES))
        cheatsheet = (ROOT / "CTF_CHEATSHEET.md").read_text()
        page = (ROOT / "index.html").read_text()
        for tool_id in set(ids):
            self.assertIn(f'<a id="approved-{tool_id}"></a>', cheatsheet)
            self.assertIn(f'id="tool-{tool_id}"', page)


if __name__ == "__main__":
    unittest.main()
