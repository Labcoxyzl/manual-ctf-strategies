"""Build the all-tool Markdown field reference from reviewed recipes and inventory."""
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from build_catalog import CATEGORIES, load_data, platform_label, is_proposed, tool_order

ROOT = Path(__file__).resolve().parent


def guide_link(path):
    from build_notes import NOTE_OUTPUTS
    url = urlsplit(path)
    return urlunsplit(url._replace(path=NOTE_OUTPUTS.get(url.path, url.path)))


def render_cheatsheet():
    inventory, resources, _ = load_data()
    recipes = json.loads((ROOT / 'research/validation/tool-recipes.json').read_text())
    playbooks = json.loads((ROOT / 'research/validation/category-playbooks.json').read_text())
    by_id = {tool['id']: tool for tool in inventory}
    expected = set(by_id)
    assert len(inventory) == len(expected) == 200
    assert set(recipes) == expected, 'Recipes must cover each exact approved entry'
    assert set(playbooks) == set(CATEGORIES), 'Expected seven category playbooks'
    lines = [
        '# CTF tool cheatsheet', '',
        'The 32 tools proposed by Trend Micro appear first in each category. The other 168 approved entries were participant requests. Both groups are approved; check the recorded platform and version.', '',
        ' · '.join(f'[{name}](#{slug})' for slug, name in CATEGORIES.items()), '',
        '[Core workflows](CORE_WORKFLOWS.md) · [Hashcat commands](HASHCAT.md) · [Python scripts and templates](scripts/templates/README.md) · [Competition rules](RULES.html)', '',
        'Replace uppercase filenames, hosts and other placeholders before running a command. Preserve original files. First actions are reference workflows unless a local check is explicitly identified. Kali availability is best effort; approval does not prove an installed version or backend works.', '',
    ]
    for slug, category in CATEGORIES.items():
        playbook = playbooks[slug]
        for field in ('first_steps', 'expected', 'fallback', 'approved_tools'):
            assert playbook.get(field), (slug, field)
        assert set(playbook['approved_tools']) <= expected
        lines += [f'<a id="{slug}"></a>', f'## {category}', '']
        lines += [f'{i}. {step}' for i, step in enumerate(playbook['first_steps'], 1)]
        lines += ['', f'**Look for:** {playbook["expected"]}', '', f'**If blocked:** {playbook["fallback"]}', '']
        lines += ['**Start with:** ' + ' · '.join(
            f'[{by_id[tool_id]["name"]} ({platform_label(by_id[tool_id])})](#approved-{tool_id})'
            for tool_id in playbook['approved_tools']), '']
        for link in playbook.get('helper_links', []):
            lines += [f'[{link["title"]}]({guide_link(link["path"])})', '']
        selected = sorted((tool for tool in inventory if resources[tool['id']]['categories'][0] == category), key=tool_order)
        for tool in selected:
            row, recipe = resources[tool['id']], recipes[tool['id']]
            for field in ('first_action', 'expected', 'fallback', 'verification'):
                assert isinstance(recipe.get(field), str) and recipe[field].strip(), (tool['id'], field)
            lines += [f'<a id="approved-{tool["id"]}"></a>', f'### {tool["name"]} · {platform_label(tool)}' + (' · Trend Micro proposal' if is_proposed(tool) else ''), '',
                      f'**Use for:** {row["challenge_use"]}', '', f'**First action:** {recipe["first_action"]}', '']
            if recipe.get('command'):
                lines += ['```sh', recipe['command'], '```', '']
            lines += [f'**Expected:** {recipe["expected"]}', '', f'**If blocked:** {recipe["fallback"]}', '']
            general_notes = (
                "Recorded platform/version is an approval-list fact, not a successful runtime check.",
                "Baseline documentation retained: this supporting utility needs a short task lookup, not a separate tutorial. Installed behavior was not tested.",
                "Event Kali installation is best-effort; local availability and version are untested.",
            )
            caveats = []
            for caveat in row.get('caveats', []):
                for note in general_notes:
                    caveat = caveat.replace(note, '').strip()
                if caveat and caveat not in caveats:
                    caveats.append(caveat)
            # Approval metadata remains exact; checks and recipe claims are kept separate.
            metadata = [f'Version: {tool["version"] or "not specified"}']
            if tool['location']:
                metadata.append(f'Location: {tool["location"]}')
            if tool['remarks']:
                metadata.append(tool['remarks'].strip())
            lines += ['**Availability:** ' + ' · '.join(metadata), '']
            lines += [f'- {caveat}' for caveat in caveats]
            if caveats:
                lines.append('')
            if recipe.get('helper'):
                lines += [f'[Related helper]({guide_link(recipe["helper"])})', '']
            references = recipe.get('references') or row['resources']
            lines += [' · '.join(f'[{ref["title"]}]({ref["url"]})' for ref in references), '']
            if recipe['verification'] != 'source-guided':
                lines += [f'**Check:** {recipe["verification"]}', '']
    return '\n'.join(lines)


if __name__ == '__main__':
    (ROOT / 'CTF_CHEATSHEET.md').write_text(render_cheatsheet())
    print('Rendered seven categories and 200 approved-tool sections')
