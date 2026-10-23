#!/usr/bin/env python3
"""Extract approved workbook rows without importing the unapproved sheet."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from zipfile import ZipFile

NS = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
DEFAULT_SOURCE = Path('/mnt/c/Users/Nicho/Downloads/AJCCBC_CTF2026_Tool_Review_List_261015r11.xlsx')


def extract(source):
    records = []
    with ZipFile(source) as archive:
        shared = [
            ''.join(node.itertext())
            for node in ET.fromstring(archive.read('xl/sharedStrings.xml')).findall('s:si', NS)
        ]
        for platform, sheet, expected in [('windows', 1, 39), ('kali', 2, 161)]:
            root = ET.fromstring(archive.read(f'xl/worksheets/sheet{sheet}.xml'))
            platform_rows = []
            for row in root.findall('s:sheetData/s:row', NS):
                cells = {}
                for cell in row:
                    value = cell.find('s:v', NS)
                    value = value.text if value is not None else ''
                    if cell.get('t') == 's':
                        value = shared[int(value)]
                    elif cell.get('t') == 'inlineStr':
                        value = ''.join(cell.find('s:is', NS).itertext())
                    cells[re.sub(r'\d', '', cell.get('r'))] = value
                if not cells.get('B', '').isdigit():
                    continue
                number = int(cells['B'])
                platform_rows.append({
                    'id': f'{platform}-{number}',
                    'platform': platform,
                    'number': number,
                    'source_row': int(row.get('r')),
                    'name': cells['C'],
                    'list': cells.get('D', ''),
                    'version': cells.get('E', ''),
                    'official_url': cells.get('F', '') if platform == 'windows' else '',
                    'category': cells.get('G', '') if platform == 'windows' else '',
                    'location': cells.get('I' if platform == 'windows' else 'F', ''),
                    'remarks': cells.get('H' if platform == 'windows' else 'G', ''),
                    'original_text': cells.get('H', '') if platform == 'kali' else '',
                })
            assert len(platform_rows) == expected, (platform, len(platform_rows))
            assert [item['number'] for item in platform_rows] == list(range(1, expected + 1))
            assert all(item['name'] for item in platform_rows)
            records.extend(platform_rows)
    assert len({item['id'] for item in records}) == 200
    return {
        'source_file': source.name,
        'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'counts': {'windows': 39, 'kali': 161},
        'notes': [
            'Each record is one approved workbook row; repeated names are retained.',
            'Kali source rows have no official URL or category column; empty values mean not supplied.',
            'Official URL values are copied verbatim and may contain explanatory text.',
        ],
        'tools': records,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', nargs='?', type=Path, default=DEFAULT_SOURCE)
    parser.add_argument('--output', type=Path, default=Path(__file__).parent / 'research/inventory.json')
    args = parser.parse_args()
    inventory = extract(args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + '\n')
    print(f"Wrote {len(inventory['tools'])} rows to {args.output}")
