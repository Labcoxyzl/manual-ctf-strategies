# Volatility 3: bounded public-fixture validation

Validated on 2026-10-25 with the prepared **Volatility 3 2.28.2** launcher. This is an independent **32-bit Windows XP SP2** regression fixture, not the missing practice31 challenge. It does not establish Windows 11, process-minidump, or arbitrary-image support.

| Check | Observed result |
| --- | --- |
| Existing cache, offline `windows.info` | Exit 1: matching kernel symbol table missing; memory layer recognized. |
| Fresh owned cache, matching local symbols, network disabled | `windows.info` succeeded; 32-bit NT 5.1, SP2 build. |
| `windows.pstree` / `windows.cmdline` | 47 rows each; identical PID sets. System process fields matched the upstream XP-specific expected result. |
| One `windows.dumpfiles --virtaddr 0x82220e78` | Two cached PE32 DLL representations, 15,385,664 and 16,233,960 bytes; both MD5 hashes exactly matched the upstream expected set. DOS/PE signatures and `file` classification also passed. |
| Warm-cache `windows.info` rerun | Identical parsed output, again with networking disabled. |
| Generated 64 KiB zero-filled invalid input | Exit 1, both layer and symbol requirements unsatisfied. This is a negative control, not a memory fixture. |

All final plugin runs used `unshare -Urn`, `--offline`, `--parallelism off`, an owned `--cache-path` and `-s` directory, at most two CPUs, a 2 GiB address-space limit, 32 MiB per-output-file limit, and a 120-second deadline. The namespace recipe had only an inactive loopback interface and no routes. The positive sequence first passed from an empty owned cache, which then contained exactly one Windows symbol record pointing to the owned symbol file. After strengthening the helper's stale-result and symbol-path checks, the complete sequence passed again with that warm cache; its final command metadata records 0.27–1.50 seconds per run. Extracted files were never executed; no sample endpoints were contacted.

## Provenance and limits

The [Foundation test corpus](https://github.com/volatilityfoundation/volatility3-test-data) explicitly supplies public regression images. Its [v0.0.1 release](https://github.com/volatilityfoundation/volatility3-test-data/releases/tag/v0.0.1) supplied `win-xp-laptop-2005-06-25.img.gz`. HEAD and a ranged gzip-trailer read preceded the download. Compressed size was 180,343,409 bytes; bounded decompression produced 536,715,264 bytes. Both originals are mode `0444` locally.

- Compressed SHA-256: `4cbdd5725adbb9505c8b3f4a51f0f042bac8dd53bf1dcc4b3bb7c71a6c8a74cd`, matching the [official digest](https://github.com/volatilityfoundation/volatility3-test-data/blob/1cd2df00a1a286c0948e09b220dc8c550f057d27/images/SHA256SUMS).
- Expanded SHA-256: `c4aeeb1b461378eef796944884d1d60adaa99cbae4d035923c144b08deee1e6e` (locally calculated).
- Independent expected observations: upstream [XP process test](https://github.com/volatilityfoundation/volatility3/blob/77ff0b1932d77527f850c8ced01d85805ea7bf97/test/plugins/windows/windows.py) and [known extraction hashes](https://github.com/volatilityfoundation/volatility3/blob/77ff0b1932d77527f850c8ced01d85805ea7bf97/test/known_files.json). Saved source snapshots were checked against that pinned commit.

The corpus README links the [Volatility Software License 1.0](https://volatilityfoundation.org/license/vsl-v1.0); it is not represented as public domain. Raw images, symbols, successful command output and recovered objects remain under ignored `artifacts/`. Source notices are retained. A repository checksum establishes agreement with that publisher's bytes, not an independently authenticated acquisition history. The upstream MD5 values are regression oracles, not a security-strength authenticity guarantee.

## Smallest guide correction

Replace the old claim that no image/symbol execution was available with the bounded result above. Keep the general `info → pstree → cmdline → evidence-selected extraction` sequence. Add one preparation instruction: **resolve and verify the exact PDB database name, GUID and age before going offline; then rerun against the image using the intended symbol/cache paths.** A symbol error remains failed analysis, not an empty finding.

For this fixture, missing-symbol diagnostics identified `ntoskrnl.pdb`, GUID `32962337F0F646388B39535CD8DD70E8`, age `2`. The 4,099,072-byte PDB was fetched directly from the [Microsoft HTTPS symbol endpoint](https://msdl.microsoft.com/download/symbols/ntoskrnl.pdb/32962337F0F646388B39535CD8DD70E82/ntoskrnl.pdb). Its locally recorded SHA-256 is in `pdb-download.json`; no separate vendor digest/signature was supplied. Do not reuse this identity for another image.

With the already downloaded PDB and prepared environment, the successful local conversion was:

```bash
# From the repository root; all paths below are this validation fixture only.
memory_dir=research/validation/round2/memory
tools/python/volatility3/bin/python -m volatility3.framework.symbols.windows.pdbconv \
  -f "$memory_dir/artifacts/ntoskrnl.pdb" -p ntoskrnl.pdb \
  -o "$memory_dir/artifacts/symbols/windows/ntoskrnl.pdb/32962337F0F646388B39535CD8DD70E8-2.json.xz"
python3 "$memory_dir/verify.py"
```

In installed 2.28.2, omitting `-p ntoskrnl.pdb` during local `-f` conversion produced `database: unknown.pdb`, which failed discovery despite the correct output filename and GUID. The corrected conversion retained the PDB database identity. The first conversion also failed when the venv Python symlink was resolved to system Python; invoke the venv path as shown. Both failed attempts are preserved, and neither is counted as a successful memory analysis.

## Evidence files

`result.json`, `download.json`, `symbol-metadata.json`, `cache-after.json`, `network-and-fresh-cache.json`, and `logs/*.meta.json` hold sanitized results and exact command metadata. `verify.py` repeats the offline checks with assertions and fresh extraction output. `sources/` holds the release, license, digests and upstream test snapshots. Raw outputs and the extraction manifest are local-only under `artifacts/`.

The general PID-plus-regex extraction selector in the core guide was help-checked, not executed here; this test used one upstream-known virtual `_FILE_OBJECT` address. No practice31 solve, modern-Windows coverage, malicious-process conclusion, or complete-file recovery claim is made.
