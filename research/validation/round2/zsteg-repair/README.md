# zsteg runtime repair

The project image now runs the default zsteg scan successfully. The Dockerfile appends one `RUN` installing `file`; every earlier build layer was cached. Package comparison found exactly one addition, `file 1:5.47-4`, with no removals or version changes. The original image layers and zsteg source hashes are unchanged. The new layer adds 5,330,886 bytes to the image.

| State | Image SHA-256 | Evidence |
| --- | --- | --- |
| Original, preserved as `cyber-sea-game-2026-tools:before-zsteg-fix` | `804df10b7a628b28cc0ea0143111851c9668de3c706a7e71f5a98fa4ece68954` | `before-final/summary.json`: 12 checks passed, including expected missing-`file` failure |
| Candidate `cyber-sea-game-2026-tools:runtime-fix` | `0e138ff37dfe13044aebf35f93e60d801ff04c6775c265509f6a2bc618c3f3b3` | `candidate/summary.json`: 14 checks passed |
| Promoted `cyber-sea-game-2026-tools:local` | Same as candidate | `promoted/summary.json`: 14 checks passed, including scans/extractions through `tools/bin-distro/zsteg` |

The existing `workflow-gaps/run-3/carrier.png` contains a red LSB plane with the authored 14-byte message `TRAINING-LSB\n\0`, followed by zero padding. Default scanning now finds the selector `b1,r,lsb,xy`. Exact extraction returns `TRAINING-LSB\n` (13 bytes; SHA-256 `46fa40b5ba0894d8df2146e48e43d4381223c7866695e3452f99e6c07334b72e`). Independent pixel decoding verifies the original 32-byte plane. Both images strip the authored trailing NUL and remaining padding; this repair does **not** establish full binary tail preservation. A wrong green-plane selector and a new empty carrier both extract empty output, and scanning the empty carrier does not produce the known message.

Versions, exact commands, exit codes, stdout/stderr and source hashes are saved with each run. Zsteg is gem version 0.2.14. Its `--version` option prints `version unknown` and exits 1, while `--help` succeeds. The incomplete `before/` and `before-confirmed/` attempts preserve harness calibration evidence: unsupported `--version`, then Kali shell `command -v file` returning 127 for absence. These were corrected before the completed runs.

Build command (from the project root):

```bash
docker build --progress=plain --pull=false -t cyber-sea-game-2026-tools:runtime-fix tools/distro
```

Recheck using a new output directory:

```bash
/opt/ctf-tools/py312/bin/python research/validation/round2/zsteg-repair/verify.py --image cyber-sea-game-2026-tools:local --expect working --launcher research/validation/round2/zsteg-repair/recheck-1
```

Rollback, if needed, restores the preserved image and its recorded ID/size:

```bash
docker tag cyber-sea-game-2026-tools:before-zsteg-fix cyber-sea-game-2026-tools:local
cp research/validation/round2/zsteg-repair/image-id.txt.before tools/distro/image-id.txt
```

No host installation, pruning, image deletion, publishing or unrelated tool update occurred. The original workflow-gaps evidence was preserved; its historical harness still expects the original default-scan failure and must be updated before rerunning against the promoted image. Validation is limited to synthetic zsteg behavior, not the full toolkit or competition-host parity.
