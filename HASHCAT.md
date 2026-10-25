# Hashcat competition cheatsheet

Use one process with `-O -w 3` as a high-throughput starting point for a dictionary attack. No flag combination is fastest for every hash, device or candidate set. These settings have not been benchmarked on competition machines.

## Choose the mode and devices

Match the full hash syntax and its source to [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes). A hash identifier's guess alone is insufficient. Replace `MODE` with the numeric hash mode.

For a file of hashes, use the existing tools to list candidates:

```sh
hashcat --identify hashes.txt
hashid -m hashes.txt
```

Use whichever is installed. These commands match structure, not provenance: a bare 32-hex-character digest can fit MD5, NTLM and other modes. Narrow the list using the source application, salt/encoding format, or a known input/output pair; do not start cracking the first listed mode merely because it appears first.

```sh
hashcat -I
```

Replace `GPU_IDS` with the GPU device numbers reported above. Use `1,2` only if those are your GPUs; one process can use both. Check that the competition environment actually exposes a working GPU backend.

## Dictionary attempt

Run from the folder containing `hashes.txt` and `candidates.txt`:

```sh
hashcat -m MODE -a 0 hashes.txt candidates.txt \
  -d GPU_IDS -O -w 3 \
  --session ctf --status --status-timer 10
```

This tests the wordlist unchanged. Add `--runtime=60` for a bounded first attempt. Keep the installed wordlist unchanged and choose candidates from the challenge evidence.

| Setting | When to change it |
| --- | --- |
| `-O` | Enables optimized kernels but limits candidate length. Check the startup maximum and `Rejected` count. Remove it when longer candidates matter; rejected candidates were not tested. |
| `-w 3` | High workload. Use `-w 2` if the desktop becomes unresponsive. `-w 4` targets headless workloads and is not automatically faster. Compare sustained speed on the actual attack. |
| `-d GPU_IDS` | Selects devices. For independent simultaneous attacks, use disjoint device IDs and different session names. Competing processes on the same GPU are not a default speed improvement. |
| `--session ctf` | Names the checkpoint files. Use a new name for a separate attack. It does not increase cracking speed. |
| `--status --status-timer 10` | Prints progress every ten seconds; monitoring does not increase speed. |

Leave `-n`, `-u` and `-T` to autotuning unless measurements justify manual tuning. Do not use `--force` or disable thermal monitoring as performance shortcuts.

## Stop, resume and read results

Press **c** to stop at the next checkpoint. Keep the session files and inputs in place, then resume from the original working directory:

```sh
hashcat --session ctf --restore
```

Display recovered values using the same hash mode:

```sh
hashcat -m MODE hashes.txt --show
```

Validate recovered values against the supplied artifact and keep password output private. `Cracked` means recovery succeeded. `Exhausted` means the tested candidates were consumed; it does not prove the password is unrecoverable. A parser or backend error means the attempt did not run correctly.

## If there is no match

Check the mode, device support and rejected candidates first. Also check what lengths and patterns your wordlist actually contains: an exhausted list with no four-character entries has not tested any four-character passwords. If a recovered checker constrains length or rearranges input, reconstruct that transformation before choosing candidates. Then use evidence to choose a better wordlist, an appropriate rule set (`-r RULE_FILE`) or a known-pattern mask. More rules and more candidates are not automatically more efficient. Archives and documents may need a format-specific extractor, such as the matching installed John jumbo converter, before Hashcat can use them.

[Hashcat options](https://hashcat.net/wiki/?id=hashcat) · [Performance and troubleshooting FAQ](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions)
