# Actual named-tool exercises

All inputs here are authored synthetic data. No historical flags, live network targets, unknown binaries, downloads, or installations were used. [results.json](results.json) records actual outputs and controls; [SHA256SUMS](SHA256SUMS) binds the local artifacts. Generated binaries and exported objects stay in ignored `work/`.

| Tool actually exercised | Local version | Evidence |
| --- | --- | --- |
| CyberChef offline web app and workers | 11.5.0, browser 148.0.7778.96 | From Base64 → Gunzip returned 51 expected bytes; non-gzip input failed with `Gunzip - invalid file signature:112,108`. Offline browser context, zero HTTP(S) requests, zero page errors. |
| TShark, Linux | 4.2.2 | HTTP export reconstructed the expected body across three segments and ignored a retransmission. |
| TShark, installed Windows Wireshark CLI | 4.6.2 | The same positive export and missing-middle negative control passed over a WSL UNC path. |
| Ghidra headless | 12.1.4, OpenJDK 21.0.12.1 | Imported the authored ELF and decompiled `check_phrase`; the recovered comparison accepted its literal, rejected a one-character mutation, and rejected missing arguments. |

The expected output SHA-256 is `45ccc5cf7b56c0d158ad7920dc13d203b363fad7a7e13be0da5da5969374d963`. Both TShark exports and CyberChef matched it byte for byte. Ghidra recovered:

```c
iVar1 = strcmp(param_1,"orchid-copper-27");
return iVar1 == 0;
```

The Wireshark **GUI was not tested**. Wireshark is organiser-proposed; the separately requested TShark supplement supplies these actual packet-analysis results. The shared Playwright MCP profile was locked by an existing browser process, so it was preserved. The CyberChef check used a temporary isolated WSL Playwright context and closed only its own browser.

## Reproduce from the repository root

These commands use already installed tools. Start with a fresh `work/` directory; deleting this specific directory removes only generated artifacts from these exercises. All substantial tool invocations have a 120-second outer limit.

```bash
source tools/activate.sh
exercise_root="$PWD/research/validation/round2/tool-exercises"
rm -rf -- "$exercise_root/work"
mkdir -p "$exercise_root/work" "$exercise_root/logs"
python "$exercise_root/make_fixtures.py"
```

Run the actual offline CyberChef app. The fixture generator authors Base64(gzip(known text)); it does not stand in for CyberChef decoding. The browser script loads the recipe through the app's `loadURIParams` method, waits for its worker output, checks the exact editor contents, and captures [the rendered result](logs/cyberchef-positive.png).

```bash
PLAYWRIGHT_MODULE=/home/ubuntu/.npm/_npx/9833c18b2d85bc59/node_modules/playwright \
CHROMIUM_PATH=/opt/google/chrome/chrome \
timeout 120s node "$exercise_root/check_cyberchef.cjs" \
  > "$exercise_root/logs/cyberchef.stdout" 2> "$exercise_root/logs/cyberchef.stderr"
```

For manual use, open `tools/windows/CyberChef/app/CyberChef_v11.5.0.html`, load [recipe.json](fixtures/recipe.json), and paste [gzip-base64.txt](fixtures/gzip-base64.txt) into Input. The recipe uses `From Base64` with alphabet `A-Za-z0-9+/=`, remove-non-alphabet enabled, strict mode enabled, then `Gunzip` without arguments. [not-gzip-base64.txt](fixtures/not-gzip-base64.txt) is the negative input.

Run both TShark installations against the same complete and incomplete captures. The packet generator uses installed Scapy 2.7.0 only to author fixtures. Actual HTTP reassembly and export occur in TShark.

```bash
for variant in positive negative; do
  capture=segmented-http.pcap
  if [ "$variant" = negative ]; then capture=missing-middle.pcap; fi
  mkdir -p "$exercise_root/work/tshark-linux-$variant" "$exercise_root/work/tshark-windows-$variant"
  timeout 120s tshark -r "$exercise_root/fixtures/$capture" -q \
    --export-objects "http,$exercise_root/work/tshark-linux-$variant" \
    > "$exercise_root/logs/tshark-linux-$variant.stdout" 2> "$exercise_root/logs/tshark-linux-$variant.stderr"
  timeout 120s '/mnt/c/Program Files/Wireshark/tshark.exe' \
    -r "$(wslpath -w "$exercise_root/fixtures/$capture")" -q \
    --export-objects "http,$(wslpath -w "$exercise_root/work/tshark-windows-$variant")" \
    > "$exercise_root/logs/tshark-windows-$variant.stdout" 2> "$exercise_root/logs/tshark-windows-$variant.stderr"
done
tshark --version > "$exercise_root/logs/tshark-linux-version.txt"
timeout 20s '/mnt/c/Program Files/Wireshark/tshark.exe' --version > "$exercise_root/logs/tshark-windows-version.txt"
tshark -r "$exercise_root/fixtures/segmented-http.pcap" -Y 'tcp.len > 0' \
  -T fields -e frame.number -e tcp.seq -e tcp.len -e tcp.analysis.retransmission -e http.file_data \
  > "$exercise_root/logs/tshark-packets.tsv"
tshark -r "$exercise_root/fixtures/segmented-http.pcap" -Y 'tcp.srcport == 80 && tcp.len > 0' \
  -T fields -e tcp.payload > "$exercise_root/logs/tcp-payload-capture-order.hex"
timeout 20s tshark -r "$exercise_root/fixtures/segmented-http.pcap" -q -z follow,tcp,raw,0 \
  > "$exercise_root/logs/follow-tcp-raw.txt"
```

Both positive directories contain `report.txt` (51 bytes). Both negative directories are empty. Capture-order payload concatenation contains 226 server bytes because it repeats a 91-byte segment; Follow TCP yields the correct 135 bytes including HTTP headers. `check_results.py` separates the tab-prefixed server direction, removes HTTP headers, and verifies the known body. It does not implement TCP reassembly.

Compile only the authored source, then perform an actual Ghidra import, analysis and decompile. `ghidra-headless` is the existing launcher that selects `/usr/lib/jvm/java-21-openjdk-amd64`; ordinary `java` on `PATH` is not assumed to be suitable.

```bash
gcc -O0 -fno-builtin -fno-pie -no-pie "$exercise_root/checker.c" -o "$exercise_root/work/checker"
timeout 120s ghidra-headless "$exercise_root/work" fixture \
  -import "$exercise_root/work/checker" -scriptPath "$exercise_root" \
  -postScript RecoverComparison.java check_phrase "$exercise_root/logs/decompiled.c" \
  -analysisTimeoutPerFile 60 -max-cpu 2 -deleteProject \
  > "$exercise_root/logs/ghidra.stdout" 2> "$exercise_root/logs/ghidra.stderr"
/usr/lib/jvm/java-21-openjdk-amd64/bin/java -version > "$exercise_root/logs/java-version.txt" 2>&1
gcc --version > "$exercise_root/logs/gcc-version.txt"
cp /opt/ctf-tools/ghidra_12.1.4_PUBLIC/Ghidra/application.properties "$exercise_root/logs/ghidra-application.properties"
python "$exercise_root/check_results.py"
(cd "$exercise_root" && sha256sum -c SHA256SUMS)
```

The checker validation obtains its candidate from Ghidra's exported C, then runs only the authored executable. Expected outcomes: recovered candidate → exit 0 / `accepted`; one-character mutation → exit 1 / `rejected`; missing argument → exit 2 / empty output. The final validation message is `PASS: CyberChef positive/negative; Linux and Windows TShark positive/missing-segment; Ghidra recovered accept/reject/arity`.

## Corrections demonstrated for the guide

- A version/help check or empty CyberChef recipe does not establish the operation works. Retain a small layered input, recipe JSON, exact output hash, and wrong-layer control.
- `tshark` on this WSL `PATH` resolves to Linux 4.2.2, not the installed Windows 4.6.2. State which executable was used; pass Windows paths with `wslpath -w`.
- `-T fields -e tcp.payload` in capture order is not a stream reconstruction. This fixture duplicates 91 bytes. Use protocol-aware object export or Follow TCP and distinguish directions; `follow,tcp,raw` prints hexadecimal text with framing, not a naked binary file.
- Successful import or headless startup does not establish decompilation. Export a named function with `DecompInterface`, check its output, and verify the comparison against the independently authored behavior.
- Keep GUI coverage separate from CLI coverage. This run establishes TShark, not desktop Wireshark interaction; Ghidra covers an unstripped O0 ELF, not arbitrary binaries.

## Primary references

- [CyberChef 11.5.0 App source](https://github.com/gchq/CyberChef/blob/v11.5.0/src/web/App.mjs): `loadURIParams`, `setInput`, `setRecipeConfig` and recipe/input state handling.
- [From Base64 operation](https://github.com/gchq/CyberChef/blob/v11.5.0/src/core/operations/FromBase64.mjs) and [Gunzip operation](https://github.com/gchq/CyberChef/blob/v11.5.0/src/core/operations/Gunzip.mjs): argument order and gzip decompression behavior.
- [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html): offline `-r`, `--export-objects`, `-T fields`, and `-z follow,prot,mode,filter` output and direction conventions.
- [Ghidra DecompInterface API](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html): `openProgram`, `decompileFunction`, completion check and disposal. Installed headless reference: `/opt/ctf-tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadlessREADME.md`.

No Wireshark desktop session, unfamiliar binary execution, or live traffic was checked. These fixtures establish the specific workflows above, not general support for every format or target.
