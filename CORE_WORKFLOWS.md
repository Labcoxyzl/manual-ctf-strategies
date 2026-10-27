# Core tool workflows

These workflows start with the 32 tools proposed by Trend Micro, including their WSL entries. Other approved tools are identified as supplements. [Practice files and exact checks](examples/core/README.md) · [All 200 tool entries](CTF_CHEATSHEET.md).

[Decode](#decode) · [Packets](#pcap) · [Images](#media) · [PDF](#pdf) · [Disk](#disk) · [Native code](#native) · [Web](#web) · [Memory](#memory) · [Crypto](#crypto) · [CAN logs](#can)

Use a new working directory, preserve originals and replace uppercase placeholders. Commands below use WSL/Bash unless marked otherwise. Binary redirection belongs in that shell. On the prepared research computer, `source tools/activate.sh` enables existing launchers; those machine-specific tools are separate from the portable reference files. Project container launchers require a working directory inside this project; for an export copied elsewhere, use tools installed in that environment. On the competition machine, confirm the actual launcher and runtime. A version/help check alone does not establish a working analysis path.

<a id="decode"></a>
## Encoded text or bytes — CyberChef

Open the prepared offline CyberChef HTML. Paste encoded text; load a file when the input is binary. Apply one operation, inspect its output, then decide whether another is justified.

Calibration: `VHJhY2U=` → **From Base64** → `Trace`. `NTQ3MjYxNjM2NQ==` → **From Base64** → `5472616365` → **From Hex** → `Trace`. Temporarily append **To Hex** to inspect bytes, then remove that display operation before saving raw output. Save the recipe/settings separately from the input and compare expected byte length or parse the resulting format. Printable output alone is not proof; unreadable UTF-8 can still be correct bytes. Undo a contradictory layer. Magic gives candidates, not validation.

<a id="pcap"></a>
## PCAP — Wireshark; TShark when repetition helps

Open the capture → Statistics → Conversations → choose a peer pair → apply its filter. Select a packet → Follow the matching stream. Record packet numbers, endpoints, stream number and direction. Use File → Export Objects → matching protocol for transferred files; save into a fresh directory and inspect the exported file. A displayed ASCII/hex transcript is not automatically the original binary payload.

If a known protocol uses a nonstandard port, use Analyze → Decode As before treating an empty protocol filter as a negative finding. Missing segments, encryption and an incorrect dissector are different failures. Supplied TLS secrets need the matching Wireshark TLS configuration; a server private key alone does not decrypt every TLS session.

TShark is a supplemental approved Windows entry. On Windows PowerShell, its default installer path can be invoked as `& 'C:\Program Files\Wireshark\tshark.exe' -r 'C:\PATH\capture.pcap' ...`; confirm the local path. With a TShark launcher in WSL/Bash:

```bash
tshark -r ./capture.pcap -Y http.request -T fields -e frame.number -e tcp.stream -e http.host -e http.request.uri
tshark -r ./capture.pcap -q -z follow,tcp,ascii,STREAM_NUMBER
tshark -r ./capture.pcap --export-objects http,NEW_OBJECT_DIR -q
```

For independently identified HTTP on port PORT, add `-d tcp.port==PORT,http` to the reading/export commands. These read an existing capture; do not omit `-r`. Expect request rows linked to packets, then a parser-valid object. The synthetic exercise exported a segmented binary response exactly. For large captures, a Zeek summary can narrow the pivot: copy the capture into a fresh analysis directory, run `zeek -r ./capture.pcap` there, then inspect `conn.log` and relevant protocol logs. The prepared container mounts only its current project directory, so an absolute input outside that directory is not visible. Zeek logs identify flows; they are not reconstructed file bytes.

<a id="media"></a>
## Image or embedded data — ExifTool, zsteg, binwalk

```bash
exiftool -a -u -g1 ./image.png
zsteg ./image.png
zsteg -E 'COPIED_SELECTOR' ./image.png > ./NEW_selected.bin
binwalk ./artifact.bin
xxd -s BYTE_OFFSET -l 32 ./artifact.bin
zbarimg --raw ./code.png
```

Keep metadata groups and explicit time zones. For decimal coordinates, `exiftool -n -GPSLatitude -GPSLongitude -GPSLatitudeRef -GPSLongitudeRef ./image.jpg` avoids manually transcribing degree/minute/second displays; inspect sign and reference. Missing metadata does not rule out appended data or pixel steganography.

For PNG/BMP, copy the entire meaningful zsteg selector, for example `b1,r,lsb,xy`; do not copy a guessed file-type label. Inspect recovered length and bytes, then run the claimed format's validator. This installed zsteg strips trailing NULs; if a binary format needs that tail, check the plane length independently. If scanning fails because `file` is missing from the same runtime, `zsteg --no-file ./image.png` can still scan text but skips file classification. The prepared container now has the missing dependency; test the competition installation separately. For an authored QR fixture, ZBar required a sufficient quiet border and scale before it decoded the exact text; a failed scan on a tight crop does not prove no code is present.

For a copied **uncompressed 8-bit PCM WAV** with an evidenced sample-LSB layout and exact payload length, use the [Linux/Kali/WSL WAV LSB template](scripts/templates/README.md#wav-lsb) to extract bytes. It reads samples in frame/channel order, then the selected low bits of each sample from most significant to least significant; payload bytes are also most significant bit first. This is a conditional byte-recovery step, not a scan for hidden data. A clean carrier can yield arbitrary bytes; inspect the recovered format and compare a clean or wrong-layout control. Steghide uses a different carrier scheme; use the route below when that is the clue.

<a id="steghide-carrier"></a>
### JPEG/BMP/WAV/AU carrier — steghide or limited Stegseek

Preserve and hash the original before copying it to a private working directory. Confirm the copied file's actual JPEG, BMP, WAV or AU signature; an extension or a PNG does not make it a steghide carrier. Use a clue-derived passphrase first. `steghide info ./COPIED_CARRIER` inspects the carrier; `steghide extract -sf ./COPIED_CARRIER -xf ./NEW_payload.bin` prompts for the passphrase and writes to a fresh path. Keep a failed passphrase distinct from a clean carrier and from an unsupported format.

For at most eight private candidate lines, put the exact bytes in `private-words.txt` and run `stegseek --crack -s -n -t 1 ./COPIED_CARRIER ./private-words.txt ./NEW_payload.bin`. `-s` suppresses default guesses and `-t 1` bounds threads; the manual command has no wall-time limit. Keep that file, tool output and extracted bytes private. The optional prewritten helper accepts a private hints JSON file such as `{"password_file":"/path/to/private-words.txt"}` with `python3 scripts/autosolve.py analyze ./COPIED_CARRIER --category images --hints ./private-hints.json --budget 30`; it limits the source to 16 MiB, eight candidates and 20 seconds, and records candidates rather than accepted answers. Check extracted length, format and content independently; use a known wrong passphrase and a separate benign clean carrier as controls. A failed search does not rule out other passphrases or embedding methods. Stegseek seed search is outside this limited route and does not generally bypass encryption. The prepared WSL steghide is 0.5.1; the workbook lists 0.6.0, so confirm installed help/version on the competition system.

For an embedded signature, distinguish the original file byte offset from a sector or decoded-stream offset. Check binwalk's major version before extraction flags. If ZIP structure is corroborated, list/test with the installed archive tool or carve the evidenced byte region to a new file and test its CRCs. A signature match alone is a lead, and recursive extraction is not the default next action.

For a candidate that runs from its start to the end of the file, use approved Python. This example's offset 224 belongs only to the synthetic fixture; replace it with the offset you observed. A format-defined length needs a bounded carve instead.

```python
from pathlib import Path
from shutil import copyfileobj
offset = 224
assert 0 <= offset < Path('artifact.bin').stat().st_size
with open('artifact.bin', 'rb') as source, open('NEW_candidate.bin', 'xb') as output:
    source.seek(offset)
    copyfileobj(source, output)
```

For a ZIP candidate, `7z t ./NEW_candidate.bin` tests structure and CRCs when the supplementary approved archive tool is available. Python's `zipfile` module is another validator.

<a id="pdf"></a>
## PDF — qpdf, pdftotext and the viewer

Compare rendered pages with extracted text, attachments and content streams:

```bash
qpdf --check ./document.pdf
pdftotext -layout ./document.pdf ./NEW_document.txt
qpdf --list-attachments ./document.pdf
qpdf --show-attachment='COPIED_KEY' ./document.pdf > ./NEW_attachment.bin
qpdf --show-pages ./document.pdf
qpdf --show-object=OBJECT,GEN ./document.pdf
qpdf --show-object=OBJECT,GEN --filtered-stream-data ./document.pdf > ./NEW_stream.bin
```

The attachment list's key selects an export; the page listing supplies object and generation numbers. `--show-object` alone describes an object; `--filtered-stream-data` returns decoded stream bytes. Validate exported files separately and relate content to the original page/object. A content stream can contain PDF drawing/text operators rather than plain prose. Password errors and malformed/encrypted streams are not empty evidence. Preserve the original: rewriting can drop orphaned objects. `pdftotext` extracts mapped text, not OCR; a blank text file can coexist with image-only pages or non-text streams.

<a id="disk"></a>
## Disk image — The Sleuth Kit

```bash
mmls -b SECTOR_BYTES ./disk.img
fsstat -b SECTOR_BYTES -o START_SECTOR ./disk.img
fls -r -p -b SECTOR_BYTES -o START_SECTOR ./disk.img
icat -b SECTOR_BYTES -o START_SECTOR ./disk.img METADATA_ADDRESS > ./NEW_recovered.bin
```

Use the actual device sector size and the filesystem partition's Start sector. A filesystem-only image uses offset zero; it need not contain a partition table. Copy the metadata address from `fls`, including all NTFS components such as `42-128-1`. For a deleted file, add `-r` to `icat`; `fls -d` selects deleted entries, and recursive listing does not traverse deleted directories. Check recovered bytes, not just its filename. Bytes may be overwritten or partial. If `fsstat` fails, revisit image type, offset and sector size before carving. The synthetic case uses sector 2048 × 512 bytes; passing 1048576 to `-o` is the wrong coordinate system. For a standalone FAT image, `fsck.fat -n ./FAT_FILESYSTEM.img` reports structure without repairing it. A local test caught zero logical-sector size, but a separate boot-signature-only edit was not flagged; a clean exit is narrower than full integrity proof.

<a id="native"></a>
## Native checker — Ghidra to GDB

In Ghidra, import with the correct architecture and analyse. Find a prompt/success string → show its references → inspect the calling function. Write down input source, length limit, transformation, comparison operands and the success branch. Compare decompiler expressions with instructions before renaming uncertain types.

In the matching isolated runtime, start GDB with the compatible ELF. Use `break main`, `run INPUT`, `disassemble /r CHECK_FUNCTION`; stop at the actual comparison. Symbols or a breakpoint expressed relative to a known symbol are preferable to copied static addresses. PIE/ASLR changes load addresses; establish the runtime mapping before setting `break *ADDRESS` on stripped code.

At **strcmp entry on x86-64 System V**, `x/s $rdi` and `x/s $rsi` show the two C strings. For memcmp, inspect its length and bounded byte arrays (`x/Nbx ADDRESS`), since NUL bytes are data. `finish`, then `p/d $eax`, checks the returned comparison result: zero means equal. Inspect the caller's branch too. These registers do not apply to every architecture or Windows ABI. Confirm a derived input and a near miss; record output and exit status. Use the supplementary x64dbg/x32dbg route for Windows PE debugging. To check a proposed x86-64 instruction encoding before using it, `llvm-mc -triple=x86_64-pc-linux-gnu -show-encoding ./SAMPLE.s` prints encoded bytes; independently disassemble a generated object if the exact instruction matters. The full object file includes metadata and is not raw shellcode.

<a id="web"></a>
## HTTP request — Burp Community

Proxy → Intercept → Open Browser. Turn Intercept off while browsing the assigned service, then select its request in Proxy → HTTP history → Send to Repeater. Burp's browser is preconfigured; an external browser needs its proxy and HTTPS trust configured separately.

Replay unchanged twice and record status, relevant headers/cookies, body and any server-side state change. Change one value, send again, then restore baseline. Check Repeater's actual target host/port/TLS settings, not only the Host header. Empty history means capture setup has not been established. Baseline differences can come from expiry, CSRF values, one-use tokens or dynamic content. These steps use Community features and were source-reviewed, not GUI-tested here.

<a id="memory"></a>
## Memory image — Volatility 3

Confirm the installed launcher with help. `vol` is the prepared suite launcher; use `python3 /PATH/vol.py` only for an actual source checkout. Before going offline, resolve the image's matching PDB database name, GUID and age; keep the converted symbols and cache together with the image. A local `pdbconv -f PDB_PATH` conversion needs `-p PDB_NAME` in the tested Volatility 3 release. Check the generated symbol metadata and run `windows.info` using the intended paths while connected, then repeat offline. The following commands assume a prepared `./symbols/windows/` tree and a writable `./vol-cache/` directory; a bare PDB in the image folder is not searched automatically.

```bash
vol --offline --cache-path ./vol-cache -s ./symbols -f ./memory.raw windows.info
vol --offline --cache-path ./vol-cache -s ./symbols -f ./memory.raw windows.pstree
vol --offline --cache-path ./vol-cache -s ./symbols -f ./memory.raw windows.cmdline
vol windows.dumpfiles --help
vol --offline --cache-path ./vol-cache -s ./symbols -f ./memory.raw -o ./NEW_DUMPS windows.dumpfiles --pid PID --filter 'EVIDENCED_NAME'
```

Create the new output directory first. Correlate process, parent, arguments and timestamps; then choose the file name or PID from that evidence. The dump filter is a regex. Validate dumped content: cached files can be incomplete. `windows.filescan` is another lead source, but confirm its offset layer before selecting `--virtaddr`/`--physaddr`. A symbol error means analysis did not run; it is not “no process found.” An [official 32-bit XP test image](https://github.com/volatilityfoundation/volatility3-test-data/releases/tag/v0.0.1) was actually checked with Volatility 3 2.28.2: `windows.info`, `pstree`, `cmdline` and one known-address `dumpfiles` extraction passed offline with a fresh local symbol cache; 47 process rows and two dumped PE files matched the publisher’s regression expectations. That result does not establish modern Windows, arbitrary images, process minidumps or the missing practice challenge dump.

<a id="crypto"></a>
## RSA or password evidence

For RSA, inspect n/e and the ciphertext representation before choosing a weakness. Use `RsaCtfTool --help` and the actual launcher. A small private exponent suggests Wiener; evidenced close factors suggest Fermat; a nontrivial gcd between moduli supplies a shared factor. Do not run all attacks or send integers to external services by default.

```bash
RsaCtfTool --dumpkey --key ./public.pem
RsaCtfTool --publickey ./public.pem --attack wiener --private --timeout 30
```

Read both stdout and stderr: the tested RsaCtfTool version prints recovery results on stderr. Do not assume `> private.pem` creates a usable key; copy only a recovered PEM block or use a locally verified output option, then parse/check it.

After recovering p/q, check `p*q == n`, compute the inverse exponent and decrypt the textbook integer. Assert `pow(m,e,n) == c` before converting with `m.to_bytes((m.bit_length()+7)//8, 'big')`. A fixed-width block may need leading zero bytes; OAEP/PKCS#1 padding needs its actual decoder. A failed attack only rejects that hypothesis. For password/hash evidence, follow [the Hashcat guide](HASHCAT.md): it covers mode ambiguity, candidate coverage, device failures and recovery verification.

Local checks exercised the actual offline CyberChef app, TShark on Linux and Windows, Ghidra headless analysis, GDB, qpdf, zsteg, TSK and an explicit RSA attack on synthetic inputs. Burp/Wireshark desktop GUI operation remains source-guided; the memory result covers the official XP fixture only. These checks do not establish competition-host compatibility.

Primary references: [Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/) · [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) · [zsteg](https://github.com/zed-0xff/zsteg) · [qpdf](https://qpdf.readthedocs.io/en/stable/cli.html) · [TSK icat](https://www.sleuthkit.org/sleuthkit/man/icat.html) · [Burp capture](https://portswigger.net/burp/documentation/desktop/getting-started/intercepting-http-traffic) · [Volatility](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html) · [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool).

<a id="can"></a>
## A supplied CAN log — can-utils

Use can-utils' log converters before opening an interface. For a compact `candump` log, a line has a timestamp, interface label and `ID#DATA`; these are recorded fields, not instructions to connect to a bus. Preserve the original and write new outputs:

```bash
log2long < ./capture.log > ./NEW_readable.txt
log2asc -I ./capture.log -O ./NEW_capture.asc can0 can1
asc2log -I ./capture.asc -O ./NEW_compact.log
```

Replace `can0 can1` with the interface **labels present in the input log**. Their order maps to ASC channel numbers 1, 2, and so on. `log2asc` only converts selected labels, so omitted labels can remove records. No CAN interface is needed for these commands. On the prepared research computer, these converters are already inside the distro image: from the project root, prefix the tool with `tools/distro/run-container`, and keep files under the project directory. No new launcher or package is required.

Check row counts, arbitration IDs, standard/extended format, data lengths, exact bytes and timestamps after conversion. In ASC, an `x` suffix marks an extended identifier; `d` identifies a data frame and `r` a remote request. A classic-CAN remote request with DLC 4 requests four bytes but carries no data payload. The zero-byte data frame is another valid case. These examples are classic CAN with ordinary DLC values 0–8; CAN FD has a different DLC-to-length mapping. Without a supplied signal definition or corroborated experiment, changing bytes do not establish a physical measurement, byte order or scale.

**Calibration:** In the [authored CAN capture](examples/core/can-capture.txt), ID `123` changes its final byte from `08` to `09` over 10 ms. ID `1ABCDEFF` has three data bytes `00 A5 FF`; ID `321` is a remote request with DLC 4; ID `456` has zero data bytes. The five records convert back with the same IDs, DLCs and bytes. An added `R`/`Rx` direction is the converter's default when the original omits direction; it is not evidence of a physical reception.

**If output differs:** Check the input format and selected channel labels first. Do not treat an existing output file or exit 0 as proof of a complete conversion. Stock can-utils 2023.03-1 showed the following limits. The prepared project container now has a narrowly patched `asc2log` date parser; this does not establish the behavior of the competition installation:

- `log2long` and `log2asc` reject malformed compact frames with exit 1 but can leave a valid-looking output prefix. Preserve diagnostics and discard that output as a completed conversion.
- `asc2log` can skip an ASC row whose declared DLC exceeds its supplied bytes and still exit 0. If its required date locale is absent, it can substitute the current time while only warning on stderr. The stock parser also produced silent one-hour shifts from an uninitialized DST field and mishandled AM dates. The local patch initializes that field and recognises AM; malformed-row loss and invalid-date fallback still require explicit checks. Frame bytes and relative timing survived this fixture; absolute dates did not. Keep the original time basis and compare timestamp fields explicitly. A converter's date header without a zone does not establish UTC.

Cannelloni is a live SocketCAN tunnel, not a log decoder. Keep its peer/interface/transport setup in a separate route requiring the assigned topology and a working interface. The prepared upstream build differs from the workbook's unavailable fork; only its help was checked here. No hardware, virtual interface, bridge or frame transmission was tested.

Sources: [linux-can converter inventory](https://github.com/linux-can/can-utils), [2023.03 log2asc source](https://github.com/linux-can/can-utils/blob/v2023.03/log2asc.c), [2023.03 asc2log source](https://github.com/linux-can/can-utils/blob/v2023.03/asc2log.c), and [cannelloni upstream documentation](https://github.com/mguentner/cannelloni). Installed help and the synthetic results are preserved in this directory; source versions do not prove competition-machine parity.
