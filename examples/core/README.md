# Core-tool practice

These are small, authored practice inputs—not organiser challenges. Run commands from the root of the copied guide. Check the inputs with `sha256sum -c examples/core/SHA256SUMS`; use a new `practice-output` directory for results. Tools must already be available in the environment where you run them.

[CyberChef](#cyberchef) · [Packets](#packets) · [Images](#images) · [PDF](#pdf) · [Disk](#disk) · [Native code](#native) · [RSA](#rsa)

```bash
mkdir practice-output
```

<a id="cyberchef"></a>
## CyberChef: reproduce a layered decode

Open your offline CyberChef copy. Load [cyberchef-recipe.json](cyberchef-recipe.json) through the recipe Load control, then paste [gzip-base64.txt](gzip-base64.txt) into Input. The operations are **From Base64 → Gunzip**. Compare the output with [expected.txt](expected.txt): 51 bytes, SHA-256 `45ccc5cf7b56c0d158ad7920dc13d203b363fad7a7e13be0da5da5969374d963`.

Replace the input with [not-gzip-base64.txt](not-gzip-base64.txt). Base64 decoding still works, but Gunzip must report an invalid signature. This distinguishes a wrong decoding hypothesis from an empty result. Save a recipe separately from input; never share a URL containing challenge data.

<a id="packets"></a>
## Wireshark/TShark: reconstruct the response

[http.pcap](http.pcap) contains a response split across three TCP segments plus a retransmission. Open it in Wireshark, follow the TCP stream, then use **File → Export Objects → HTTP**. The exported `report.txt` must match [expected.txt](expected.txt).

The supplemental TShark path performs that export directly:

```bash
tshark -r examples/core/http.pcap --export-objects http,practice-output/http -q
cmp practice-output/http/report.txt examples/core/expected.txt
```

Run the missing-middle control into a different, new directory:

```bash
tshark -r examples/core/http-incomplete.pcap --export-objects http,practice-output/incomplete -q
```

Expect no exported object. Do not reuse a directory containing an earlier success. Captured TCP payloads concatenated in packet order duplicate retransmissions; `follow,tcp,raw` also includes hexadecimal framing and directions, not just raw file bytes.

[http-port19091.pcap](http-port19091.pcap) carries HTTP on a nonstandard port. Use Decode As in Wireshark, or:

```bash
tshark -r examples/core/http-port19091.pcap -d tcp.port==19091,http --export-objects http,practice-output/port19091 -q
cmp practice-output/port19091/payload.bin examples/core/expected-payload.bin
```

<a id="images"></a>
## Images: extract a selected plane or inspect an appended archive

Read metadata from [carrier.png](carrier.png), scan it, then extract the specific red-channel LSB plane:

```bash
exiftool -a -u -g1 examples/core/carrier.png
zsteg examples/core/carrier.png
(set -C; zsteg -E 'b1,r,lsb,xy' examples/core/carrier.png > practice-output/lsb.bin)
cmp practice-output/lsb.bin examples/core/expected-lsb.txt
```

Expected: `TRAINING-LSB` followed by LF. The tested zsteg version strips trailing NULs; the fixture includes that padding, so this does not prove exact recovery of a binary file ending in NUL. The green-plane selector `b1,g,lsb,xy` yields an empty result. If scanning fails because its `file` dependency is missing, `--no-file` permits text scanning but disables file-type identification.

[appended.png](appended.png) contains an appended ZIP. Run `binwalk examples/core/appended.png`, then `7z l examples/core/appended.png`. Record the reported byte boundary; test the recovered archive and its CRC rather than assuming a signature match proves recovery. No recursive extraction is necessary.

<a id="pdf"></a>
## PDF: distinguish attachments from page streams

```bash
qpdf --check examples/core/attachment.pdf
qpdf --list-attachments examples/core/attachment.pdf
(set -C; qpdf --show-attachment=training-payload examples/core/attachment.pdf > practice-output/pdf-attachment.bin)
cmp practice-output/pdf-attachment.bin examples/core/expected-payload.bin
qpdf --show-pages examples/core/streams.pdf
(set -C; qpdf --show-object=4 --filtered-stream-data examples/core/streams.pdf > practice-output/pdf-stream.bin)
cmp practice-output/pdf-stream.bin examples/core/expected-stream.txt
```

The attachment is 17 bytes, including NUL and `ff`; text display is insufficient to check it. The page stream is `% TRAINING-STREAM` followed by LF, so the rendered page can be blank despite stored content. Copy object numbers and attachment keys from the actual PDF; these values belong only to the supplied fixtures.

<a id="disk"></a>
## Disk image: recover the deleted entry

[disk.img](disk.img) is an authored MBR disk with an ext2 partition starting at sector 2048, using 512-byte sectors. Find the deleted `training.bin` metadata address rather than inferring it from a filename:

```bash
mmls -b 512 examples/core/disk.img
fsstat -b 512 -o 2048 examples/core/disk.img
fls -r -p -d -b 512 -o 2048 examples/core/disk.img
(set -C; icat -r -b 512 -o 2048 examples/core/disk.img 12 > practice-output/deleted.bin)
cmp practice-output/deleted.bin examples/core/expected-payload.bin
```

The supplied entry is inode 12; other images will differ. As a negative control, `fls -o 1048576 examples/core/disk.img` must fail: that number is the byte offset, while `-o` requires sectors. Never mount or repair an original image to perform this exercise.

<a id="native"></a>
## Native checker: derive and test the comparison

[checker.c](checker.c) is a benign comparison exercise. Build it before opening the source if you want to practise recovery; compilation needs an already installed C compiler:

```bash
gcc -O0 -fno-builtin -fno-pie -no-pie examples/core/checker.c -o practice-output/checker
```

Import the resulting ELF into Ghidra, analyse it, and follow the `accepted`/`rejected` string references to the comparison. For an installed headless launcher, [RecoverComparison.java](RecoverComparison.java) exports the named function and refuses to overwrite its output:

```bash
ghidra-headless practice-output fixture -import practice-output/checker -scriptPath examples/core -postScript RecoverComparison.java check_phrase practice-output/decompiled.c -analysisTimeoutPerFile 60 -max-cpu 2 -deleteProject
```

The recovered comparison uses `strcmp`. The derived input must produce `accepted`/exit 0; a one-character mutation produces `rejected`/exit 1; no argument exits 2. A successful import alone is not the check. Ghidra can return exit 0 after a post-script error; require a freshly created output and inspect the log. Repeating this command with the same output should preserve it and log an overwrite refusal. The launcher name and Java runtime are installation-specific; the GUI route does not require that wrapper.

For GDB operand inspection, [gdb-checker.c](gdb-checker.c) builds its expected string at runtime. Compile it with `gcc -O0 -g -fno-builtin ...`; stop before its comparison and inspect both operands, then verify the caller's branch. Do not copy x86-64 System V register assumptions to another architecture or Windows ABI.

<a id="rsa"></a>
## RSA: test an evidenced close-factor case

This toy modulus deliberately has close factors:

```bash
RsaCtfTool -n 1000000016000000063 -e 65537 --attack fermat --private --decrypt 481265877869100520 --timeout 10
```

Expect factors 1000000007 and 1000000009 and plaintext `LEARN`. Independently check their product, then decrypt and re-encrypt the integer in Python. This is textbook RSA; do not apply bare integer conversion to OAEP or PKCS#1 padded ciphertext.

The tested tool prints results on stderr alongside other messages. Empty stdout is not an empty recovery; do not redirect stdout to a PEM file and assume it is a key. Check flags against the installed version and parse any copied PEM block before relying on it.


<a id="can"></a>
## CAN log: preserve records and time meaning

[can-capture.txt](can-capture.txt) has five authored classic-CAN frames; no interface is needed. With can-utils available:

```bash
(set -C; log2long < examples/core/can-capture.txt > practice-output/can-readable.txt)
log2asc -I examples/core/can-capture.txt -O practice-output/can.asc can0 can1
asc2log -I practice-output/can.asc -O practice-output/can-roundtrip.txt
```

Check five records and their exact IDs/DLC/data, not merely exit 0. ID `123` changes its final byte from `08` to `09` over 10 ms. Extended ID `1ABCDEFF` carries `00 A5 FF`; ID `321` is a remote request for four bytes, with no payload; ID `456` is a zero-byte data frame. Interface names here are labels from the log, not interfaces to open. Compare absolute time as well as elapsed intervals; the ASC header does not establish a timezone.

As a negative control, convert [can-malformed.asc](can-malformed.asc) separately. The tested asc2log drops its malformed DLC row yet returns 0; that is not a complete conversion. Missing required locales can also replace absolute timestamps while only warning. Stock can-utils 2023.03-1 additionally showed silent one-hour/DST shifts and an AM parsing defect. The prepared local container has a narrow date-parser patch, but other installations need the same comparison against the original. Read stderr and compare records before trusting output. On the prepared project machine, prefix these converter names with `tools/distro/run-container` and work inside the project; an export elsewhere needs a native can-utils installation.
