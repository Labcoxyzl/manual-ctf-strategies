# CTF tool cheatsheet

The 32 tools proposed by Trend Micro appear first in each category. The other 168 approved entries were participant requests. Both groups are approved; check the recorded platform and version.

[Digital Forensics](#forensics) · [Malware Analysis](#malware) · [Web Security](#web) · [Reverse Engineering](#reversing) · [OSINT](#osint) · [Cryptography](#crypto) · [Miscellaneous](#misc)

[Core workflows](CORE_WORKFLOWS.md) · [Hashcat commands](HASHCAT.md) · [Python scripts and templates](scripts/templates/README.md) · [Competition rules](RULES.html)

Replace uppercase filenames, hosts and other placeholders before running a command. Preserve original files. First actions are reference workflows unless a local check is explicitly identified. Kali availability is best effort; approval does not prove an installed version or backend works.

<a id="forensics"></a>
## Digital Forensics

1. Preserve the original and identify its actual format with file or a matching GUI. Record the question, source path and relevant timestamps before extracting anything.
2. PCAP: choose a conversation in Wireshark, follow the stream and export a relevant object. Disk image: find the partition start with mmls, list with fls and recover the selected metadata address with icat.
3. Memory: resolve Volatility 3 symbols, then inspect image information, process tree and command lines. Windows artifact: select an EVTX, registry, MFT or browser parser for the file actually supplied.
4. Media: read ExifTool metadata; check PNG/JPEG structure, a justified zsteg plane or an audio spectrogram. PDF: compare rendered pages with attachments and object streams.
5. Validate recovered content using its format, and keep the source offset, packet, record or object identifier that supports the answer.
6. A valid image and clean metadata do not exclude appended content. If the clue remains unexplained, list the file with 7z, inspect later strings or container boundaries, and compare related files before carving; preserve offsets and validate recovered members with CRC or their format parser.

**Look for:** A recovered file or specific record supported by a traceable source location and correctly interpreted time/format.

**If blocked:** When a parser fails, check format, partition offset, symbols and missing sidecars first. Use carving only when metadata is unusable; false signatures and incomplete recovery remain limitations.

**Start with:** [file (libmagic) (Kali)](#approved-kali-42) · [Wireshark (Windows)](#approved-windows-2) · [The Sleuth Kit (Windows / WSL)](#approved-windows-23) · [volatility3 (Windows / WSL)](#approved-windows-31) · [Eric Zimmerman's Tools (Windows)](#approved-windows-39) · [ExifTool (Windows / WSL)](#approved-windows-14) · [zsteg (Windows / WSL)](#approved-windows-12) · [qpdf (Windows / WSL)](#approved-windows-26) · [Audacity (Kali)](#approved-kali-10) · [sqlite3 (Kali)](#approved-kali-131) · [TestDisk and PhotoRec (Kali)](#approved-kali-143)

[Bounded file inspection](TOOLKIT.html#inspect)

[Forensic and packet practice](research/learning/practice/README.html)

[Audio inspection practice](research/learning/video-coverage/practice/AUDIO_PRACTICE.html)

<a id="approved-windows-13"></a>
### binwalk · Windows / WSL · Trend Micro proposal

**Use for:** Find embedded files or compressed regions inside an unknown blob or firmware image.

**First action:** Scan the original blob for embedded signatures; inspect candidate offsets and check the installed major version before selecting extraction flags.

```sh
binwalk ./ARTIFACT.bin
```

**Expected:** A plausible embedded region corroborated by bytes or a valid extracted object.

**If blocked:** Confirm helper extractors and false positives; inspect an offset with xxd before recursive extraction.

**Availability:** Version: Latest · Location: installed in WSL

- Workbook says latest; determine v2 versus v3 before copying extraction options.

[binwalk — documentation](https://github.com/ReFirmLabs/binwalk) · [Binwalk v3 usage wiki](https://github.com/ReFirmLabs/binwalk/wiki)

<a id="approved-windows-14"></a>
### ExifTool · Windows / WSL · Trend Micro proposal

**Use for:** Read metadata, comments, timestamps and location clues before deeper media analysis.

**First action:** Read duplicate/unknown metadata with group names; compare dates, GPS and comments across groups and preserve explicit time-zone fields.

```sh
exiftool -a -u -g1 ./IMAGE.jpg
```

**Expected:** Source-tagged clues suitable for corroboration.

**If blocked:** Missing metadata does not rule out hidden content; move to format or pixel analysis and treat conflicts as unverified.

**Availability:** Version: Latest · Location: installed in WSL

- Windows-approved row runs in WSL. Keep the original unchanged; metadata can be forged.

[Related helper](TOOLKIT.html#inspect)

[ExifTool application manual (upstream repository)](https://github.com/exiftool/exiftool/blob/master/html/exiftool_pod.html)

<a id="approved-windows-29"></a>
### fsck.fat (dosfstools) · Windows / WSL · Trend Micro proposal

**Use for:** Check FAT structure without repair

**First action:** Run the non-writing FAT check on a standalone filesystem image and record structural errors.

```sh
fsck.fat -n ./FAT_FILESYSTEM.img
```

**Expected:** FAT, directory or allocation diagnostics without source repair.

**If blocked:** For a whole disk, locate the FAT partition first; perform any repair only on a separate copy.

**Availability:** Version: Latest · Location: installed in WSL

- Repair modes modify evidence; start with non-writing checks.

[fsck.fat (dosfstools) — upstream repository](https://github.com/dosfstools/dosfstools/blob/master/manpages/fsck.fat.8.in)

**Check:** Local fsck.fat 4.2 checked an authored FAT12 image with -n without changing it and rejected zero logical-sector size. A separate boot-signature-only edit was not flagged.

<a id="approved-windows-32"></a>
### OpenSSH-Session-Key-Recovery · Windows · Trend Micro proposal

**Use for:** Recover SSH session keys from supported memory evidence

**First action:** Check the recovery repository's support requirements; pair supplied Linux memory with matching SSH traffic and confirm OpenSSH layout, plugin and symbols.

**Expected:** Compatible session material associated with the captured connection.

**If blocked:** Unsupported memory/build or missing session evidence is a limitation; this is not arbitrary SSH decryption.

**Availability:** Version: not specified · Location: installed in volatility3 · Plugin for Volatility3

- Requires compatible OpenSSH structures, memory and capture; not general SSH decryption.

[OpenSSH-Session-Key-Recovery — upstream repository](https://github.com/fox-it/OpenSSH-Session-Key-Recovery)

<a id="approved-windows-3"></a>
### PDF Viewer · Windows · Trend Micro proposal

**Use for:** Inspect PDF text and attachments; viewer identity is unspecified

**First action:** Inspect PDF pages, properties and the installed viewer's attachment panel; record the page or attachment behind the clue.

**Expected:** Visible text, images or attachment names to compare with object-level analysis.

**If blocked:** Use qpdf for objects or pdftotext for existing text; an image-only page will not become text without OCR.

**Availability:** Version: Any current version · Location: installed in Windows

- Viewer unspecified; Adobe attachment UI is only an example.

[Related helper](research/learning/video-coverage/practice/TRIAGE_PRACTICE.html)

[PDF Viewer — official documentation](https://helpx.adobe.com/acrobat/desktop/edit-documents/use-links-and-attachments/open-attachment.html)

<a id="approved-windows-15"></a>
### pdftotext (Poppler utils) · Windows / WSL · Trend Micro proposal

**Use for:** Extract PDF text

**First action:** Extract existing PDF text with layout preserved into a new file and compare it with rendered pages.

```sh
pdftotext -layout ./DOCUMENT.pdf ./NEW_DOCUMENT.txt
```

**Expected:** Searchable text and line placement linked to page content.

**If blocked:** Empty output can mean image-only pages or unusual font mappings; inspect PDF objects and remember this is not OCR.

**Availability:** Version: Latest · Location: installed in WSL

- Image-only pages need a separately approved OCR tool; extraction is not OCR.

[pdftotext (Poppler utils) — official documentation](https://manpages.debian.org/bookworm/poppler-utils/pdftotext.1.en.html)

**Check:** Local pdftotext 24.02.0 extracted exact authored PDF text with page separator. Image-only OCR was not tested.

<a id="approved-windows-26"></a>
### qpdf · Windows / WSL · Trend Micro proposal

**Use for:** Inspect PDF objects and streams

**First action:** List PDF attachments and pages, then inspect a relevant object; save decoded streams separately and compare with the document.

```sh
qpdf --list-attachments ./DOCUMENT.pdf
qpdf --show-pages ./DOCUMENT.pdf
```

**Expected:** Attachment identifiers, object references or stream content.

**If blocked:** Return to the original if rewriting loses a clue; orphaned objects can disappear. Use pdf-parser or mutool for another view.

**Availability:** Version: Latest · Location: installed in WSL

- Write transformed output separately; rewriting can remove orphaned objects.

[Related helper](research/learning/video-coverage/practice/TRIAGE_PRACTICE.html)

[qpdf — official documentation](https://qpdf.readthedocs.io/en/stable/cli.html)

<a id="approved-windows-11"></a>
### strings · Windows / WSL · Trend Micro proposal

**Use for:** Extract readable strings

**First action:** Extract ASCII strings with hex offsets; repeat in UTF-16LE for Windows-oriented data and inspect meaningful hits in the original file.

```sh
strings -a -t x ./ARTIFACT.bin
strings -a -e l -t x ./ARTIFACT.bin
```

**Expected:** Candidate messages, paths or URLs with reproducible locations.

**If blocked:** Encoded or packed content may have no strings; identify the format or use FLOSS for a supported executable.

**Availability:** Version: Bundled with GNU Binutils · Location: installed in WSL

- Strings are clues, not proof of executed behavior; use -a for all bytes.

[Related helper](TEMPLATES.html#file-intel)

[strings — official documentation](https://sourceware.org/binutils/docs/binutils/strings.html)

<a id="approved-windows-23"></a>
### The Sleuth Kit · Windows / WSL · Trend Micro proposal

**Use for:** Inspect filesystem images

**First action:** Find the partition start sector, list its files using that offset, then recover a selected metadata address to a new destination.

```sh
mmls ./DISK.img
fls -r -o START_SECTOR ./DISK.img
icat -o START_SECTOR ./DISK.img METADATA_ADDRESS > ./NEW_RECOVERED.bin
```

**Expected:** A path and metadata address linked to recovered bytes.

**If blocked:** Check sector size, format and offset; use Autopsy for GUI inspection or PhotoRec when metadata recovery fails.

**Availability:** Version: Latest · Location: installed in WSL

- Offsets are sectors; recursive fls does not traverse deleted directories.

[The Sleuth Kit — official documentation](https://www.sleuthkit.org/sleuthkit/man/fls.html)

<a id="approved-windows-31"></a>
### volatility3 · Windows / WSL · Trend Micro proposal

**Use for:** Inspect Windows memory images

**First action:** With the prepared Volatility 3 launcher, supply the image’s matching converted symbols and a writable cache, then inspect Windows image information, process tree and command lines. A source checkout may use its own vol.py instead.

```sh
vol --offline --cache-path ./vol-cache -s ./symbols -f ./MEMORY.raw windows.info
vol --offline --cache-path ./vol-cache -s ./symbols -f ./MEMORY.raw windows.pstree
vol --offline --cache-path ./vol-cache -s ./symbols -f ./MEMORY.raw windows.cmdline
```

**Expected:** Consistent PID/parent relationships and arguments that select an artifact.

**If blocked:** A symbol error is failed analysis, not an empty finding. Check PDB name, GUID and age, `./symbols/windows/` layout, cache path, image format and installed plugin version before interpreting output. Volatility 2 uses profiles and different commands.

**Availability:** Version: Latest · Location: installed in WSL

- Volatility 3 uses symbols rather than Volatility 2 profiles; symbols may require network/cache preparation.

[Related helper](CORE_WORKFLOWS.html#memory)

[volatility3 — official documentation](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html)

**Check:** Local Volatility 3 2.28.2 check on an official 32-bit XP test image: info, pstree, cmdline and a known-address file extraction passed offline with matching symbols. Modern Windows, process minidumps and competition machines were not tested.

<a id="approved-windows-2"></a>
### Wireshark · Windows · Trend Micro proposal

**Use for:** Follow suspicious conversations and export transferred objects from a supplied PCAP.

**First action:** Open the supplied capture; choose Statistics → Conversations, filter a peer pair, then Follow the matching stream. Use Export Objects for a relevant transferred file.

**Expected:** A conversation or object tied to endpoints and packet numbers.

**If blocked:** Check missing packets and encryption; use Zeek summaries to select another stream.

**Availability:** Version: Latest · Location: installed in Windows

- Encrypted payloads need supplied keys or other evidence.

[Related helper](research/learning/practice/README.html)

[Following Protocol Streams](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html) · [Exporting Data](https://www.wireshark.org/docs/wsug_html_chunked/ChIOExportSection.html)

<a id="approved-windows-28"></a>
### xxd · Windows / WSL · Trend Micro proposal

**Use for:** Inspect magic bytes or turn a supplied hexadecimal dump back into bytes.

**First action:** Inspect a bounded byte prefix with offsets. Before reversing a hex dump, distinguish plain hex from xxd's address-bearing format.

```sh
xxd -l 128 ./ARTIFACT.bin
```

**Expected:** Exact bytes and offsets in a known representation.

**If blocked:** Reverse mode can skip malformed text; verify reconstructed length and bytes independently.

**Availability:** Version: Bundled with Vim · Location: installed in WSL

- Windows-approved row runs in WSL. Reverse mode can skip malformed text; inspect the reconstructed bytes.

[Related helper](TEMPLATES.html#binary)

[xxd — documentation](https://github.com/vim/vim/blob/master/runtime/doc/xxd.1)

**Check:** Local xxd round-tripped an authored plain-hex dump and displayed the expected bounded bytes. Address-bearing reverse dumps were not tested.

<a id="approved-windows-25"></a>
### xz · Windows / WSL · Trend Micro proposal

**Use for:** Inspect and decompress XZ data

**First action:** Test XZ integrity, then decompress to a new file while preserving the input.

```sh
xz -t ./ARCHIVE.xz
xz -dc ./ARCHIVE.xz > ./NEW_PAYLOAD.bin
```

**Expected:** A valid stream and separate payload to identify.

**If blocked:** Check XZ versus raw LZMA and truncation; a different decoder cannot restore missing bytes.

**Availability:** Version: Latest · Location: installed in WSL

- Windows-list entry runs in WSL.

[xz — Inspect and decompress XZ data](https://tukaani.org/xz/man/xz.1.html)

**Check:** Local xz 5.4.5 integrity check and decompression reproduced authored bytes. Raw LZMA/truncated input was not tested.

<a id="approved-windows-19"></a>
### ZBar · Windows / WSL · Trend Micro proposal

**Use for:** Decode a visible or reconstructed QR/barcode locally.

**First action:** Decode a local visible QR/barcode image and compare the text with the code; inspect decoded URLs before navigating.

```sh
zbarimg ./CODE.png
```

**Expected:** A symbology label and payload.

**If blocked:** Try a derived crop or contrast improvement; damage or unsupported symbology can prevent decoding.

**Availability:** Version: Latest · Location: installed in WSL

- Windows-approved row runs in WSL. Failed decoding can reflect damage or unsupported symbology, not absence of a code.

[ZBar — documentation](https://github.com/mchehab/zbar)

**Check:** Local zbarimg 0.23.93 decoded an authored padded QR as CORE-QR-2026; the unpadded 25×25 version gave no payload. Damaged-code recovery was not tested.

<a id="approved-windows-18"></a>
### zeek · Windows / WSL · Trend Micro proposal

**Use for:** Turn a large PCAP into connection and protocol logs for triage.

**First action:** Work from a fresh analysis directory containing a copied capture, run Zeek on that local filename, then inspect conn.log and the relevant protocol log to choose endpoints and time windows. The project container launcher mounts only its current project directory.

```sh
zeek -r ./CAPTURE.pcap
```

**Expected:** Connection summaries that identify a Wireshark pivot.

**If blocked:** If Zeek cannot open an absolute capture path, copy it into the analysis directory first. Encrypted traffic may produce connections without application content; preserve the capture and check dissector/protocol visibility.

**Availability:** Version: Latest · Location: installed in WSL

- Windows approval row installs in WSL; current docs may differ from installed version.

[zeek reference](https://docs.zeek.org/en/current/quickstart.html)

**Check:** Local Zeek 9.0.0 parsed an authored HTTP PCAP: conn.log had one TCP connection and http.log matched the request, status 200 and 51-byte body. No encrypted or arbitrary-port case was tested.

<a id="approved-windows-12"></a>
### zsteg · Windows / WSL · Trend Micro proposal

**Use for:** PNG/BMP pixel-bit steganography: enumerate plausible channels, then extract only a meaningful hit.

**First action:** Scan the original PNG/BMP, choose a meaningful channel/bit-order hit, and extract with its exact reported -E selector into a new file.

```sh
zsteg ./IMAGE.png
```

**Expected:** Repeatable extracted bytes that validate as the claimed format or message.

**If blocked:** Random signatures are common; check carrier format and inspect relevant planes with StegSolve.

**Availability:** Version: Latest (Ruby gem) · Location: installed in WSL

- False positives are common; a detected file signature alone is not a recovered payload.

[zsteg — documentation](https://github.com/zed-0xff/zsteg)

<a id="approved-kali-2"></a>
### 7-Zip (7z) · Kali

**Use for:** Inspect and extract archives

**First action:** List archive members and sizes before extraction; extract selected content into a fresh directory without running it.

```sh
7z l ./ARCHIVE.bin
7z x ./ARCHIVE.bin -oNEW_EXTRACTED_DIR
```

**Expected:** Member paths identify the useful artifact and extracted bytes remain separate from the archive.

**If blocked:** Test integrity if extraction fails; check encryption, unsupported format and unsafe member paths before retrying.

**Availability:** Version: 26.02

[Related helper](TOOLKIT.html#inspect)

[7-Zip (7z) — Inspect and extract archives](https://7-zip.org/)

<a id="approved-kali-4"></a>
### ALEAPP (Android Logs Events And Protobuf Parser) · Kali

**Use for:** Parse Android forensic artifacts

**First action:** Select the supplied Android extraction type in ALEAPP, choose relevant artifact parsers and write a report to a new output directory.

**Expected:** App/device records linked to original artifact files and parser output.

**If blocked:** Verify the app/schema version and completeness of the extraction; inspect a relevant SQLite/protobuf artifact directly if unsupported.

**Availability:** Version: - · No installation information recorded

- Workbook records no installation information; support depends on app/schema version.

[ALEAPP (Android Logs Events And Protobuf Parser) — upstream repository](https://github.com/abrignoni/ALEAPP)

<a id="approved-kali-7"></a>
### AperiSolve · Kali

**Use for:** Aggregate local image metadata, bit-plane and embedded-file inspection when a working local deployment exists.

**First action:** Confirm a working local AperiSolve deployment before loading an image; inspect metadata, bit planes and embedded-file results relevant to the clue.

**Expected:** Local analysis reports with an actionable channel, offset or embedded object.

**If blocked:** If the stack is unavailable, use ExifTool, zsteg and binwalk directly; do not upload challenge files to the public service.

**Availability:** Version: (not captured) · Location: git (/opt/tools/AperiSolve)

- Never upload challenge files to the public AperiSolve service. A source checkout does not prove a running deployment; avoid spending competition time rebuilding the stack.

[AperiSolve — documentation](https://github.com/Zeecka/AperiSolve)

<a id="approved-kali-10"></a>
### Audacity · Kali

**Use for:** Inspect audio for frequency-domain text, tones, pulses and channel differences.

**First action:** Open audio in Audacity, inspect each channel and switch to Spectrogram; adjust frequency range and window size around the suspected signal.

**Expected:** Visible tone, pulse or time-frequency structure that supports a specific decoder.

**If blocked:** Change display settings and inspect channel differences before concluding no signal exists; keep edits in a derived copy.

**Availability:** Version: (not captured) · Location: /usr/bin/audacity

- Default display settings can hide short events or high-frequency content; preserve the source audio.

[Related helper](research/learning/video-coverage/practice/AUDIO_PRACTICE.html)

[Audacity — documentation](https://manual.audacityteam.org/man/spectrogram_view.html)

<a id="approved-windows-34"></a>
### Autopsy · Windows

**Use for:** Inspect forensic images

**First action:** Create an Autopsy case, add the image and enable relevant ingest modules; inspect keywords, deleted files and artifact views.

**Expected:** A file/event tied to its source path and metadata.

**If blocked:** If broad ingest is slow, list the relevant partition and recover one file with Sleuth Kit.

**Availability:** Version: Latest · Location: installed in Windows · MSI installer (bundles Java and The Sleuth Kit). Administrator rights required.

- Full ingest can be slow; documentation pinned to 4.22.0 may differ from installed release.

[Autopsy — official documentation](https://sleuthkit.org/autopsy/docs/user-docs/4.22.0/ingest_page.html)

<a id="approved-kali-14"></a>
### bulk_extractor · Kali

**Use for:** Extract forensic features from bulk data

**First action:** Run bulk_extractor on a copied image into a new report directory, then inspect only the relevant feature file and follow its reported offsets.

```sh
bulk_extractor -o ./NEW_FEATURES_DIR ./IMAGE.raw
```

**Expected:** Candidate emails, URLs or other features tied to byte locations.

**If blocked:** Broad scanning is noisy; use an artifact-specific parser first when a filesystem or application format is already known.

**Availability:** Version: 2.1.1

- Bulk results can be noisy and costly; begin with known artifact parsers when possible.

[bulk_extractor — upstream repository](https://github.com/simsong/bulk_extractor)

<a id="approved-kali-15"></a>
### bvi · Kali

**Use for:** Inspect binary data

**First action:** Open the binary in bvi's read-only mode and search for a known text or byte pattern; record its offset and neighboring bytes.

**Expected:** A precise location suitable for carving or format inspection.

**If blocked:** If the terminal setup is unusable, inspect a bounded region with xxd or use HxD; do not save changes to the evidence copy.

**Availability:** Version: (not captured) · Interactive tool; the version check returned 'Input is not from a terminal'

- Interactive terminal needed; workbook version check failed outside a terminal.

[bvi — official documentation](https://bvi.sourceforge.net/)

<a id="approved-kali-17"></a>
### bzip2 · Kali

**Use for:** Decompress BZip2 data

**First action:** Test the BZip2 stream, then decompress to a new output without deleting the compressed original.

```sh
bzip2 -t ./ARCHIVE.bz2
bzip2 -dc ./ARCHIVE.bz2 > ./NEW_PAYLOAD.bin
```

**Expected:** A valid stream and separate decoded payload.

**If blocked:** Check whether the input is BZip2, a concatenated stream or truncated; partial output is not a validated recovery.

**Availability:** Version: 1.0.8

[bzip2 — Decompress BZip2 data](https://sourceware.org/bzip2/manual/manual.html)

<a id="approved-kali-18"></a>
### cabextract · Kali

**Use for:** Inspect Microsoft cabinet archives

**First action:** List CAB members, identify the relevant file and extract into a separate directory with the installed cabextract options.

```sh
cabextract -l ./ARCHIVE.cab
```

**Expected:** Cabinet member names and an unpacked artifact.

**If blocked:** A multi-part cabinet needs its neighboring volumes; distinguish CAB from a different installer wrapper.

**Availability:** Version: 1.11

[cabextract — Inspect Microsoft cabinet archives](https://www.kali.org/tools/cabextract/)

<a id="approved-kali-20"></a>
### Chainsaw · Kali

**Use for:** Search Windows event logs

**First action:** Search the supplied EVTX directory for a known event ID or distinctive string; inspect full matching records before adding Sigma rules and their matching mapping.

**Expected:** Timestamped events with host/user fields that answer a focused question.

**If blocked:** Check rule/mapping versions and time zone; a rule hit alone is not a confirmed malicious event.

**Availability:** Version: 2.16.5

- Rule and mapping versions matter; hits are leads, not confirmed malicious events.

[Chainsaw — upstream repository](https://github.com/WithSecureOpenSource/chainsaw)

<a id="approved-kali-25"></a>
### DB Browser for SQLite · Kali

**Use for:** Inspect SQLite records

**First action:** Open a copied SQLite database with its WAL/sidecars in DB Browser; inspect tables and schema, then run a focused SELECT without Write Changes.

**Expected:** Rows with source-table and timestamp context.

**If blocked:** Check WAL completeness and schema if records are absent; use FQLite when deleted-record recovery is the actual need.

**Availability:** Version: 3.13.1

- Keep DB and WAL together; avoid Write Changes on evidence.

[DB Browser for SQLite — official documentation](https://sqlitebrowser.org/)

<a id="approved-kali-26"></a>
### DBeaver Community Edition · Kali

**Use for:** Query local databases

**First action:** Create a local connection to the copied database using the appropriate installed driver; inspect schema and run a bounded SELECT.

**Expected:** Query results with table/column context and known connection settings.

**If blocked:** Offline driver downloads may block setup; use sqlite3 or DB Browser for SQLite rather than rebuilding a general database environment.

**Availability:** Version: 26.1.3

[DBeaver Community Edition — Query local databases](https://dbeaver.com/docs/dbeaver/SQL-Execution/)

<a id="approved-kali-32"></a>
### dwarf2json · Kali

**Use for:** Generate Linux memory-analysis symbols.

**First action:** Obtain the exact kernel's vmlinux debug data and optional System.map; generate Volatility 3 Linux symbols into a new JSON file.

```sh
dwarf2json linux --elf /PATH/TO/MATCHING/vmlinux > ./NEW_KERNEL_SYMBOLS.json
```

**Expected:** A symbol table matching the memory image's kernel build.

**If blocked:** A similar kernel version is insufficient; confirm debug symbols and available memory before processing large DWARF data.

**Availability:** Version: 0.9.0

- Exact kernel build matters; large DWARF inputs require at least 8 GB RAM per upstream.

[dwarf2json — upstream repository](https://github.com/volatilityfoundation/dwarf2json)

<a id="approved-windows-39"></a>
### Eric Zimmerman's Tools · Windows

**Use for:** Select an artifact-specific Windows parser

**First action:** Select MFTECmd for $MFT, EvtxECmd for EVTX or RECmd for registry hives; read that installed binary's help and export focused records separately.

**Expected:** Artifact-specific records and timestamps with parser provenance.

**If blocked:** Check installed subset and .NET runtime; the collection name does not guarantee every parser.

**Availability:** Version: Latest · Location: installed in Windows · Run Get-ZimmermanTools.ps1 to download the tools. Internet access and the .NET Desktop Runtime are required.

- Collection is many binaries; installed subset and .NET requirements must be checked.

[Eric Zimmerman's Tools — official documentation](https://ericzimmerman.github.io/)

<a id="approved-kali-34"></a>
### ewf-tools (libewf) · Kali

**Use for:** Read or export an E01 disk image.

**First action:** Inspect E01 metadata and segment completeness, then expose/export its raw image with the installed libewf tools for filesystem analysis.

```sh
ewfinfo ./IMAGE.E01
```

**Expected:** Acquisition metadata and a readable raw view of the full image.

**If blocked:** Verify all segments and local tool options for the old recorded release; a missing segment can make later filesystem errors misleading.

**Availability:** Version: 20140816

- Recorded 20140816 release is old; verify available commands against local help.

[ewf-tools (libewf) — upstream repository](https://github.com/libyal/libewf)

<a id="approved-kali-40"></a>
### FFmpeg · Kali

**Use for:** Extract relevant audio/video streams or frames before inspecting hidden media content.

**First action:** Inspect input stream metadata, choose the exact audio/video stream and extract a relevant interval, frame or stream into a derived file.

**Expected:** Media matching the selected stream and time range, ready for spectrogram or image analysis.

**If blocked:** Default stream selection may miss secondary content; distinguish lossless stream copy from transcoding and retain the original.

**Availability:** Version: (not captured) · Location: apt (ffmpeg)

- Automatic stream selection can miss a second stream; stream copy and transcoding serve different purposes.

[FFmpeg — documentation](https://ffmpeg.org/ffmpeg.html)

<a id="approved-kali-42"></a>
### file (libmagic) · Kali

**Use for:** Triage an unknown artifact by content instead of its filename extension.

**First action:** Identify a supplied file by its bytes before choosing an extractor or executing anything.

```sh
file -- ./ARTIFACT.bin
```

**Expected:** A format hypothesis, encoding clue or generic data classification.

**If blocked:** Truncated/polyglot files can mislead magic detection; inspect the header with xxd and validate using the actual format parser.

**Availability:** Version: 5.47

- Magic signatures are heuristic and may be misleading for truncated or polyglot files.

[Related helper](TOOLKIT.html#inspect)

[file (libmagic) — documentation](https://github.com/file/file)

<a id="approved-kali-44"></a>
### foremost · Kali

**Use for:** Carve known file types from a raw image or combined binary after initial identification.

**First action:** Select relevant file types after inspecting the raw input, then carve into a fresh output directory and inspect its audit report.

**Expected:** Candidate recovered files with source offsets.

**If blocked:** Fragmentation and false headers can produce incomplete files; validate each object and prefer filesystem recovery when metadata survives.

**Availability:** Version: (not captured) · Installed; version not captured

- Carving may lose filenames and fragmented content; recovered headers do not guarantee complete files.

[foremost — documentation](https://www.kali.org/tools/foremost/)

<a id="approved-kali-45"></a>
### FQLite · Kali

**Use for:** Inspect deleted SQLite records.

**First action:** Load the copied SQLite database together with WAL/journal evidence into FQLite; inspect deleted or unallocated records and their provenance.

**Expected:** Recoverable row fragments linked to pages or sidecar data.

**If blocked:** Overwritten bytes cannot be recovered; corroborate fragments with schema and live rows instead of treating every fragment as a complete record.

**Availability:** Version: (not captured) · Location: /opt/fqlite/bin/fqlite (symlinked to /usr/local/bin)

- Recovery depends on surviving bytes; retain source DB and sidecars together.

[FQLite — upstream repository](https://github.com/pawlaszczyk/fqlite)

<a id="approved-kali-51"></a>
### G'MIC (gmic) · Kali

**Use for:** Reveal low-contrast image content or inspect channels with an alternative image processor.

**First action:** Load a copied image into G'MIC and apply normalization or channel inspection only to a derived output for a specific low-contrast clue.

**Expected:** Previously faint structure becomes visible while the untouched original remains available.

**If blocked:** Normalization changes pixel values; use original bytes for zsteg and ImageMagick for simpler channel inspection.

**Availability:** Version: (not captured) · Version not captured (the command started the G'MIC interpreter)

- Keep as an alternative rather than another full image workflow; normalization modifies evidence pixels, so save a derived copy.

[G'MIC normalize command and example](https://gmic.eu/reference/normalize.html)

<a id="approved-kali-49"></a>
### Git · Kali

**Use for:** Trace file history in a local repository.

**First action:** Inspect all local branches' history and the changed files around a suspicious commit; read a historical blob without altering the working tree.

```sh
git log --all --oneline --decorate
```

**Expected:** A deleted/changed value tied to a commit and path.

**If blocked:** Shallow or incomplete history limits recovery; inspect available refs and avoid pushing or publishing recovered content.

**Availability:** Version: 2.53.0

- Work locally; do not push or expose recovered secrets.

[Git — official documentation](https://git-scm.com/docs/git-log)

<a id="approved-kali-50"></a>
### Gitleaks · Kali

**Use for:** Locate exposed secrets in local repository history.

**First action:** Scan the supplied repository history with the installed Gitleaks workflow and redacted reporting, then inspect each relevant commit locally.

**Expected:** Candidate embedded secrets with commit/path context.

**If blocked:** False positives need contextual verification; choose the local version's git/history command and keep detected values out of shared output.

**Availability:** Version: (not captured) · The tool does not report a version (set at build time)

- False positives and redaction settings need review; do not publish detected values.

[Gitleaks — upstream repository](https://github.com/gitleaks/gitleaks)

<a id="approved-kali-57"></a>
### gzip · Kali

**Use for:** Unpack and check gzip files

**First action:** Test gzip integrity, then decompress to a new file with the original retained.

```sh
gzip -t ./ARCHIVE.gz
gzip -dc ./ARCHIVE.gz > ./NEW_PAYLOAD.bin
```

**Expected:** A checked stream and separate content for identification.

**If blocked:** Confirm gzip versus raw DEFLATE/zlib and inspect truncation; a filename suffix alone is insufficient.

**Availability:** Version: 1.13

[gzip — Unpack and check gzip files](https://www.gnu.org/software/gzip/manual/gzip.html)

<a id="approved-kali-61"></a>
### Hayabusa · Kali

**Use for:** Build a Windows event timeline.

**First action:** Generate a Hayabusa timeline from the relevant EVTX files and filter by host, event type and the question's time window.

**Expected:** Ordered event records and rule matches with their original event context.

**If blocked:** Normalize time zones and validate a hit in the source log; avoid duplicating a broad Chainsaw hunt without a new question.

**Availability:** Version: (not captured) · Version not captured (the --version option is not supported)

- Alternative to Chainsaw for timeline-led work; avoid duplicating broad hunts.

[Hayabusa — upstream repository](https://github.com/Yamato-Security/hayabusa)

<a id="approved-kali-63"></a>
### Hindsight (pyhindsight) · Kali

**Use for:** Parse a saved browser profile.

**First action:** Parse a copied browser profile with Hindsight into a new report; inspect visits, downloads and timestamps relevant to the clue.

**Expected:** A browser-activity timeline linked to profile artifacts.

**If blocked:** Preserve SQLite sidecars and profile completeness; use direct SQLite inspection if the browser/schema version is unsupported.

**Availability:** Version: (not captured) · Location: pipx (pyhindsight)

- Current upstream browser support may exceed the installed version; supply complete relevant profile files.

[Hindsight (pyhindsight) — upstream repository](https://github.com/RyanDFIR/hindsight)

<a id="approved-windows-35"></a>
### HxD · Windows

**Use for:** Inspect bytes in a hex editor

**First action:** Open a copy in HxD; inspect signature, size and clue offset, then byte-search or compare the suspected region.

**Expected:** A reproducible byte location with surrounding context.

**If blocked:** Check search encoding and byte order; save any changes only to a derived copy.

**Availability:** Version: Latest · Location: installed in Windows · Installer or portable edition.

- Use evidence copies before editing or saving.

[HxD — official documentation](https://mh-nexus.de/en/hxd/)

<a id="approved-kali-66"></a>
### iLEAPP (iOS Logs, Events, And Plists Parser) · Kali

**Use for:** Parse iOS forensic artifacts.

**First action:** Point iLEAPP at the supplied iOS extraction and select relevant app/device artifacts with a fresh report destination.

**Expected:** Parsed records linked to source plist, database or log files.

**If blocked:** It does not acquire or decrypt arbitrary devices; check extraction completeness, encryption and supported app versions.

**Availability:** Version: - · No installation information recorded

- Not an acquisition tool; encrypted or unsupported artifacts require appropriate evidence/key material.

[iLEAPP (iOS Logs, Events, And Plists Parser) — upstream repository](https://github.com/abrignoni/iLEAPP)

<a id="approved-kali-67"></a>
### ImageMagick · Kali

**Use for:** Inspect dimensions and channels and create derived images for visual analysis.

**First action:** Inspect image dimensions, channels and format with ImageMagick 7; create a separate crop/channel/contrast derivative only for a visual hypothesis.

```sh
magick identify ./IMAGE.png
```

**Expected:** A reproducible derived view and known image properties.

**If blocked:** Transcoding can destroy LSB evidence; retain the original for zsteg and distinguish visual changes from recovered bytes.

**Availability:** Version: 7.1.2-27

- Use ImageMagick 7 magick syntax. Transformations can destroy LSB evidence; keep the original for zsteg.

[ImageMagick — documentation](https://imagemagick.org/command-line-processing/)

<a id="approved-kali-74"></a>
### Jpeginfo · Kali

**Use for:** Distinguish malformed or truncated JPEG structure from ordinary steganography clues.

**First action:** Check JPEG structure and decoding errors before interpreting unusual image behavior as steganography.

```sh
jpeginfo -c ./IMAGE.jpg
```

**Expected:** Integrity diagnostics distinguish a normal file from a malformed or truncated JPEG.

**If blocked:** Valid JPEG structure does not exclude appended or hidden content; inspect metadata and embedded-file clues next.

**Availability:** Version: 1.7.1

- Do not use deletion options on evidence; a valid JPEG can still contain hidden data.

[Jpeginfo — documentation](https://github.com/tjko/jpeginfo)

<a id="approved-kali-80"></a>
### libesedb tools · Kali

**Use for:** Inspect Windows ESE database tables.

**First action:** Confirm the file is an ESE database, inspect metadata with libesedb tools and export selected tables into a separate directory.

```sh
esedbinfo ./DATABASE.edb
```

**Expected:** Table records ready for application-specific interpretation.

**If blocked:** The .edb suffix is ambiguous; verify format and schema, and preserve transaction-related sidecars where supplied.

**Availability:** Version: 20240420 · Version of esedbexport

- ESE .edb differs from other EDB formats; table schemas are application-specific.

[libesedb tools — upstream repository](https://github.com/libyal/libesedb)

<a id="approved-kali-82"></a>
### lrzip · Kali

**Use for:** Unpack long-range compressed files

**First action:** Inspect local lrzip help for test/decompression mode, then decode the supplied .lrz stream to a separate output while preserving it.

**Expected:** A validated decompressed payload and any integrity diagnostics.

**If blocked:** Memory needs and stream damage can block decoding; identify the actual compression format before choosing another tool.

**Availability:** Version: 0.660

[lrzip — Unpack long-range compressed files](https://github.com/ckolivas/lrzip)

<a id="approved-kali-84"></a>
### lz4 · Kali

**Use for:** Unpack LZ4 data

**First action:** Test the LZ4 stream with the installed CLI, then decompress into a new file.

```sh
lz4 -t ./ARCHIVE.lz4
lz4 -d ./ARCHIVE.lz4 ./NEW_PAYLOAD.bin
```

**Expected:** A decoded payload whose size/content can be checked.

**If blocked:** LZ4 frames and raw blocks are different; raw data needs the format's external size/settings rather than arbitrary CLI guesses.

**Availability:** Version: 1.10.0

[lz4 — Unpack LZ4 data](https://github.com/lz4/lz4)

<a id="approved-kali-85"></a>
### lzip · Kali

**Use for:** Unpack and check lzip files

**First action:** Check the lzip stream, then decompress to a new destination while retaining the source.

```sh
lzip -t ./ARCHIVE.lz
lzip -dc ./ARCHIVE.lz > ./NEW_PAYLOAD.bin
```

**Expected:** An integrity-checked LZMA-based stream and separate decoded content.

**If blocked:** Distinguish lzip from .xz and raw .lzma; inspect truncation or concatenated members before changing formats.

**Availability:** Version: 1.26

[lzip — Unpack and check lzip files](https://www.nongnu.org/lzip/manual/lzip_manual.html)

<a id="approved-kali-86"></a>
### mac_apt · Kali

**Use for:** Parse macOS artifacts from saved evidence.

**First action:** Match mac_apt's supported image/artifact mode to the saved macOS evidence and run only relevant plugins into a new report directory.

**Expected:** Parsed macOS records with source paths and timestamps.

**If blocked:** Check filesystem, encryption and OS-version support; use extracted SQLite/plist artifacts when whole-image parsing is unavailable.

**Availability:** Version: (not captured) · Location: git (/opt/tools/mac_apt)

- Image format and macOS version support depend on installed revision.

[mac_apt — upstream repository](https://github.com/ydkhatri/mac_apt)

<a id="approved-kali-87"></a>
### MediaInfo · Kali

**Use for:** Read audio/video container, codec, stream and duration information to choose an extraction route.

**First action:** Inspect the local file with MediaInfo and record container, stream IDs, codecs, channels and duration before extraction.

```sh
mediainfo ./MEDIA_FILE
```

**Expected:** The exact stream characteristics needed for FFmpeg or audio analysis.

**If blocked:** Metadata alone does not reveal hidden content; select the relevant stream and inspect a spectrogram/frame sequence.

**Availability:** Version: (not captured) · Version not captured

- Use the local CLI, not MediaInfoOnline; project page does not validate installed-version command flags.

[MediaInfo — documentation](https://mediaarea.net/en/MediaInfo)

<a id="approved-kali-89"></a>
### mimikatz · Kali

**Use for:** Understand offline Windows authentication-dump analysis.

**First action:** Read mimikatz's offline minidump workflow only for an explicitly supplied authentication-memory artifact; confirm supported Windows build and architecture before parsing in the isolated lab.

**Expected:** Supported authentication structures can be inspected locally with their source context.

**If blocked:** Wine presence does not establish functionality; use pypykatz for a supported offline dump or report incompatibility without live collection.

**Availability:** Version: 2.2.0 · Location: Wine (Windows binary)

- Wine binary presence does not establish functionality; architecture and Windows build compatibility matter.

[mimikatz — upstream repository](https://github.com/gentilkiwi/mimikatz/wiki)

<a id="approved-kali-91"></a>
### multimon-ng · Kali

**Use for:** Decode supported audio modulation formats

**First action:** Identify the audio modulation from challenge clues/spectrogram, check sample rate and encoding, then select only the corresponding multimon-ng decoder.

**Expected:** A decoded candidate message from a supported modulation.

**If blocked:** Wrong sample representation or modulation yields noise; use SoX/FFmpeg on a derived file and verify against a known signal.

**Availability:** Version: (not captured) · Location: apt (multimon-ng)

[multimon-ng — Decode supported audio modulation formats](https://github.com/EliasOenal/multimon-ng)

<a id="approved-kali-92"></a>
### mupdf-tools (mutool) · Kali

**Use for:** Inspect PDF objects and extract resources.

**First action:** Use mutool to inspect the PDF object tree; identify relevant objects or extract images/fonts into a separate directory.

```sh
mutool show ./DOCUMENT.pdf trailer
```

**Expected:** Object content or resources that can be compared with rendered pages.

**If blocked:** Extraction is not OCR and may include unrelated assets; use qpdf/pdf-parser for another object-level view.

**Availability:** Version: 1.27.0

- Latest docs may differ from recorded 1.27.0; extraction is not text OCR.

[mupdf-tools (mutool) — official documentation](https://mupdf.readthedocs.io/en/latest/tools/mutool.html)

<a id="approved-kali-100"></a>
### OpenStego · Kali

**Use for:** Extract a payload when clues indicate an OpenStego image carrier.

**First action:** If clues point to OpenStego, use its Extract Data workflow on the image with the supplied/clue-derived password and a fresh output directory.

**Expected:** A recovered embedded payload validated by its content.

**If blocked:** An incorrect password or different embedding scheme can look like no data; use carrier-specific evidence rather than treating OpenStego as a universal LSB decoder.

**Availability:** Version: (not captured) · Location: GitHub .deb package

- Not a generic decoder for every LSB scheme; installed version is unknown.

[OpenStego — documentation](https://www.openstego.com/)

<a id="approved-kali-106"></a>
### pff-tools (libpff) · Kali

**Use for:** Inspect and extract Outlook personal-folder data.

**First action:** Inspect PST/OST metadata, then export relevant messages and attachments to a separate directory using the installed libpff tools.

```sh
pffinfo ./MAILBOX.pst
```

**Expected:** Message headers, timestamps and attachment files linked to the mailbox.

**If blocked:** Check supported mailbox variant and local pffexport options; corruption or partial stores may limit recovery.

**Availability:** Version: 20231205 · Version of pffexport

- Check local pffexport help and format support; preserve original mailbox.

[pff-tools (libpff) — upstream repository](https://github.com/libyal/libpff)

<a id="approved-kali-107"></a>
### Plaso (log2timeline, psort, pinfo) · Kali

**Use for:** Build a forensic timeline from artifacts.

**First action:** Parse only the relevant artifact set into a new Plaso storage file; inspect its metadata with pinfo and export the question's interval with psort.

**Expected:** A timeline retaining parser/source provenance and normalized timestamp interpretation.

**If blocked:** Whole-image parsing may waste time; narrow inputs and verify time zones and timestamp semantics before correlating events.

**Availability:** Version: 20260119-1kali1

- Whole-image parsing costs time; normalize time zones and retain parser provenance.

[Plaso (log2timeline, psort, pinfo) — official documentation](https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html)

<a id="approved-kali-108"></a>
### pngcheck · Kali

**Use for:** Inspect PNG chunks, integrity failures and text metadata before pixel analysis.

**First action:** Inspect PNG chunks and integrity before attempting pixel-bit analysis. Record text chunks, unexpected trailing data and any CRC/truncation errors.

```sh
pngcheck -v ./IMAGE.png
```

**Expected:** Structural findings distinguish format damage from a steganography lead.

**If blocked:** Check local version options and confirm with another PNG reader; valid structure does not exclude LSB content.

**Availability:** Version: (not captured) · Location: apt (pngcheck)

- Repository targets pngcheck 4; installed version is unknown. Do not assume every current option exists locally.

[pngcheck — documentation](https://github.com/pnggroup/pngcheck)

<a id="approved-kali-112"></a>
### pypykatz · Kali

**Use for:** Parse a supplied Windows memory dump.

**First action:** Select pypykatz's offline minidump parser for an explicitly supplied Windows authentication dump and inspect only relevant records locally.

**Expected:** Supported authentication structures with source context.

**If blocked:** Build/dump incompatibility is not proof of absent data; keep recovered values private and avoid replacing offline analysis with live acquisition.

**Availability:** Version: 0.6.13

- Requires supported dump/build; avoid printing recovered secrets into public reports.

[pypykatz — upstream repository](https://github.com/skelsec/pypykatz)

<a id="approved-kali-115"></a>
### qemu-img (qemu-utils) · Kali

**Use for:** Identify and convert virtual disk formats.

**First action:** Inspect virtual-disk format and backing files before converting a copy to raw with enough free output space.

```sh
qemu-img info ./VIRTUAL_DISK
```

**Expected:** Correct source format/backing chain and a raw image suitable for filesystem tools.

**If blocked:** Missing backing files make dependent images incomplete; do not modify an image in use or mistake conversion for recovery.

**Availability:** Version: 11.0.3

- Do not modify an image in use; allocate enough output space and retain backing-chain evidence.

[qemu-img (qemu-utils) — official documentation](https://www.qemu.org/docs/master/tools/qemu-img.html)

<a id="approved-kali-118"></a>
### RegRipper · Kali

**Use for:** Extract artifacts from offline Windows registry hives.

**First action:** Identify the offline registry hive type and select the relevant installed RegRipper 3 plugin; retain plugin name and source hive with its output.

**Expected:** Keys, values and available timestamps relevant to the question.

**If blocked:** Transaction logs are not replayed automatically; note missing recent state and use another approved parser if replay is required.

**Availability:** Version: 3.0

- RegRipper does not automatically replay hive transaction logs; do not silently omit them.

[RegRipper — upstream repository](https://github.com/keydet89/RegRipper3.0)

<a id="approved-kali-122"></a>
### rtptools (rtpdump, rtpplay and others) · Kali

**Use for:** Parse RTP recordings and understand replay formats.

**First action:** Identify whether the supplied recording is an rtptools dump or a PCAP; use the matching rtptools inspection/replay workflow only for its supported RTP dump format.

**Expected:** RTP headers, sequence numbers and timing can be examined or replayed in an isolated endpoint.

**If blocked:** Replay is not audio decoding; for PCAP use Wireshark RTP analysis and decode the payload with the correct codec.

**Availability:** Version: (not captured) · Location: /opt/tools/rtptools · Built from source

- RTP dump formats are distinct from arbitrary PCAP files; replay is not audio decoding.

[rtptools (rtpdump, rtpplay and others) reference](https://github.com/irtlab/rtptools)

<a id="approved-kali-128"></a>
### Sonic Visualiser · Kali

**Use for:** Inspect and measure audio spectrograms in separate panes/layers.

**First action:** Open audio in Sonic Visualiser, add a spectrogram layer and align separate panes/channels to measure tone frequencies or pulse timing.

**Expected:** Measurable time/frequency intervals supporting a decoder or symbol mapping.

**If blocked:** Adjust FFT/window settings and channel selection; use Audacity for basic inspection when measurement detail is unnecessary.

**Availability:** Version: 5.2.1

- Keep as the measurement-focused alternative to Audacity; no need to duplicate basic spectrogram instructions.

[Related helper](research/learning/video-coverage/practice/AUDIO_PRACTICE.html)

[Sonic Visualiser — documentation](https://www.sonicvisualiser.org/doc/reference/5.2.1/en/)

<a id="approved-kali-129"></a>
### SoX (Sound eXchange) · Kali

**Use for:** Create repeatable audio spectrograms and manipulate channels using the installed SoX_ng build.

**First action:** Confirm whether the installed executable is SoX_ng and inspect its supported effects; create a spectrogram or channel derivative only after checking input rate/channels.

```sh
sox --help
```

**Expected:** A repeatable derived audio view with explicit processing settings.

**If blocked:** Exact options may differ from legacy SoX; use Audacity or FFmpeg when the local build cannot perform the intended operation.

**Availability:** Version: 14.7.1.2 · SoX_ng build

- Workbook reports SoX_ng, not legacy SoX. Current source fetch blocked; exact installed options remain unverified.

[Related helper](research/learning/video-coverage/practice/AUDIO_PRACTICE.html)

[SoX (Sound eXchange) — documentation](https://codeberg.org/sox_ng/sox_ng)

<a id="approved-kali-130"></a>
### SQLCipher Community Edition — CLI · Kali

**Use for:** Open a SQLCipher database with its known key and settings.

**First action:** Open the copied SQLCipher database, supply the known key interactively and set the required compatibility/KDF parameters before the first query.

**Expected:** A readable schema and rows from the encrypted database.

**If blocked:** Wrong compatibility settings can resemble a wrong key; verify the producer's SQLCipher version rather than treating this CLI as a password cracker.

**Availability:** Version: SQLite 3.53.4 / SQLCipher 4.18.0

- Not a password cracker; a wrong compatibility setting can look like a wrong key.

[SQLCipher Community Edition — CLI — official documentation](https://www.zetetic.net/sqlcipher/sqlcipher-api/)

<a id="approved-kali-131"></a>
### sqlite3 · Kali

**Use for:** Inspect a SQLite database without changing it.

**First action:** Open the copied SQLite database read-only with its sidecars; inspect tables/schema, then query only the relevant rows and timestamp fields.

```sh
sqlite3 -readonly ./DATABASE.sqlite '.tables'
```

**Expected:** Records whose table, column and time encoding can be explained.

**If blocked:** Preserve WAL files and check application-specific timestamp units; missing rows may require deleted-record analysis.

**Availability:** Version: 3.53.4

- Preserve WAL sidecars; SQL timestamps may need application-specific conversion.

[sqlite3 — official documentation](https://sqlite.org/cli.html)

<a id="approved-kali-133"></a>
### sstv (command-line SSTV decoder) · Kali

**Use for:** Decode SSTV audio only if the installed executable is actually a decoder.

**First action:** Inspect the actual installed executable/package before decoding: the workbook labels sstv a decoder but records PySSTV, which is an encoder.

**Expected:** A confirmed identity shows whether an approved decoder is actually available.

**If blocked:** Do not assume colaclanth/sstv is installed from the row name. If only PySSTV exists, inspect audio visually and record the decoding gap.

**Availability:** Version: (not captured) · Location: pip (PySSTV)

- Workbook tool label says decoder but location says pip PySSTV, an encoder. Do not claim colaclanth/sstv is installed or separately approved.

[sstv (command-line SSTV decoder) — documentation](https://github.com/colaclanth/sstv) · [PySSTV package description and CLI](https://pypi.org/project/pySSTV/)

<a id="approved-kali-134"></a>
### steghide · Kali

**Use for:** Inspect and extract a steghide carrier using a known or clue-derived passphrase.

**First action:** Inspect supported carrier information, then extract with the supplied or clue-derived passphrase into a new file.

```sh
steghide info ./CARRIER.jpg
```

**Expected:** A steghide payload whose recovered bytes validate.

**If blocked:** PNG is not a supported steghide carrier; wrong passphrase or a different embedding scheme needs a new hypothesis.

**Availability:** Version: 0.6.0

- Kali page version badge says 0.5.1 while embedded help says 0.6.0, matching workbook; validate local help. PNG is not a listed carrier.

[steghide — documentation](https://www.kali.org/tools/steghide/)

<a id="approved-kali-135"></a>
### stegseek · Kali

**Use for:** Recover a steghide payload with a wordlist; use seed mode to detect steghide structure.

**First action:** For a likely steghide carrier, run a focused wordlist attempt to a new output; use seed detection only with its documented limits.

**Expected:** A validated payload and, where found, its matching password candidate.

**If blocked:** Seed mode detects structure; passwordless recovery requires unencrypted data. A wrong carrier or exhausted list needs evidence, not claims of decryption.

**Availability:** Version: 0.6

- Seed mode is not universal passwordless decryption: content recovery without a password requires unencrypted data.

[stegseek — documentation](https://github.com/RickdeJager/stegseek)

<a id="approved-kali-136"></a>
### stegsnow (SNOW) · Kali

**Use for:** Decode trailing-space/tab steganography in text when whitespace is the clue.

**First action:** Preserve the original text's trailing spaces/tabs and use stegsnow's decode mode, adding a supplied password only if the clue requires it.

```sh
stegsnow ./WHITESPACE.txt
```

**Expected:** Decoded bytes from the untouched whitespace carrier.

**If blocked:** Copy/paste or editor cleanup can destroy the payload; return to the original file and check whether compression/password settings apply.

**Availability:** Version: (not captured) · Location: apt (stegsnow)

- Text editors and copy/paste may strip the payload. Author homepage failed current fetch; distro help was reopened.

[Kali stegsnow package usage](https://www.kali.org/tools/stegsnow/)

<a id="approved-kali-137"></a>
### StegSolve · Kali

**Use for:** Visually inspect image bit planes and investigate a specific data-extraction hypothesis.

**First action:** Open the original image in a working StegSolve GUI and inspect the clue's channel/bit planes; use Data Extract only after choosing a concrete order/plane hypothesis.

**Expected:** A visible pattern or extracted byte sequence that can be reproduced.

**If blocked:** The recorded launch failed headlessly and the reference fork may differ; use zsteg or derived channel views if the GUI is unavailable.

**Availability:** Version: (not captured) · Version not captured (GUI tool; it was started without a display)

- Reference is a modified fork, not proof of the organiser-installed build. Requires a working graphical display; workbook records a headless launch failure.

[StegSolve — documentation](https://github.com/Giotino/stegsolve)

<a id="approved-kali-141"></a>
### tar · Kali

**Use for:** List and extract archive members

**First action:** List archive members first, inspect paths and sizes, then extract the relevant members into a fresh directory.

```sh
tar -tf ./ARCHIVE.tar
```

**Expected:** Expected files recovered without overwriting the source tree.

**If blocked:** Check compression and missing multipart data; treat absolute/traversal paths and symlink members carefully before extraction.

**Availability:** Version: 1.35

[tar — List and extract archive members](https://www.gnu.org/software/tar/manual/html_node/extract.html)

<a id="approved-kali-142"></a>
### tcpdump · Kali

**Use for:** Read a capture using host/port filters for quick packet triage.

**First action:** Read a supplied capture with a narrow host/port/protocol filter and a bounded packet count before escalating to stream reconstruction.

```sh
tcpdump -nn -r ./CAPTURE.pcap -c 50
```

**Expected:** Packet summaries identify relevant peers and protocols.

**If blocked:** tcpdump filters differ from Wireshark display filters; use Wireshark/TShark when payload reassembly or protocol fields are needed.

**Availability:** Version: 4.99.6

- Capture filters are not Wireshark display filters; upstream manual was blocked in this browsing session.

[Kali tcpdump package documentation](https://www.kali.org/tools/tcpdump/)

<a id="approved-kali-143"></a>
### TestDisk and PhotoRec · Kali

**Use for:** Recover files from a disk image.

**First action:** Use TestDisk's file-list/copy workflow on an image when filesystem metadata survives; use PhotoRec carving only when metadata recovery cannot locate the content.

**Expected:** Recovered files in a separate destination, with names/paths where metadata permits.

**If blocked:** Carving loses original names and fragmented files may fail; validate file content and never recover into the source image/device.

**Availability:** Version: 7.2

- Carving loses names/paths and can be noisy; recover to another destination, never the source.

[TestDisk and PhotoRec — official documentation](https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step)

<a id="approved-windows-36"></a>
### tshark · Windows

**Use for:** Extract selected packet fields into compact text for searching or sorting.

**First action:** Read an existing capture with a display filter and emit only the needed fields, including packet numbers for traceability.

```sh
tshark -r ./CAPTURE.pcap -Y http.request -T fields -e frame.number -e http.host -e http.request.uri
```

**Expected:** Searchable rows linked to packets in Wireshark.

**If blocked:** Check local field names and dissection; -Y display filters differ from capture filters.

**Availability:** Version: Latest · Location: installed in Windows · Included in the Wireshark installer (TShark component).

- Windows TShark component may not be on PATH; display and capture filter syntaxes differ.

[Related helper](research/learning/practice/README.html)

[tshark reference](https://www.wireshark.org/docs/man-pages/tshark.html)

<a id="approved-kali-144"></a>
### unar · Kali

**Use for:** List and extract supported archive formats

**First action:** List supported archive contents with the accompanying lsar tool, then extract selected content with unar to a new directory using local options.

```sh
lsar ./ARCHIVE
```

**Expected:** Member metadata and extracted files for the next format-specific tool.

**If blocked:** Check multipart volumes, passwords and format support; use 7-Zip for another local archive view.

**Availability:** Version: 1.10.8

[unar — List and extract supported archive formats](https://theunarchiver.com/command-line)

<a id="approved-kali-147"></a>
### unrar · Kali

**Use for:** List, test and extract RAR archives

**First action:** List the RAR archive, test its integrity and extract needed members into a new directory with all supplied volumes present.

```sh
unrar l ./ARCHIVE.rar
unrar t ./ARCHIVE.rar
```

**Expected:** Member names and integrity results before recovery.

**If blocked:** Missing volumes or a password are different from corruption; resolve those inputs before repeatedly extracting.

**Availability:** Version: (not captured) · Location: /usr/bin/unrar

[unrar — List, test and extract RAR archives](https://www.rarlab.com/rar_add.htm)

<a id="approved-kali-148"></a>
### unzip · Kali

**Use for:** List and extract ZIP members

**First action:** List ZIP members and test the archive before extracting selected entries to a fresh directory.

```sh
unzip -l ./ARCHIVE.zip
unzip -t ./ARCHIVE.zip
```

**Expected:** Names, sizes and integrity diagnostics that select the useful file.

**If blocked:** Check encryption and unsupported ZIP features; use 7-Zip for another parser and do not ignore failed CRC checks.

**Availability:** Version: 6.0-30

[unzip — List and extract ZIP members](https://infozip.sourceforge.net/UnZip.html)

<a id="approved-kali-151"></a>
### Volatility 2 · Kali

**Use for:** Identify a memory image profile and inspect processes.

**First action:** For a supported legacy Windows memory image, obtain profile suggestions and corroborate the OS/build before running process or network plugins with that profile.

**Expected:** Consistent legacy memory structures and process records.

**If blocked:** Wrong profiles produce misleading output; use matching evidence and Volatility 3 for a supported newer image rather than mixing command syntax.

**Availability:** Version: (not captured) · Location: git (/opt/tools/volatility)

- Volatility 2 is legacy and profile-based; do not paste Volatility 3 commands into it.

[Volatility 2 — upstream repository](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)

<a id="approved-kali-152"></a>
### Volatility 2 community plugins · Kali

**Use for:** Load community plugins for Volatility 2.

**First action:** Select one Volatility 2 community plugin for the artifact missing from core coverage; read its dependencies and load it with the matching profile.

**Expected:** The plugin appears in help and returns records consistent with known core-plugin findings.

**If blocked:** Check plugin API/Python compatibility; a directory of community plugins is not blanket proof that every plugin works.

**Availability:** Version: (not captured) · Location: git (/opt/tools/community)

- Plugin-specific dependencies and compatibility are unverified; no blanket functionality claim.

[Volatility 2 community plugins — upstream repository](https://github.com/volatilityfoundation/community)

<a id="approved-kali-153"></a>
### Volatility 2 profiles (Linux and macOS) · Kali

**Use for:** Match Linux or macOS profiles to memory images.

**First action:** Match the memory image's exact Linux/macOS build to an available Volatility 2 profile and verify recognized core structures before using artifact plugins.

**Expected:** A profile whose output agrees with independent OS/kernel evidence.

**If blocked:** A similarly named kernel is insufficient; if no exact profile exists, report the gap or use the compatible Volatility 3 symbol route.

**Availability:** Version: (not captured) · Location: git (/opt/tools/profiles)

- A similarly named kernel is insufficient; profile availability does not guarantee a match.

[Volatility 2 profiles (Linux and macOS) — upstream repository](https://github.com/volatilityfoundation/profiles)

<a id="approved-kali-154"></a>
### Volatility 3 community plugins (community3) · Kali

**Use for:** Load Volatility 3 community plugins; check each plugin against the installed release.

**First action:** Choose the specific Volatility 3 community plugin needed, inspect its release requirements and load it from an explicit plugin directory.

**Expected:** The plugin is discoverable and produces plausible records with the image's matching symbols.

**If blocked:** Upstream warns of incompatibility with current Volatility 3; use a core plugin or report unsupported behavior instead of assuming presence means readiness.

**Availability:** Version: (not captured) · Location: git (/opt/tools/community3)

- Upstream warns plugins may be incompatible with current Volatility 3; test the exact plugin.

[Volatility 3 community plugins (community3) — upstream repository](https://github.com/volatilityfoundation/community3)

<a id="approved-kali-160"></a>
### zstd · Kali

**Use for:** Inspect and decompress Zstandard data

**First action:** Test the Zstandard stream and decompress to a separate destination using the installed CLI.

```sh
zstd -t ./ARCHIVE.zst
zstd -dc ./ARCHIVE.zst > ./NEW_PAYLOAD.bin
```

**Expected:** Integrity diagnostics and a decoded payload to identify.

**If blocked:** A dictionary-compressed frame needs its matching dictionary; confirm framing and missing inputs before blaming the decoder.

**Availability:** Version: 1.5.7

[zstd — Inspect and decompress Zstandard data](https://github.com/facebook/zstd/blob/dev/programs/README.md)

<a id="approved-kali-161"></a>
### Zui (formerly Brim) · Kali

**Use for:** Explore large imported capture-derived datasets with queries.

**First action:** Import an already supported capture-derived dataset into Zui and query connections/protocol records by the relevant endpoint or time window.

**Expected:** A small set of records that can be traced to packets or source logs.

**If blocked:** Verify the installed version and PCAP-import dependencies; use Zeek plus Wireshark if direct import is unavailable.

**Availability:** Version: (not captured) · Version not captured (the command only printed a startup message)

- Repository moved to the superdb organisation; installed version unknown and PCAP import prerequisites must be checked.

[Zui upstream repository](https://github.com/superdb/zui)

<a id="malware"></a>
## Malware Analysis

1. Keep the sample local and begin with static identification: file/Detect It Easy for format and architecture, strings or FLOSS for text, and capa for supported executable capabilities.
2. Follow meaningful capa/string locations in Ghidra or the format-specific decompiler; record the code that supports each claimed behavior.
3. For Office/PDF content, select oletools or the exact Didier Stevens script to list streams/objects and extract code without enabling macros.
4. For packaged content, use the identified wrapper's extractor: asar, pyinstxtractor-ng, innoextract or UPX. Identify each output before opening it.
5. Use a debugger, Frida or simulated network only when a specific runtime question remains and an isolated compatible lab is available.
6. For an obfuscated PHP/HTA script, inspect source as data first. Follow only evidenced literal transforms, cap input and output at each decoding layer, and retain intermediate hashes. Never eval the sample or instantiate serialized objects just to inspect it.

**Look for:** A code-backed behavior or configuration finding, with extracted content tied to its original object/function.

**If blocked:** Packing, unsupported bytecode or absent runtime dependencies can limit analysis. Report static hypotheses separately from observed execution and choose one compatible extractor/debugger rather than trying every tool.

**Start with:** [Detect It Easy (DIE) (Kali)](#approved-kali-27) · [strings (Windows / WSL)](#approved-windows-11) · [FLOSS (FLARE Obfuscated String Solver) (Kali)](#approved-kali-43) · [capa (Kali)](#approved-kali-19) · [Ghidra (Windows / WSL)](#approved-windows-22) · [oletools (full suite: olevba, oleid, oleobj, rtfobj, mraptor, msodde, olemeta, oletimes, pyxswf) (Kali)](#approved-kali-98) · [Didier Stevens Suite (pdfid.py, pdf-parser.py, oledump.py and others) (Kali)](#approved-kali-30) · [asar (@electron/asar) (Kali)](#approved-kali-9) · [pyinstxtractor-ng (Kali)](#approved-kali-111) · [UPX (Kali)](#approved-kali-149) · [FakeNet-NG (Kali)](#approved-kali-37) · [rat-king-parser (Kali)](#approved-kali-117)

[Read-only byte preview](TEMPLATES.html#file-intel)

[Container and document triage practice](research/learning/video-coverage/practice/TRIAGE_PRACTICE.html)

[YARA match and near-miss practice](research/learning/practice/README.html)

<a id="approved-kali-11"></a>
### AutoIt-Ripper · Kali

**Use for:** Extract an embedded AutoIt script from an identified AutoIt executable.

**First action:** Confirm the executable appears to contain supported AutoIt data, then use the installed AutoIt-Ripper extraction workflow on a copy.

**Expected:** An extracted script or embedded resources for static reading.

**If blocked:** A failed extraction may reflect a variant or packing; inspect the wrapper with Detect It Easy and preserve the original.

**Availability:** Version: (not captured) · Location: pipx (autoit-ripper)

- Only supported AutoIt formats; extraction failure does not rule out AutoIt.

[AutoIt-Ripper — primary documentation](https://github.com/nazywam/AutoIt-Ripper)

<a id="approved-kali-19"></a>
### capa · Kali

**Use for:** Identify likely capabilities, then use verbose match locations to select functions to inspect.

**First action:** Run capa with verbose matches on the supported sample; use rule names and addresses to choose functions for manual inspection.

```sh
capa -v ./SAMPLE.bin
```

**Expected:** Capability hypotheses linked to specific code locations.

**If blocked:** Packing or unsupported formats can hide behavior; inspect the format and corroborate matches in Ghidra.

**Availability:** Version: 9.4.0

- Capability matches guide investigation; they are not proof of observed runtime behavior.

[capa — primary documentation](https://github.com/mandiant/capa)

<a id="approved-kali-27"></a>
### Detect It Easy (DIE) · Kali

**Use for:** Identify file type, compiler and probable packer before choosing the next tool.

**First action:** Open the sample in Detect It Easy and inspect format, architecture, sections and probable compiler/packer.

**Expected:** A format/packing hypothesis that selects the next analysis tool.

**If blocked:** Confirm signature matches with bytes and code; a detected packer name is not proof of successful unpacking.

**Availability:** Version: 3.21

- Signature detections are hypotheses; confirm with sections, strings and code.

[Detect It Easy (DIE) — primary documentation](https://github.com/horsicq/Detect-It-Easy)

<a id="approved-kali-29"></a>
### Didier Stevens Beta tools (onedump.py) · Kali

**Use for:** List OneNote embedded objects and extract the suspicious object for separate inspection.

**First action:** Use installed onedump.py help to list objects in the supplied OneNote file; select a relevant object explicitly and extract it to a new file.

**Expected:** An object index and extracted bytes with their original container retained.

**If blocked:** The beta interface may differ; identify the extracted format before choosing another tool and do not execute embedded content.

**Availability:** Version: (not captured) · Location: git (/opt/tools/Beta)

- Beta tool manual is incomplete; check installed help and select objects explicitly.

[Didier Stevens Beta tools (onedump.py) — primary documentation](https://github.com/DidierStevens/Beta/blob/master/onedump.py)

<a id="approved-kali-30"></a>
### Didier Stevens Suite (pdfid.py, pdf-parser.py, oledump.py and others) · Kali

**Use for:** Triage PDF indicators, inspect referenced streams, or extract OLE macro streams.

**First action:** For PDF, run PDFiD for indicators then inspect referenced objects with pdf-parser; for OLE, list streams with oledump and select the macro/object stream.

```sh
python3 /PATH/TO/DIDIER_SUITE/pdfid.py /ABSOLUTE/PATH/DOCUMENT.pdf
python3 /PATH/TO/DIDIER_SUITE/pdf-parser.py /ABSOLUTE/PATH/DOCUMENT.pdf
```

**Expected:** Suspicious object types or extracted code linked to object/stream identifiers.

**If blocked:** Counts are triage only; compressed or indirect objects need the matching stream parser, not a malware verdict from keyword counts.

**Availability:** Version: (not captured) · Location: git (/opt/tools/DidierStevensSuite)

- PDFiD counts are triage only; repository is a suite, so pick the exact script and inspect its help.

[Related helper](research/learning/video-coverage/practice/TRIAGE_PRACTICE.html)

[Didier Stevens Suite (pdfid.py, pdf-parser.py, oledump.py and others) — primary documentation](https://github.com/DidierStevens/DidierStevensSuite) · [Author PDF tools guide](https://blog.didierstevens.com/programs/pdf-tools/)

<a id="approved-kali-37"></a>
### FakeNet-NG · Kali

**Use for:** Observe attempted DNS/HTTP behavior against simulated network services.

**First action:** In a disposable isolated lab, configure FakeNet-NG's simulated services and capture/log destinations before running an authorised sample.

**Expected:** Attempted DNS/HTTP or other supported connections visible in local logs.

**If blocked:** If containment or required privileges are unavailable, use static strings/capa and supplied captures; do not redirect the shared network.

**Availability:** Version: (not captured) · Location: /opt/tools/flare-fakenet-ng (fakenet in PATH)

- Requires a contained lab and network privileges; never redirect the shared competition network.

[FakeNet-NG — primary documentation](https://github.com/mandiant/flare-fakenet-ng)

<a id="approved-kali-43"></a>
### FLOSS (FLARE Obfuscated String Solver) · Kali

**Use for:** Recover decoded and stack-built strings, then cross-reference meaningful results.

**First action:** Run FLOSS on a supported executable to recover static, stack-built or decoded strings, then follow meaningful results into the code.

```sh
floss ./SAMPLE.exe
```

**Expected:** Candidate hidden strings with enough context to choose a function or address.

**If blocked:** FLOSS is not a universal unpacker; inspect packing/architecture and use Ghidra when emulation cannot recover strings.

**Availability:** Version: (not captured) · Location: pipx (flare-floss)

- Not a universal unpacker; use local output rather than uploading challenge data to a hosted viewer.

[FLOSS (FLARE Obfuscated String Solver) — primary documentation](https://github.com/mandiant/flare-floss)

<a id="approved-kali-70"></a>
### internet_detector · Kali

**Use for:** Consult INetSim service simulation only after confirming what this workbook row installed.

**First action:** Resolve the workbook's identity conflict first: inspect the recorded launcher/package locally and determine whether it is INetSim or a separate internet_detector program.

**Expected:** A confirmed executable, package and version that can be matched to documentation.

**If blocked:** If identity remains unclear, keep this entry reference-only. Do not assume INetSim options or network-simulation behavior from the row label.

**Availability:** Version: (not captured) · Location: apt (inetsim) · Provided by the apt package 'inetsim'

- Workbook calls it internet_detector but records apt package inetsim; the executable identity is unresolved.

[internet_detector — primary documentation](https://www.inetsim.org/)

<a id="approved-kali-98"></a>
### oletools (full suite: olevba, oleid, oleobj, rtfobj, mraptor, msodde, olemeta, oletimes, pyxswf) · Kali

**Use for:** Triage an Office file and extract VBA, DDE or embedded objects using the matching suite tool.

**First action:** Choose the Office parser by artifact: oleid for triage, olevba for VBA, rtfobj/oleobj for embedded objects, and msodde when DDE is the clue.

```sh
olevba ./DOCUMENT.docm
```

**Expected:** Extracted code or objects tied to their document streams.

**If blocked:** Never enable macros to inspect them; unsupported containers need archive/object inspection and decoded content still requires analysis.

**Availability:** Version: (not captured) · Location: pipx (oletools)

- Do not enable macros; extracted or decoded content still needs inspection.

[Related helper](research/learning/video-coverage/practice/TRIAGE_PRACTICE.html)

[oletools (full suite: olevba, oleid, oleobj, rtfobj, mraptor, msodde, olemeta, oletimes, pyxswf) — primary documentation](https://github.com/decalage2/oletools) · [olevba usage and examples](https://github.com/decalage2/oletools/wiki/olevba)

<a id="approved-kali-105"></a>
### peepdf-3 · Kali

**Use for:** Inspect a PDF object graph and decode suspicious streams interactively.

**First action:** Open the PDF in peepdf-3 and inspect its object graph, suspicious references and decoded streams relevant to the clue.

**Expected:** A specific object/stream explains embedded code or unusual document behavior.

**If blocked:** Optional JavaScript features may be unavailable; extract/inspect the stream with qpdf or pdf-parser rather than executing it.

**Availability:** Version: (not captured) · Location: pipx (peepdf-3)

- Use this Python 3 fork; JavaScript analysis features may require optional dependencies.

[peepdf-3 — primary documentation](https://github.com/digitalsleuth/peepdf-3)

<a id="approved-kali-117"></a>
### rat-king-parser · Kali

**Use for:** Extract configuration after evidence identifies a supported RAT family.

**First action:** Confirm evidence for a supported RAT family, then select the matching rat-king-parser family workflow on a copied sample.

**Expected:** Extracted configuration fields that agree with the sample's code or strings.

**If blocked:** Variant coverage is finite; empty output does not prove no configuration, so inspect the storage/decryption routine manually.

**Availability:** Version: 4.2.4

- Family and variant coverage is finite; empty output does not prove absence of configuration.

[rat-king-parser — primary documentation](https://github.com/jeFF0Falltrades/rat_king_parser)

<a id="approved-kali-157"></a>
### YARA · Kali

**Use for:** Write a small signature and scan a local sample corpus for related files.

**First action:** Compile a small meaningful YARA rule and scan a local sample plus a near-miss control; inspect matched strings and offsets.

```sh
yara -s ./RULES.yar ./SAMPLE.bin
```

**Expected:** A pattern match that distinguishes the intended bytes from the control.

**If blocked:** A hit is not a malware verdict; refine overly broad strings and validate syntax/conditions before scanning a large corpus.

**Availability:** Version: 4.5.8

- A rule match identifies a pattern, not a malware verdict; stable docs identify as 4.4.0 versus approved 4.5.8.

[Related helper](research/learning/practice/README.html)

[YARA — primary documentation](https://yara.readthedocs.io/en/stable/writingrules.html)

<a id="approved-kali-158"></a>
### yara-python (and YARA on Linux) · Kali

**Use for:** Use Python bindings only when a prewritten batch-scanning workflow needs structured match data.

**First action:** Use yara-python only when an existing Python workflow needs structured matches; compile the same rule used by the CLI and compare results on the same sample/control.

**Expected:** Python match data agrees with the CLI for the selected rule and files.

**If blocked:** Check binding/library version compatibility; use the YARA CLI directly when no structured integration is needed.

**Availability:** Version: (not captured) · Location: pip (yara-python)

- Avoid duplicating the CLI route; binding version is unknown and must match expected API behavior.

[yara-python (and YARA on Linux) — primary documentation](https://yara.readthedocs.io/en/stable/yarapython.html)

<a id="web"></a>
## Web Security

1. Reproduce the intended action in Chrome and capture its request, session state and response in Burp. Replay an unchanged baseline in Repeater.
2. Change one input and compare status, body, headers and protected content with the baseline and a negative control.
3. Inspect client code and linked routes before discovery. If discovery is needed, calibrate a nonexistent path and use one bounded ffuf run with a short appropriate wordlist.
4. Use the relevant offline PayloadsAllTheThings entry only after identifying a plausible primitive. Match sqlmap, jwt_tool or a padding-oracle tool to demonstrated prerequisites.
5. Retest the specific behavior through an independent request; a scanner hit or decoded JWT is not proof of an exploitable condition.
6. Read response headers as well as status and body: Server, Content-Type, Location and authentication/session fields can change the next test. Treat a version banner as a lead, not proof of exploitability; preserve redirects and reject incomplete responses.

**Look for:** A reproducible request/response difference that establishes the precise behavior or vulnerability and its session requirements.

**If blocked:** Resolve expired cookies, redirects, wildcard responses, throttling and an unstable baseline before broadening tests. Prefer manual Repeater/curl checks when automation obscures the signal.

**Start with:** [Google Chrome (Windows)](#approved-windows-5) · [Burp Suite Community Edition (Windows / WSL)](#approved-windows-20) · [curl (Kali)](#approved-kali-23) · [ffuf (Kali)](#approved-kali-41) · [SecLists (Kali)](#approved-kali-126) · [PayloadsAllTheThings (offline copy) (Kali)](#approved-kali-103) · [sqlmap (Kali)](#approved-kali-132) · [jwt_tool (Kali)](#approved-kali-77) · [padding-oracle-attacker (Kali)](#approved-kali-101) · [Katana (Kali)](#approved-kali-78)

[Single HTTP request template](TEMPLATES.html#http)

[Reviewed web learning references](LEARNING_RESOURCES.html)

<a id="approved-windows-20"></a>
### Burp Suite Community Edition · Windows / WSL · Trend Micro proposal

**Use for:** Replay an observed HTTP request while changing one parameter at a time.

**First action:** Send a captured request to Repeater, replay it unchanged, then modify one input and compare status, body, headers and session effects.

**Expected:** A reproducible difference attributable to that input.

**If blocked:** Restore the baseline and refresh expired session state; this manual route works in Community Edition.

**Availability:** Version: 2026.4.x (confirm latest at install time) · Location: installed in WSL

- Community edition; avoid recipes requiring Professional scanner features. Windows row installs in WSL.

[Related helper](TEMPLATES.html#http)

[Burp Suite Community Edition reference](https://portswigger.net/burp/documentation/desktop/tools/repeater)

<a id="approved-windows-5"></a>
### Google Chrome · Windows · Trend Micro proposal

**Use for:** Inspect request headers, response bodies, JavaScript and public-source pages.

**First action:** Open DevTools → Network before reproducing an action; inspect its request URL, headers, cookies, payload and response.

**Expected:** One HTTP exchange and the session state that produced it.

**If blocked:** Reload with DevTools open and check filters; use Burp Repeater for controlled changes or Sources for client-side code.

**Availability:** Version: Latest · Location: installed in Windows

- Keep challenge files local; Chrome AI assistance is not part of the competition workflow.

[Google Chrome reference](https://developer.chrome.com/docs/devtools/network/)

<a id="approved-kali-23"></a>
### curl · Kali

**Use for:** Reproduce HTTP requests and inspect headers, redirects and cookies.

**First action:** Reproduce one observed HTTP request and inspect status, headers and body before changing a single parameter. Keep redirects visible during baseline comparison.

```sh
curl -i 'https://ASSIGNED_HOST/KNOWN_PATH'
```

**Expected:** An exchange comparable with the browser/Burp request.

**If blocked:** Check quoting, cookies and content type if behavior differs; follow a redirect only after inspecting its destination.

**Availability:** Version: 8.21.0

- Quoting differs between shells; redirects and stale cookies can change results.

[Related helper](TEMPLATES.html#http)

[curl reference](https://curl.se/docs/manpage.html)

<a id="approved-kali-35"></a>
### Exploit-DB / searchsploit (offline archive) · Kali

**Use for:** Match an identified product/version to offline vulnerability references.

**First action:** Search the offline Exploit-DB archive using the identified product and version; read candidate code and prerequisites before selecting any procedure.

```sh
searchsploit 'PRODUCT VERSION'
```

**Expected:** A relevant reference with a specific version/configuration condition to verify.

**If blocked:** A title match is not applicability; inspect service evidence and avoid running unrelated proof-of-concept code.

**Availability:** Version: 2026-08-19 · Version is the archive date

- Archive date is not software version; a matching title is not proof of exploit applicability.

[Exploit-DB / searchsploit (offline archive) reference](https://www.exploit-db.com/searchsploit)

<a id="approved-kali-39"></a>
### Feroxbuster · Kali

**Use for:** Discover nested web paths when recursive traversal is useful.

**First action:** Establish an assigned-host baseline and nonexistent-path response, then use Feroxbuster with a small wordlist, bounded depth/rate and a short run.

**Expected:** Candidate nested paths that differ from wildcard responses and can be opened manually.

**If blocked:** Stop recursion if hits are repetitive; check local limit options or use the reviewed bounded ffuf route instead.

**Availability:** Version: 2.13.1

- Overlaps ffuf and Gobuster; use one discovery tool first and bound recursion/rate.

[Feroxbuster reference](https://github.com/epi052/feroxbuster)

<a id="approved-kali-41"></a>
### ffuf · Kali

**Use for:** Compare path, parameter or virtual-host responses using one FUZZ marker.

**First action:** Request a unique nonexistent path first, then fuzz one marker on the assigned host with a short list, low rate and time limit; verify interesting hits manually.

```sh
ffuf -w ./PATHS.txt -u 'https://ASSIGNED_HOST/FUZZ' -rate 10 -t 1 -maxtime 60 -ac
```

**Expected:** Responses distinguishable from the baseline by content, status or size.

**If blocked:** Wildcard/calibration behavior can hide or invent hits; compare candidates with negative controls and narrow the list.

**Availability:** Version: 2.1.0-dev

- Inventory is a development build; calibrate wildcard responses before trusting hits.

[ffuf reference](https://github.com/ffuf/ffuf)

<a id="approved-kali-54"></a>
### Gobuster · Kali

**Use for:** Discover directories or virtual hosts with explicit separate modes.

**First action:** Choose Gobuster's directory or virtual-host mode from the observed need, establish a nonexistent-name baseline and use a short focused list against the assigned host.

**Expected:** Candidate paths or hosts that differ from the baseline.

**If blocked:** Modes and wildcard handling differ; verify candidates manually or use the existing bounded ffuf route instead of parallel broad scans.

**Availability:** Version: 3.8.2

- Alternative to ffuf; DNS enumeration is active and is not passive OSINT.

[Gobuster reference](https://github.com/OJ/gobuster)

<a id="approved-kali-65"></a>
### Hydra · Kali

**Use for:** Test challenge login candidates when protocol and failure condition are understood.

**First action:** Identify the assigned login protocol and manually confirm one known failure response; configure a small candidate set and conservative concurrency for that exact service.

**Expected:** A reported credential candidate that succeeds in an independent normal login.

**If blocked:** Lockouts, throttling and incorrect failure matching can create false results; stop and fix the signal before expanding the attempt.

**Availability:** Version: (not captured) · Installed; version not captured

- Version uncaptured; throttling, lockout and incorrect failure matching can invalidate results.

[Hydra reference](https://github.com/vanhauser-thc/thc-hydra)

<a id="approved-kali-77"></a>
### jwt_tool · Kali

**Use for:** Inspect JWT claims and choose a test matching the token algorithm and trust model.

**First action:** Decode the token with jwt_tool to inspect header and claims; select any modification only from the algorithm and trust model actually observed.

```sh
python3 /PATH/TO/JWT_TOOL/jwt_tool.py 'CHALLENGE_JWT'
```

**Expected:** Token fields and a controlled comparison of original, modified and missing-token requests.

**If blocked:** Decoding is not signature verification; check actual protected content and session behavior before calling a modification accepted.

**Availability:** Version: (not captured) · Location: /opt/tools/jwt_tool (/usr/local/bin/jwt_tool)

- Version unknown; token decoding alone does not establish signature validity.

[jwt_tool wiki](https://github.com/ticarpi/jwt_tool/wiki) · [JWT attacks](https://portswigger.net/web-security/jwt)

<a id="approved-kali-78"></a>
### Katana · Kali

**Use for:** Extract linked and JavaScript-discovered routes before wordlist discovery.

**First action:** Crawl the assigned web root with explicit scope and a small depth; inspect linked and JavaScript-discovered routes before wordlist discovery.

**Expected:** Routes linked to source pages/scripts, including potentially unlinked application endpoints.

**If blocked:** Refresh authentication if necessary and check scope; a crawler can miss runtime-only or inaccessible routes, so use manual DevTools evidence next.

**Availability:** Version: (not captured) · Location: go install (github.com/projectdiscovery/katana/cmd/katana@latest)

- Version unknown; scope and depth matter and authenticated crawling needs current session state.

[Katana reference](https://docs.projectdiscovery.io/opensource/katana/usage)

<a id="approved-kali-103"></a>
### PayloadsAllTheThings (offline copy) · Kali

**Use for:** Look up syntax and prerequisites for a specific suspected web vulnerability.

**First action:** Open the local PayloadsAllTheThings section for the suspected vulnerability and compare its prerequisites with a captured request before selecting one test.

**Expected:** A single input change and negative control support or reject the hypothesis.

**If blocked:** Syntax examples may depend on a different parser/version; adapt from actual errors and do not treat linked tools as automatically approved.

**Availability:** Version: (not captured) · Location: git (/opt/tools/PayloadsAllTheThings)

- Offline copy age unknown; linked tools are not automatically event-approved.

[PayloadsAllTheThings (offline copy) reference](https://github.com/swisskyrepo/PayloadsAllTheThings)

<a id="approved-kali-126"></a>
### SecLists · Kali

**Use for:** Select a short task-specific content-discovery list.

**First action:** Locate the installed SecLists data directory and select a short list suited to paths, usernames or the specific content-discovery task.

**Expected:** A deliberate wordlist path and scope for the chosen tool.

**If blocked:** The workbook's executable-like location is not proof of the data directory; inspect installed files and avoid using the largest list by default.

**Availability:** Version: (not captured) · Location: /usr/bin/seclists

- Workbook executable-like location is not proof of wordlist directory; locate installed data first.

[SecLists reference](https://github.com/danielmiessler/SecLists)

<a id="approved-kali-132"></a>
### sqlmap · Kali

**Use for:** Test a suspected injection point using a captured, reproducible HTTP request.

**First action:** Save a reproducible captured HTTP request and identify the suspected parameter; run the low-risk single-thread sqlmap check against that parameter only.

```sh
sqlmap -r ./REQUEST.txt -p PARAMETER --batch --level=1 --risk=1 --threads=1
```

**Expected:** Injection evidence tied to a specific input and reproducible response distinction.

**If blocked:** Refresh authentication and verify baseline/negative controls; do not raise risk or enumerate data to compensate for an unstable request.

**Availability:** Version: 1.10.8 (stable)

- Preserve authentication and identify the intended parameter; higher risk/level adds requests and effects.

[sqlmap reference](https://github.com/sqlmapproject/sqlmap/wiki/Usage)

<a id="reversing"></a>
## Reverse Engineering

1. Identify native, .NET, Android, Java, JavaScript or Python bytecode and its architecture/version before choosing a decompiler.
2. Find an input prompt or success/failure string and follow references to the validation routine. Use Ghidra for native code, dnSpyEx for .NET or JADX for APK/DEX.
3. Trace input parsing, transformations and comparison; record widths, signedness, byte order and character encoding.
4. Check reconstructed logic against assembly, IL, smali or bytecode. Use a debugger at a known location when runtime values are the missing evidence.
5. Test a candidate through the original checker, including a near-miss input, before claiming the recovered condition is sufficient.
6. If an executable has UPX evidence but stock unpacking fails, inspect section names and loader structure before considering a repair. Work on a copy, record the exact byte diff, require upx -t success and validate the unpacked format; do not apply a generic section rename to unrelated packers.

**Look for:** A faithful input condition or transformation and a candidate validated against the actual checker.

**If blocked:** Strip packaging first when appropriate; unsupported decompiler output needs a lower-level view. Use angr only after locating the check and modeling its environment, with concrete validation afterward.

**Start with:** [file (libmagic) (Kali)](#approved-kali-42) · [Ghidra (Windows / WSL)](#approved-windows-22) · [gdb (Windows / WSL)](#approved-windows-9) · [objdump (Windows / WSL)](#approved-windows-10) · [x64dbg (Windows)](#approved-windows-33) · [dnSpyEx (dnSpy) (Windows)](#approved-windows-38) · [jadx (jadx-gui) (Kali)](#approved-kali-72) · [Apktool (Kali)](#approved-kali-8) · [pycdc (Decompyle++) (Kali)](#approved-kali-110) · [angr (Kali)](#approved-kali-6) · [pwndbg (Kali)](#approved-kali-109) · [checksec (Kali)](#approved-kali-21)

[Benign checker practice](research/learning/practice/README.html)

[Binary parser template](TEMPLATES.html#binary)

[Transport and packing blocks](TEMPLATES.html#transport)

<a id="approved-windows-9"></a>
### gdb · Windows / WSL · Trend Micro proposal

**Use for:** Stop at the input check; inspect registers, memory and the comparison.

**First action:** Open a compatible ELF in GDB, set a breakpoint at the statically located check, then run a known input in an isolated challenge environment and inspect operands.

```sh
gdb ./CHALLENGE_ELF
```

**Expected:** Registers or compared memory explain the validation branch.

**If blocked:** For stripped code, use a disassembly address and account for runtime loading; use x64dbg for Windows PE debugging.

**Availability:** Version: Latest (distro package) · Location: installed in WSL

- Windows-list entry runs in WSL; this is not a Windows PE debugger.

[Related helper](research/learning/practice/README.html)

[gdb — primary documentation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints.html)

<a id="approved-windows-22"></a>
### Ghidra · Windows / WSL · Trend Micro proposal

**Use for:** Import binary, analyze, follow string cross-references and rename the validation routine.

**First action:** Import into Ghidra with the correct architecture, analyze, find a prompt/success string and follow references to the check; compare decompiler and assembly.

**Expected:** A located validation routine with a documented transformation or comparison.

**If blocked:** Correct types only with evidence; check ambiguous decompilation instruction by instruction or in a debugger.

**Availability:** Version: 12.1.4 · Location: installed in WSL

- Workbook places Ghidra in WSL; decompiler output needs checking against assembly.

[Related helper](research/learning/practice/README.html)

[Ghidra — primary documentation](https://github.com/NationalSecurityAgency/ghidra) · [Ghidra beginner student guide](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html)

<a id="approved-windows-27"></a>
### llvm-mc (LLVM tools) · Windows / WSL · Trend Micro proposal

**Use for:** Translate a short instruction sequence between assembly and bytes.

**First action:** Match a target triple and instruction mode; use llvm-mc's encoding display on a short assembly sequence to check exact bytes.

```sh
llvm-mc -triple=x86_64-pc-linux-gnu -show-encoding ./SAMPLE.s
```

**Expected:** Instruction bytes for the selected architecture.

**If blocked:** Check syntax dialect and target support; this component is not a full linker or emulator.

**Availability:** Version: Latest · Location: installed in WSL

- Select the correct target triple and instruction mode.

[llvm-mc (LLVM tools) — primary documentation](https://llvm.org/docs/CommandGuide/llvm-mc.html)

**Check:** Local LLVM 16.0.6 assembled authored x86-64 nop/ret to bytes 90 c3; objdump of the generated object independently showed both instructions. Other targets and shellcode extraction were not tested.

<a id="approved-windows-10"></a>
### objdump · Windows / WSL · Trend Micro proposal

**Use for:** Inspect headers and disassemble a native checker before opening a GUI.

**First action:** Read executable headers and sections before disassembling the selected native-code region. Match syntax and architecture to the file.

```sh
objdump -f -h ./CHALLENGE_ELF
```

**Expected:** Section addresses and instructions around the relevant function.

**If blocked:** Import into Ghidra for control-flow navigation and compare its decompiler with assembly.

**Availability:** Version: Bundled with GNU Binutils · Location: installed in WSL

- Choose the target architecture and syntax; disassembly does not reconstruct source.

[objdump — primary documentation](https://sourceware.org/binutils/docs/binutils/objdump.html)

<a id="approved-kali-1"></a>
### .NET SDK · Kali

**Use for:** Build and run managed projects

**First action:** Run the SDK inventory, then build the supplied managed project using its declared target framework and already available dependencies.

```sh
dotnet --info
```

**Expected:** The installed SDK/runtime compatibility is known and the project builds with meaningful diagnostics.

**If blocked:** Missing targeting packs or NuGet packages can block offline builds; inspect the assembly with dnSpyEx when building is unnecessary.

**Availability:** Version: 6.0.400

[.NET SDK — Build and run managed projects](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet)

<a id="approved-kali-5"></a>
### Android Studio · Kali

**Use for:** Inspect APK contents and debug a compatible pre-built app when static inspection stalls.

**First action:** Use Android Studio's APK inspection/debug workflow on the supplied APK; identify package, resources and native libraries before starting a compatible emulator/device.

**Expected:** Package structure and, for a debuggable app, breakpoints in the relevant code.

**If blocked:** A non-debuggable APK or missing device setup blocks that route; use JADX and Apktool for static inspection.

**Availability:** Version: - · No installation information recorded

- Installation not recorded; debugging requires a debuggable APK and compatible device setup.

[Android Studio — primary documentation](https://developer.android.com/studio/debug/apk-debugger)

<a id="approved-kali-6"></a>
### angr · Kali

**Use for:** Model a small checker with symbolic input and explicit success/failure targets.

**First action:** Locate success/failure addresses in the checker first. Adapt an angr example with bounded symbolic input and explicit state/environment assumptions, then seek the success state.

**Expected:** A concrete candidate input from a satisfiable state that can be checked against the original checker.

**If blocked:** If exploration explodes or APIs are unmodeled, narrow the function/input constraints; use GDB to verify assumptions rather than trusting a symbolic result.

**Availability:** Version: (not captured) · Location: pipx (angr)

- State explosion and inaccurate environment models can dominate time; first locate the check manually.

[angr — primary documentation](https://docs.angr.io/en/latest/core-concepts/pathgroups.html) · [angr worked examples](https://docs.angr.io/en/latest/examples.html)

<a id="approved-kali-8"></a>
### Apktool · Kali

**Use for:** Decode Android manifest, resources and smali into a fresh output directory.

**First action:** Decode the APK into a new directory, then inspect AndroidManifest.xml, resources and the smali for the method found in JADX.

```sh
apktool d ./APP.apk -o ./NEW_APK_DIR
```

**Expected:** Manifest settings and bytecode-level behavior that can resolve decompiler ambiguity.

**If blocked:** Check the installed 2.x options and malformed resources; avoid force-overwriting an existing analysis directory.

**Availability:** Version: 2.7.0-dirty

- Approved 2.7.0 differs from default 3.x docs; even 2.x docs include later options. Avoid force-delete flags.

[Apktool — primary documentation](https://apktool.org/docs/2.x/cli-parameters/)

<a id="approved-kali-9"></a>
### asar (@electron/asar) · Kali

**Use for:** List and extract app.asar, then inspect JavaScript entry points.

**First action:** List app.asar members, extract into a fresh directory and inspect package.json plus its JavaScript entry point.

```sh
asar list ./app.asar
asar extract ./app.asar ./NEW_ASAR_DIR
```

**Expected:** Application source/assets available for static reading.

**If blocked:** Missing files may live in an adjacent unpacked directory; ASAR packaging itself is not encryption.

**Availability:** Version: 4.3.1

- An ASAR is a container, not encryption; retain original files and use a new output directory.

[Related helper](research/learning/video-coverage/practice/TRIAGE_PRACTICE.html)

[asar (@electron/asar) — primary documentation](https://github.com/electron/asar)

<a id="approved-kali-12"></a>
### BinDiff · Kali

**Use for:** Compare two binary versions to find changed functions worth reversing.

**First action:** Prepare compatible analysis exports for two binary versions and compare them in BinDiff; inspect low-similarity or unmatched functions first.

**Expected:** Candidate changed functions with similarity and graph context.

**If blocked:** Confirm architecture and export compatibility; compare functions manually in Ghidra when the installed exporter is unavailable.

**Availability:** Version: 8 · Build @568181968 (Sep 25 2023)

- Requires compatible exported analysis; do not assume an unapproved commercial disassembler is available.

[BinDiff — primary documentation](https://www.zynamics.com/bindiff/manual/)

<a id="approved-kali-16"></a>
### Bytecode Viewer · Kali

**Use for:** Inspect a JAR using multiple decompiler views when one view is misleading.

**First action:** Open the JAR/class in Bytecode Viewer, find the input check and compare decompiler views when the source looks inconsistent.

**Expected:** A readable candidate method plus bytecode supporting its branches and constants.

**If blocked:** Decompilers can disagree or fail on obfuscation; inspect bytecode and use Fernflower as another view.

**Availability:** Version: 2.13.2 · Location: Fat Jar

- Decompiler disagreement requires checking bytecode; Java runtime needed.

[Bytecode Viewer — primary documentation](https://github.com/Konloch/bytecode-viewer)

<a id="approved-kali-21"></a>
### checksec · Kali

**Use for:** Read ELF protection properties before analyzing a crash or native target.

**First action:** Run the installed Bash-era checksec against the ELF and record architecture-related protection properties before analyzing a crash.

```sh
checksec --file=./CHALLENGE_ELF
```

**Expected:** PIE, NX, canary and RELRO information relevant to runtime address and overwrite assumptions.

**If blocked:** Confirm local help: newer Go checksec syntax differs; protection metadata does not establish a reachable vulnerability.

**Availability:** Version: 2.6.0

- Workbook pins Bash 2.6.0; current Go CLI syntax differs.

[checksec 2.6.0: Bash command-line options](https://raw.githubusercontent.com/slimm609/checksec/2.6.0/checksec)

<a id="approved-kali-24"></a>
### Cutter · Kali

**Use for:** Use a graph and string references to locate the checker as a GUI alternative.

**First action:** Open the binary in Cutter, verify architecture and analysis settings, then follow strings/references into the check's graph and disassembly.

**Expected:** A navigable function graph and candidate input condition.

**If blocked:** If the AppImage cannot launch, check its GUI/FUSE requirement or use Ghidra; Cutter's Rizin backend is not radare2 CLI compatibility.

**Availability:** Version: (not captured) · Location: AppImage (/opt/tools/cutter.AppImage) · The GUI needs FUSE

- AppImage needs FUSE per workbook; Cutter uses Rizin, not current radare2 command compatibility.

[Cutter — primary documentation](https://github.com/rizinorg/cutter)

<a id="approved-kali-28"></a>
### dex2jar · Kali

**Use for:** Convert DEX to JAR when a Java decompiler provides a useful second view.

**First action:** If direct JADX output is incomplete, convert the relevant DEX/APK with the installed dex2jar launcher into a new JAR and inspect it in a Java decompiler.

**Expected:** An alternative Java view of the input check.

**If blocked:** Conversion can lose information or reject malformed code; return to Apktool smali for the decisive instructions.

**Availability:** Version: 2.1-nightly-28

- Prefer direct JADX inspection first; conversion can lose information or fail on malformed bytecode.

[dex2jar — primary documentation](https://github.com/pxb1988/dex2jar)

<a id="approved-windows-38"></a>
### dnSpyEx (dnSpy) · Windows

**Use for:** Open a managed assembly, find the validation method and inspect its C# and IL.

**First action:** Open the .NET assembly, locate entry point or prompt references and inspect the validation method; compare C# reconstruction with IL.

**Expected:** A managed method and its input transformation or expected value.

**If blocked:** Native code needs a native disassembler; resolve uncertain conditions/types from IL.

**Availability:** Version: Latest · Location: installed in Windows · Portable zip. Use dnSpy-net-win64.zip (self-contained; no .NET installation needed).

- For .NET assemblies, not a general native decompiler.

[dnSpyEx (dnSpy) — primary documentation](https://github.com/dnSpyEx/dnSpy)

<a id="approved-kali-33"></a>
### Eclipse Temurin JDK (OpenJDK) · Kali

**Use for:** Provide the Java runtime needed by approved Java analysis tools.

**First action:** Inspect the Java runtime version and compare it with the approved Java analysis tool's requirements before launching its JAR.

```sh
java -version
```

**Expected:** A compatible runtime or a specific version mismatch.

**If blocked:** Select an already installed compatible JDK; Java availability alone does not prove a GUI display or tool dependencies are ready.

**Availability:** Version: 25.0.4 (2026-07-21) · Reported as 'openjdk'

- Utility dependency, not its own challenge-solving workflow; match required JDK version.

[Eclipse Temurin JDK (OpenJDK) — primary documentation](https://adoptium.net/temurin)

<a id="approved-kali-38"></a>
### Fernflower · Kali

**Use for:** Decompile a Java class or JAR to inspect a validation method.

**First action:** Run the installed Fernflower JAR on a copied class/JAR with a fresh destination directory, then inspect the validation method.

**Expected:** Reconstructed Java source suitable for tracing input and constants.

**If blocked:** Inspect bytecode or another approved decompiler where reconstruction is incomplete; preserve the original JAR.

**Availability:** Version: (not captured) · Location: /opt/tools/fernflower/build/libs/fernflower.jar (/usr/local/bin/fernflower)

- Source reconstruction can be inaccurate; compare bytecode or another approved decompiler.

[Fernflower — primary documentation](https://github.com/JetBrains/fernflower/blob/master/README.md)

<a id="approved-kali-46"></a>
### Frida · Kali

**Use for:** Observe native or Java method arguments at runtime after locating the relevant method.

**First action:** Locate the relevant native/Java method statically, then use Frida in the isolated compatible runtime to observe arguments or returns for known inputs.

**Expected:** Runtime values that confirm or reject a specific validation hypothesis.

**If blocked:** Check matching client/server versions and Frida 17 bridge packaging; if attach fails, continue with static code or a debugger.

**Availability:** Version: 17.23.3

- Approved Frida 17 changes bridge packaging; older Android examples require adaptation and device access.

[Frida — primary documentation](https://frida.re/docs/javascript-api/) · [Frida Android CTF example](https://frida.re/docs/examples/android/)

<a id="approved-kali-47"></a>
### GCC, G++ and build tools (build-essential, make, CMake, pkg-config) · Kali

**Use for:** Build small local programs with debug information

**First action:** Compile a reviewed small C/C++ source with debug information and low optimization before using a debugger to test a specific behavior.

```sh
gcc -g -O0 ./REVIEWED_SOURCE.c -o ./NEW_PROGRAM
```

**Expected:** A reproducible local binary whose source lines and variables are inspectable.

**If blocked:** Read existing build files before running them; missing libraries or architecture mismatch require matching the project toolchain, not stripping checks.

**Availability:** Version: 15.3.0 · Debian gcc 15.3.0-2

- Workbook: Debian gcc 15.3.0-2

[Related helper](research/learning/practice/README.html)

[GCC, G++ and build tools (build-essential, make, CMake, pkg-config) — Build small local programs with debug information](https://gcc.gnu.org/onlinedocs/gcc/Debugging-Options.html)

<a id="approved-kali-48"></a>
### GEF (GDB Enhanced Features) · Kali

**Use for:** Inspect registers, stack and memory with the existing GDB enhancement.

**First action:** Start GDB with the existing GEF configuration only, stop at a known check and inspect its register/stack/context display.

**Expected:** Execution state tied to the breakpoint and input.

**If blocked:** If startup fails, use plain GDB or one other frontend; do not load GEF, PEDA and pwndbg together.

**Availability:** Version: (not captured) · Location: /opt/tools/gef.py · Load with: gdb -x /opt/tools/gef.py. Not auto-sourced, to avoid a clash with peda

- Choose one GDB frontend; do not load GEF, PEDA and pwndbg together.

[GEF (GDB Enhanced Features) — primary documentation](https://hugsy.github.io/gef/)

<a id="approved-kali-55"></a>
### GoReSym · Kali

**Use for:** Recover function names and metadata from a stripped Go binary.

**First action:** Run the installed GoReSym workflow on a stripped Go binary and inspect recovered function names, source metadata and addresses.

**Expected:** Go runtime metadata that makes functions easier to locate in Ghidra.

**If blocked:** A newer/modified Go layout may be unsupported; verify reported addresses against the binary before importing or renaming.

**Availability:** Version: (not captured) · Location: go install (github.com/mandiant/GoReSym@latest)

- Recovery depends on supported Go metadata; recovered names still need mapping into the analysis tool.

[GoReSym — primary documentation](https://github.com/mandiant/GoReSym)

<a id="approved-kali-69"></a>
### innoextract · Kali

**Use for:** List and extract an Inno Setup installer without running its payload.

**First action:** List the Inno Setup installer's files without executing it, then extract relevant content into a fresh directory.

```sh
innoextract --list ./INSTALLER.exe
```

**Expected:** Installer members available for static inspection.

**If blocked:** Unsupported installer revisions or a different wrapper require format re-identification; do not run the installer to identify its payload.

**Availability:** Version: dev build

- Only supported Inno Setup formats; extract into a fresh directory.

[innoextract — primary documentation](https://constexpr.org/innoextract/)

<a id="approved-kali-72"></a>
### jadx (jadx-gui) · Kali

**Use for:** Open APK/DEX, search strings and follow usages to the input-validation method.

**First action:** Open APK/DEX in jadx-gui, inspect manifest entry points and search for the prompt or success text; follow usages to the validation method.

**Expected:** Java-like logic that connects input to its comparison.

**If blocked:** A failed or suspicious decompilation needs Apktool smali or another bytecode view; reconstructed code is not authoritative.

**Availability:** Version: 1.5.6

- JADX warns it cannot decompile every method correctly; use smali for ambiguous code.

[jadx (jadx-gui) — primary documentation](https://github.com/skylot/jadx)

<a id="approved-kali-75"></a>
### js-beautify · Kali

**Use for:** Format a JavaScript payload before following variables and control flow.

**First action:** Pretty-print the JavaScript locally into a new file, then trace names, constants and branches around input handling without executing it.

```sh
js-beautify ./SCRIPT.js > ./NEW_FORMATTED.js
```

**Expected:** Readable formatting with the original semantics still available for comparison.

**If blocked:** Beautifying does not resolve string arrays or control-flow obfuscation; use a matching deobfuscator only when the pattern fits.

**Availability:** Version: 2.0.3

- Formatting does not undo semantic obfuscation; use the local CLI.

[js-beautify — primary documentation](https://github.com/beautifier/js-beautify)

<a id="approved-kali-76"></a>
### js-deobfuscator · Kali

**Use for:** Simplify JavaScript string arrays and proxy functions for static reading.

**First action:** Confirm the installed package is ben-sb's js-deobfuscator; use its documented local workflow on a copy to simplify supported string arrays/proxy functions.

**Expected:** A transformed script whose relevant expressions are easier to follow.

**If blocked:** Compare transformed code with the original; unsupported patterns or semantic changes require manual analysis, not blind execution.

**Availability:** Version: (not captured) · Location: npm (js-deobfuscator)

- Pinned identity is ben-sb npm js-deobfuscator; review transformed output and retain original.

[js-deobfuscator — primary documentation](https://github.com/ben-sb/javascript-deobfuscator)

<a id="approved-kali-83"></a>
### ltrace · Kali

**Use for:** Observe dynamically linked library calls around a password comparison.

**First action:** In an isolated environment, trace a trusted challenge binary's library calls with a known input and look for comparisons or transformed buffers.

```sh
ltrace ./CHALLENGE_ELF
```

**Expected:** Dynamic library-call arguments that explain the input check.

**If blocked:** Static/inlined code may produce no relevant calls; use GDB breakpoints or Ghidra rather than treating absence as no comparison.

**Availability:** Version: 0.7.91

- Static linking and inlined functions can hide calls; execution is required.

[ltrace — primary documentation](https://ltrace.org/)

<a id="approved-kali-93"></a>
### NASM (Netwide Assembler) · Kali

**Use for:** Check x86 assembly syntax or assemble a minimal local experiment.

**First action:** Match x86 bitness and desired output format, then assemble a small reviewed experiment with NASM to check its instruction encoding.

**Expected:** Bytes/object code for the exact chosen instruction mode.

**If blocked:** Raw binary, ELF and PE objects are not interchangeable; inspect output with objdump or xxd before using it.

**Availability:** Version: 3.01

- Assembler reference only; match 16/32/64-bit mode and output format.

[NASM (Netwide Assembler) — primary documentation](https://www.nasm.us/docs.html)

<a id="approved-kali-96"></a>
### obfuscator-io-deobfuscator · Kali

**Use for:** Recover readable strings and control flow from recognized Obfuscator.io output.

**First action:** Confirm the script resembles supported Obfuscator.io output; run the installed local deobfuscator on a copy and inspect recovered strings/control flow.

**Expected:** Readable candidate expressions that can be compared with the original.

**If blocked:** Unsupported transforms need manual analysis or js-beautify; do not upload challenge code to the advertised service.

**Availability:** Version: 1.0.6

- Use local CLI, not the advertised upload service; not a universal JavaScript deobfuscator.

[obfuscator-io-deobfuscator — primary documentation](https://github.com/ben-sb/obfuscator-io-deobfuscator)

<a id="approved-kali-99"></a>
### OllyDbg · Kali

**Use for:** Trace a legacy 32-bit Windows checker using its existing debugger.

**First action:** For a legacy 32-bit Windows checker, open it in the existing OllyDbg setup and break at the identified check before testing a known input.

**Expected:** Registers and memory show the comparison and branch.

**If blocked:** The recorded Wine build may not run reliably; use x32dbg where available or continue static inspection.

**Availability:** Version: 1.10-1kali5 · Location: Wine (Windows binary)

- Workbook has 1.10 under Wine; use native x64dbg route where practical.

[OllyDbg — primary documentation](https://www.ollydbg.de/quickst.htm)

<a id="approved-kali-104"></a>
### peda · Kali

**Use for:** Use the preconfigured PEDA context view for a native debugging session.

**First action:** Use the preconfigured PEDA session in GDB, stop at the known check and inspect its register, stack and disassembly context.

**Expected:** State at the breakpoint explains how a known input is handled.

**If blocked:** If plugin initialization conflicts, use plain GDB or one frontend; do not stack PEDA with GEF/pwndbg.

**Availability:** Version: (not captured) · Location: /opt/tools/peda (sourced in ~/.gdbinit)

- Already sourced in .gdbinit per workbook; avoid stacking debugger plugins.

[peda — primary documentation](https://github.com/longld/peda)

<a id="approved-kali-109"></a>
### pwndbg · Kali

**Use for:** Inspect native execution state and memory using pwndbg commands.

**First action:** Start the existing pwndbg configuration alone, stop at a known input-check location and inspect registers, stack and pointed-to memory.

**Expected:** Runtime operands tied to the supplied input and instruction.

**If blocked:** Resolve debugger/plugin compatibility or fall back to plain GDB; do not combine competing .gdbinit frontends.

**Availability:** Version: (not captured) · Location: /opt/tools/pwndbg · setup.sh completed

- Do not combine with PEDA or GEF initialization; installed version is not recorded.

[pwndbg — primary documentation](https://pwndbg.re/stable/commands/)

<a id="approved-kali-110"></a>
### pycdc (Decompyle++) · Kali

**Use for:** Try Python bytecode decompilation; fall back to pycdas disassembly on unsupported constructs.

**First action:** Identify the PYC version and try pycdc; compare incomplete or questionable reconstruction with pycdas disassembly.

```sh
pycdc ./MODULE.pyc
pycdas ./MODULE.pyc
```

**Expected:** Candidate Python logic supported by bytecode instructions.

**If blocked:** Unsupported opcodes can make output partial or wrong; select another decompiler only if it supports that bytecode version.

**Availability:** Version: (not captured) · Version not captured (no --version option)

- Support depends on bytecode version and opcode; partial output is not guaranteed correct.

[pycdc (Decompyle++) — primary documentation](https://github.com/zrax/pycdc)

<a id="approved-kali-111"></a>
### pyinstxtractor-ng · Kali

**Use for:** Extract a PyInstaller bundle, identify its Python bytecode version, then choose a decompiler.

**First action:** Extract a copied PyInstaller bundle with pyinstxtractor-ng, record the reported Python version and identify the application PYC among bundled dependencies.

```sh
pyinstxtractor-ng ./BUNDLE.exe
```

**Expected:** Bytecode and resources available for static inspection.

**If blocked:** Extraction is not decompilation; use a version-compatible decompiler and inspect the wrapper if the bundle format is unsupported.

**Availability:** Version: (not captured) · Location: pipx (pyinstxtractor-ng)

- Extraction is not decompilation; preserve the bundle and inspect extracted files without running them.

[Related helper](research/learning/video-coverage/practice/TRIAGE_PRACTICE.html)

[pyinstxtractor-ng — primary documentation](https://github.com/pyinstxtractor/pyinstxtractor-ng)

<a id="approved-kali-116"></a>
### radare2 · Kali

**Use for:** Analyze functions, list strings and disassemble a chosen routine from the terminal.

**First action:** Open the binary in radare2, inspect information/strings and analyze only enough functions to locate the input check; disassemble that routine.

```sh
r2 ./CHALLENGE_ELF
```

**Expected:** Function addresses and references explain the comparison.

**If blocked:** Broad analysis can be costly or misleading; use targeted navigation or Ghidra, and do not assume Cutter/Rizin commands are identical.

**Availability:** Version: 6.0.5

- Use targeted analysis on large files; commands differ from Rizin/Cutter.

[radare2 — primary documentation](https://book.rada.re/analysis/intro.html)

<a id="approved-kali-121"></a>
### ROPgadget · Kali

**Use for:** Find and inspect a small set of instruction gadgets for a native binary task.

**First action:** Search the copied native binary for the small gadget class required by an already identified exploitation primitive; inspect candidate instructions in disassembly.

```sh
ROPgadget --binary ./CHALLENGE_ELF --only 'pop|ret'
```

**Expected:** Usable instruction sequences with file-relative/runtime-address assumptions recorded.

**If blocked:** A gadget address needs the correct load base and safe side effects; its existence alone does not establish an exploit.

**Availability:** Version: 7.7

- Addresses depend on binary and load base; finding a gadget is not a validated exploit.

[ROPgadget — primary documentation](https://github.com/JonathanSalwan/ROPgadget)

<a id="approved-kali-138"></a>
### strace · Kali

**Use for:** Trace file access and system calls to explain missing inputs or hidden file dependencies.

**First action:** In an isolated environment, trace the challenge binary's relevant file/process syscalls with a known input and save the trace separately.

```sh
strace -f -o ./NEW_TRACE.txt ./CHALLENGE_ELF
```

**Expected:** Paths, failures or child-process activity explain missing inputs or hidden dependencies.

**If blocked:** Linux execution is required; for static triage or incompatible binaries, inspect strings/disassembly instead.

**Availability:** Version: 7.0

- Linux execution required; trace child processes explicitly when relevant.

[strace — primary documentation](https://strace.io/)

<a id="approved-kali-145"></a>
### uncompyle6 · Kali

**Use for:** Decompile a supported older Python PYC after checking its bytecode version.

**First action:** Identify the PYC bytecode version before using uncompyle6 and compare important conditions with disassembly.

```sh
uncompyle6 ./MODULE.pyc
```

**Expected:** Reconstructed older Python source supported by the bytecode.

**If blocked:** Its documented support reaches Python 3.8 bytecode; running it under a newer interpreter does not add newer opcode support.

**Availability:** Version: 3.9.3

- README supports bytecode through 3.8; a newer host Python does not imply newer bytecode support.

[uncompyle6 — primary documentation](https://github.com/rocky/python-uncompyle6)

<a id="approved-kali-146"></a>
### unpyc3 (unpyc37-3.10) · Kali

**Use for:** Try the approved alternate Python decompiler when its supported bytecode matches.

**First action:** Match the supplied PYC to unpyc37-3.10's documented version coverage, then use its installed entry point for an alternate decompilation view.

**Expected:** Partial or complete candidate source with version limits explicitly recorded.

**If blocked:** Support declines across 3.7–3.10; use pycdas or another version-compatible view rather than trusting incomplete output.

**Availability:** Version: (not captured) · Location: git (/opt/tools/unpyc3)

- README states good 3.7, decent 3.8, mostly complete 3.9 and minimal 3.10 support.

[unpyc3 (unpyc37-3.10) — primary documentation](https://github.com/greyblue9/unpyc37-3.10)

<a id="approved-kali-149"></a>
### UPX · Kali

**Use for:** Test a suspected UPX file and unpack a copy before normal static analysis.

**First action:** Test a suspected UPX executable, then unpack to a new file and identify/analyze that output statically.

```sh
upx -t ./SAMPLE.exe
upx -d -o ./NEW_UNPACKED.exe ./SAMPLE.exe
```

**Expected:** A recognized packed file and a separate unpacked executable.

**If blocked:** Modified packers can defeat normal unpacking; inspect code/sections rather than claiming every UPX-like file is handled.

**Availability:** Version: 4.2.4

- Modified packers may fail; development docs may differ from approved 4.2.4.

[Related helper](research/learning/video-coverage/practice/TRIAGE_PRACTICE.html)

[UPX — primary documentation](https://github.com/upx/upx/blob/devel/doc/upx-doc.txt)

<a id="approved-kali-155"></a>
### VS Code extension: C/C++ (ms-vscode.cpptools) · Kali

**Use for:** Configure C/C++ source debugging

**First action:** Select the built C/C++ executable and matching GDB/debug symbols in VS Code's C/C++ debug configuration, then stop at a known source line in a reviewed local program.

**Expected:** Source breakpoints correspond to actual instructions and variables.

**If blocked:** Rebuild with debug information and check working directory/architecture; use standalone GDB if editor integration obscures the failure.

**Availability:** Version: (not captured) · Location: VS Code extension (ms-vscode.cpptools)

[VS Code extension: C/C++ (ms-vscode.cpptools) — Configure C/C++ source debugging](https://code.visualstudio.com/docs/cpp/cpp-debug)

<a id="approved-windows-33"></a>
### x64dbg · Windows

**Use for:** Set a Windows input-check breakpoint and inspect the compared buffers.

**First action:** Open the copied checker in x64dbg, or x32dbg for 32-bit code, in an isolated environment; break at the statically located input check and submit a known input.

**Expected:** Buffers, registers and branch decisions explain the comparison.

**If blocked:** Locate the module entry point if stopped in loader code; use Ghidra while resolving runtime dependencies.

**Availability:** Version: Latest · Location: installed in Windows · Portable zip (snapshot_*.zip). Extract and run; no installer.

- Use x32dbg for 32-bit targets; dynamic execution needs an isolated challenge environment.

[x64dbg — primary documentation](https://help.x64dbg.com/en/latest/gui/tips.html) · [x64dbg conditional breakpoints](https://help.x64dbg.com/en/latest/introduction/ConditionalBreakpoint.html)

<a id="osint"></a>
## OSINT

1. Separate supplied evidence from public-source facts. Extract image/document metadata with ExifTool or pdftotext and record explicit time zones and contradictory tags.
2. Choose a distinctive public phrase, visible landmark or named entity; search in Chrome and open the underlying source instead of relying on a snippet.
3. Record source URL, author/date where available and exactly what the source supports. Distinguish an event date from publication or capture time.
4. Corroborate the decisive claim with an independent source. For a public-domain task, Subfinder can suggest names with source provenance; verify those names in their cited sources.
5. Keep private challenge artifacts local; use visible/public clues rather than uploading the original to an unrelated hosted analyzer.
6. If GPS is absent, compare visible signs, road geometry and buildings with public photographs and maps. Prefer a corroborated camera viewpoint over a business/map pin; check conflicting coordinate fields and preserve signs when rounding to the requested precision. Public event sites may require the year-specific archive.

**Look for:** A supported identity/location/time claim with sources and unresolved contradictions clearly separated.

**If blocked:** Metadata can be absent or forged and public indexes stale. Narrow by independent visual/text clues; lack of search results does not establish absence.

**Start with:** [Google Chrome (Windows)](#approved-windows-5) · [ExifTool (Windows / WSL)](#approved-windows-14) · [pdftotext (Poppler utils) (Windows / WSL)](#approved-windows-15) · [Subfinder (Kali)](#approved-kali-139) · [GNU Wget (Kali)](#approved-kali-52) · [curl (Kali)](#approved-kali-23) · [ZBar (Windows / WSL)](#approved-windows-19) · [Obsidian (Kali)](#approved-kali-97)

[Metadata and format inspection](TOOLKIT.html#inspect)

[Source and learning references](LEARNING_RESOURCES.html)

<a id="approved-kali-139"></a>
### Subfinder · Kali

**Use for:** Collect publicly indexed subdomains for a challenge-supplied public domain.

**First action:** Query a challenge-supplied public domain with Subfinder while retaining source provenance, then corroborate candidate names in their cited public sources.

```sh
subfinder -d PUBLIC_DOMAIN -oJ -cs -o ./NEW_HOSTS.jsonl
```

**Expected:** Hostname candidates with source information and observation time.

**If blocked:** Public indexes can be stale and private domains may have no entries; absence is not evidence that no host exists.

**Availability:** Version: 2.16.0

- Sources may require API keys or return stale records; private challenge domains may have no public results.

[Subfinder usage](https://docs.projectdiscovery.io/opensource/subfinder/usage)

<a id="crypto"></a>
## Cryptography

1. Write down the exact provided values, encodings and construction. Distinguish reversible encoding, a password hash, symmetric ciphertext and a mathematical public-key problem.
2. Encoding: apply one justified CyberChef operation and inspect bytes after each layer. Use known-key XOR or binary conversion only when key/bit order comes from evidence.
3. Hashes: use hashid -m as a candidate shortlist, then match source format, salts and full syntax with Hashcat example hashes before selecting a mode and bounded wordlist attempt.
4. RSA/group problems: test the specific weakness with RsaCtfTool, SageMath, PARI/GP or a matching crypto-attacks implementation; verify every prerequisite.
5. Verify results independently: factors multiply to n, plaintext re-encrypts to c, or a recovered password actually opens the original artifact.
6. Hash shape only yields candidate algorithms: use hashcat --identify or hashid -m, then confirm the mode from the producing application or known pairs. Check candidate length coverage before interpreting Exhausted. For RFID or framed bits, separate byte conversion, demodulation, field extraction and parity checks; a readable field with failed parity is not a valid protocol frame.

**Look for:** A result that satisfies the original cryptographic relation or successfully validates against the supplied artifact.

**If blocked:** Do not treat readable output or a hash-length guess as proof. Recheck encoding, padding, modulus/group order, salts and KDF parameters before widening searches; use local math instead of external value submission.

**Start with:** [CyberChef (Windows)](#approved-windows-1) · [Python 3 (Windows / WSL)](#approved-windows-7) · [OpenSSL (Windows / WSL)](#approved-windows-24) · [RsaCtfTool (Windows / WSL)](#approved-windows-30) · [hashcat (Kali)](#approved-kali-59) · [hashid (Kali)](#approved-kali-60) · [John the Ripper (jumbo) (Kali)](#approved-kali-73) · [bkcrack (Kali)](#approved-kali-13) · [crypto-attacks (Kali)](#approved-kali-22) · [PARI/GP (Kali)](#approved-kali-102) · [SageMath (Kali)](#approved-kali-125) · [rockyou.txt (Kali 'wordlists' package) (Kali)](#approved-kali-120)

[Hashcat modes, bounded runs and recovery](HASHCAT.html)

[Binary text conversion](TOOLKIT.html#bits)

[Known-key XOR](TOOLKIT.html#xor)

[Structured binary parsing](TEMPLATES.html#binary)

<a id="approved-windows-1"></a>
### CyberChef · Windows · Trend Micro proposal

**Use for:** Decode layered encodings and inspect byte transformations.

**First action:** Load bytes into local CyberChef; apply one justified operation such as From Hex or From Base64, inspect output, then add another layer only if the result supports it.

**Expected:** Reproducible bytes and a saved recipe whose output structure can be checked.

**If blocked:** Undo a contradictory layer; Magic supplies hypotheses, so validate with the matching file parser.

**Availability:** Version: Latest (browser-based, no install) · Location: Bookmark

- Magic proposes candidates; verify bytes and file structure. Use a local/offline copy for challenge data and never share input-bearing recipe URLs.

[Related helper](TOOLKIT.html#bits)

[CyberChef — Build a decoding recipe](https://github.com/gchq/CyberChef) · [CyberChef Magic: detection methods](https://github.com/gchq/CyberChef/wiki/Automatic-detection-of-encoded-data-using-CyberChef-Magic)

<a id="approved-windows-24"></a>
### OpenSSL · Windows / WSL · Trend Micro proposal

**Use for:** Decrypt symmetric ciphertext when cipher and key derivation are known.

**First action:** Establish cipher, mode, key/IV representation and password derivation before decrypting. For a PEM public key, inspect its parameters to select a crypto route.

```sh
openssl pkey -pubin -in ./PUBLIC_KEY.pem -text -noout
```

**Expected:** Known encryption settings or readable public-key parameters.

**If blocked:** A Salted__ prefix does not identify all settings; recover the producer's cipher, digest and KDF rather than guessing.

**Availability:** Version: Latest 3.x · Location: installed in WSL

- Match cipher, salt, digest, IV and PBKDF2 settings; enc does not provide a universal encrypted-file detector. Windows-list entry runs in WSL.

[OpenSSL — Understand symmetric decryption parameters](https://docs.openssl.org/3.0/man1/openssl-enc/)

**Check:** Local OpenSSL 3.0.13 round-tripped authored AES-256-CBC/PBKDF2 bytes and rejected a wrong password. CBC authenticity and unknown settings were not established.

<a id="approved-windows-30"></a>
### RsaCtfTool · Windows / WSL · Trend Micro proposal

**Use for:** Recover weak textbook RSA keys or decrypt given ciphertext.

**First action:** Inspect RSA n and e, select a local attack matching a demonstrated weakness, then verify recovered factors or plaintext mathematically.

```sh
RsaCtfTool --dumpkey --key ./PUBLIC_KEY.pem
```

**Expected:** Factors satisfy p*q == n; a plaintext integer satisfies pow(m,e,n) == c.

**If blocked:** Check installed flags/dependencies; avoid indiscriminate attacks or external integer submission.

**Availability:** Version: Latest (GitHub script, run via Python 3) · Location: installed in WSL

- Current upstream flags may differ from installed version. Some attacks call external services; select local attacks and verify dependencies first. Windows-list entry runs in WSL.

[RsaCtfTool — Study RSA attack prerequisites](https://github.com/RsaCtfTool/RsaCtfTool)

<a id="approved-kali-3"></a>
### aircrack-ng · Kali

**Use for:** Test a supplied wireless handshake capture against a candidate wordlist offline.

**First action:** Inspect the supplied wireless capture for a suitable handshake and target network; run an offline candidate-wordlist test only against that recorded evidence.

**Expected:** A supported handshake and, if a candidate matches, a password validated against it.

**If blocked:** Missing handshake messages, wrong network selection or the wrong security mode need better evidence, not more guesses.

**Availability:** Version: 1.7

- Requires suitable handshake evidence; hardware capture and deauthentication are outside this candidate.

[aircrack-ng reference](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)

<a id="approved-kali-13"></a>
### bkcrack · Kali

**Use for:** Recover ZipCrypto internal keys from known plaintext.

**First action:** List ZIP entries and encryption, then establish at least 12 known plaintext bytes with 8 contiguous bytes matching the encrypted compressed stream before using bkcrack's tutorial workflow.

**Expected:** ZipCrypto internal-key candidates that decrypt a member into valid bytes.

**If blocked:** ZIP AES is outside this attack; compression differences or an incorrect plaintext offset invalidate known-plaintext assumptions.

**Availability:** Version: 1.8.1 (2025-10-25)

- Requires ZipCrypto, at least 12 known plaintext bytes with 8 contiguous; known bytes must match the encrypted compressed stream. Not ZIP AES.

[bkcrack — Understand ZIP known-plaintext recovery](https://github.com/kimci86/bkcrack) · [bkcrack worked example](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)

<a id="approved-kali-22"></a>
### crypto-attacks · Kali

**Use for:** Use mathematical implementations after identifying a concrete crypto weakness.

**First action:** Identify a concrete mathematical weakness, select the matching crypto-attacks implementation and read its test vector and prerequisites before substituting challenge values.

**Expected:** A candidate solution satisfying the original equations or encryption relation.

**If blocked:** Check Sage/Python requirements and input assumptions; repository presence does not imply every attack runs or fits the problem.

**Availability:** Version: (not captured) · Location: git (/opt/tools/crypto-attacks)

- Requires compatible Sage/Python and attack-specific inputs; repository presence alone does not make each attack runnable.

[crypto-attacks — Find mathematical attack implementations](https://github.com/jvdsn/crypto-attacks)

<a id="approved-kali-36"></a>
### factordb-python · Kali

**Use for:** Understand how known integer factors are looked up.

**First action:** Inspect the factordb-python API using its public example integers only; determine whether a result contains complete prime factors and verify their product locally.

**Expected:** A known public example demonstrates the query/result model without disclosing challenge values.

**If blocked:** Use local SageMath/PARI factorization for challenge integers unless external submission is explicitly allowed; network lookup is not local computation.

**Availability:** Version: (not captured) · Location: pip (factordb-python)

- Sends submitted integers to an external service. Keep reference-only for public examples; do not send challenge-derived values without explicit event permission.

[factordb-python — Look up known integer factors](https://github.com/ryosan-470/factordb-python)

<a id="approved-kali-59"></a>
### hashcat · Kali

**Use for:** Recover passwords offline from a correctly identified hash format.

**First action:** Match the full hash syntax and source format to Hashcat's example hashes; choose the numeric mode, check the backend, then run one bounded dictionary attempt.

```sh
hashcat -m MODE ./HASHES.txt ./WORDLIST.txt --runtime 60
hashcat -m MODE ./HASHES.txt --show
```

**Expected:** A recovered candidate shown by --show and validated against the original artifact.

**If blocked:** Use hashid only for candidate modes; ambiguous formats, missing salts and backend errors must be resolved before increasing guesses.

**Availability:** Version: 7.1.2

- Confirm installed supported mode and compute backend; use example hashes to diagnose format errors before spending time on attacks.

[Related helper](HASHCAT.html)

[hashcat — Match hash formats and choose a recovery mode](https://hashcat.net/wiki/doku.php?id=example_hashes)

<a id="approved-kali-60"></a>
### hashid · Kali

**Use for:** Generate candidate hash algorithms from encoded hash syntax.

**First action:** Ask hashid for candidate hash types and Hashcat mode numbers, then compare full syntax, length, salt and source context with Hashcat example hashes.

```sh
hashid -m ./HASHES.txt
```

**Expected:** A shortlist of plausible algorithms/modes, not a deterministic identification.

**If blocked:** Equal-length hashes can map to many algorithms; use the producing application's format or a known test value to distinguish them.

**Availability:** Version: 3.1.4

- Identification is heuristic: equal-length hashes are ambiguous. Corroborate with source format and upstream hash examples.

[Related helper](HASHCAT.html)

[hashid — Suggest possible hash formats](https://github.com/psypanda/hashID)

<a id="approved-kali-62"></a>
### hcxtools · Kali

**Use for:** Convert supplied wireless authentication evidence into offline cracking input.

**First action:** Inspect the supplied wireless capture, then use the installed hcxtools converter to produce the authentication format required by the chosen offline cracking mode.

**Expected:** Converted records with capture-quality warnings that guide a valid offline attempt.

**If blocked:** Incomplete handshakes or unsupported capture types need different evidence; preserve the PCAP and avoid online upload helpers.

**Availability:** Version: 7.1.2 · Version of hcxpcapngtool

- Do not use bundled online upload helpers with challenge files; preserve original capture.

[hcxtools reference](https://github.com/ZerBea/hcxtools)

<a id="approved-kali-64"></a>
### hlextend · Kali

**Use for:** Study secret-prefix hash length extension.

**First action:** Read the hlextend example and confirm a secret-prefix hash construction, supported digest, known message/tag and plausible secret-length range before adapting it locally.

**Expected:** An extended message/tag candidate whose exact padding bytes are accepted by the vulnerable verifier.

**If blocked:** HMAC is not vulnerable to this construction; wrong secret length or changed transport encoding invalidates the candidate.

**Availability:** Version: (not captured) · Location: Python module (/usr/local/lib/python3.14/dist-packages/hlextend.py)

- Needs a vulnerable secret-prefix construction, compatible hash and known/guessed secret length; not HMAC. Preserve padding bytes through transport encoding.

[hlextend — Explore hash length extension with generic examples](https://github.com/stephenbradshaw/hlextend)

<a id="approved-kali-73"></a>
### John the Ripper (jumbo) · Kali

**Use for:** Recover passwords offline using supported jumbo formats.

**First action:** Convert the supplied archive/document into John's matching hash representation with the installed jumbo converter, then run a short dictionary attempt and show results.

```sh
john --wordlist=./WORDLIST.txt --max-run-time=60 ./EXTRACTED_HASHES.txt
john --show ./EXTRACTED_HASHES.txt
```

**Expected:** A password candidate tied to the correct extracted hash format.

**If blocked:** Check converter availability and format names; a generic hash guess cannot replace archive-specific extraction.

**Availability:** Version: 1.9.0-Jumbo-1

- Jumbo converter availability and format names depend on installed build; extract the correct hash before selecting wordlists.

[John the Ripper jumbo command-line options](https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/doc/OPTIONS)

<a id="approved-kali-101"></a>
### padding-oracle-attacker · Kali

**Use for:** Study CBC padding-oracle behavior in an authorized web challenge.

**First action:** Confirm a stable valid/invalid padding distinction with a baseline and negative control on the assigned CBC endpoint; match block size and transport encoding before using the attacker.

**Expected:** Oracle responses are reproducible enough for a candidate plaintext/decryption result to be checked.

**If blocked:** Rate limits, generic errors or inconsistent responses invalidate the oracle; resolve the signal before spending requests.

**Availability:** Version: (not captured) · Version not captured (the command printed a banner only)

- Requires a stable padding-error signal, correct block size and encoding; request volume can be large. No live target validation performed. Workbook: Version not captured (the command printed a banner only)

[padding-oracle-attacker — Understand the tool's padding oracle input and response options](https://github.com/KishanBagaria/padding-oracle-attacker)

<a id="approved-kali-102"></a>
### PARI/GP · Kali

**Use for:** Perform integer factorization and modular arithmetic.

**First action:** In GP, use a small known integer to confirm factorization and modular-arithmetic conventions, then apply the operation justified by the challenge.

```sh
gp
```

**Expected:** Factors or modular results that satisfy the original equation.

**If blocked:** Large inputs may be infeasible; use structural clues rather than assuming generic factorization is cheap.

**Availability:** Version: 2.17.4

- Upstream arithmetic manual timed out in this pass; baseline reference retained without fresh verification.

[PARI/GP — Explore modular arithmetic and discrete logarithms](https://pari.math.u-bordeaux.fr/dochtml/html-stable/Arithmetic_functions.html)

<a id="approved-kali-120"></a>
### rockyou.txt (Kali 'wordlists' package) · Kali

**Use for:** Supply the approved local dictionary to offline password tools.

**First action:** Locate the installed rockyou wordlist and check whether it is compressed; make a separate decompressed copy if needed and pass its real path to one offline cracking attempt.

**Expected:** A readable local candidate dictionary used by the selected cracking tool.

**If blocked:** A wordlist is not a cracking engine and may omit the answer; use challenge clues to narrow candidates rather than repeatedly rerunning it.

**Availability:** Version: (not captured) · Location: /usr/share/wordlists/rockyou.txt

- A wordlist is not a cracking engine; verify whether the local file is compressed and avoid modifying the shared installed copy.

[Related helper](HASHCAT.html)

[rockyou.txt (Kali 'wordlists' package) — Locate the approved password dictionary](https://www.kali.org/tools/wordlists/)

<a id="approved-kali-125"></a>
### SageMath · Kali

**Use for:** Solve supported finite-group logarithms and mathematical crypto subproblems.

**First action:** Confirm SageMath availability, reproduce a small known finite-field/group example, then formulate the exact modular equation or discrete-log problem from challenge parameters.

**Expected:** A candidate solution verified by substitution or exponentiation in the original group.

**If blocked:** Missing installation or a large hard group blocks the method; use structural weaknesses and check group order rather than assuming arbitrary logs are easy.

**Availability:** Version: - · No installation information recorded

- Workbook records no installation information. Feasibility depends on group order and parameters; documentation examples do not imply arbitrary logs are easy. Workbook: No installation information recorded

[SageMath — Explore discrete logarithms; workbook records no installation information](https://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html)

<a id="misc"></a>
## Miscellaneous

1. Identify the input type with file and inspect archive members with 7-Zip before extracting into a new directory.
2. Use existing tools for focused data work: ripgrep for text, jq for JSON, xxd for bytes and the matching decompressor for a known stream.
3. For an assigned service, inspect the specified port/banner with Nmap/Ncat and perform one manual protocol exchange; record exact delimiters, lengths and encoding.
4. If repeated interaction is necessary, adapt the existing transport or timed-arithmetic template to the observed protocol and success condition.
5. Check the real interpreter/environment and run a known sample plus an incomplete/invalid-input case before relying on an adapted helper.
6. For rapid question services, reuse one connection, parse only the expected question grammar, send one correctly formatted answer, and wait for the completion signal. Test split/coalesced packets and total deadlines locally. For five-bit text, preserve incomplete trailing groups and letter/figure shift state rather than silently dropping data.

**Look for:** A correctly identified payload or repeatable protocol exchange with explicit parsing and completion rules.

**If blocked:** Wrong format, missing runtime/dependency or a different wire protocol requires a targeted adjustment. Use the approved tool directly when a helper's scope does not cover the task.

**Start with:** [file (libmagic) (Kali)](#approved-kali-42) · [7-Zip (7z) (Kali)](#approved-kali-2) · [ripgrep (rg) (Kali)](#approved-kali-119) · [jq (Windows / WSL)](#approved-windows-21) · [xxd (Windows / WSL)](#approved-windows-28) · [Nmap (with Ncat / Nping) (Kali)](#approved-kali-94) · [socat (Kali)](#approved-kali-127) · [Python 3 (Windows / WSL)](#approved-windows-7) · [uv (Windows / WSL)](#approved-windows-8) · [Windows Subsystem for Linux (WSL) (Windows)](#approved-windows-6) · [Python 3.11 (via uv) (Kali)](#approved-kali-114)

[Existing byte and inspection toolkit](TOOLKIT.html)

[Protocol templates](TEMPLATES.html#transport)

[Timed arithmetic client](TEMPLATES.html#timed-math)

[Binary parsing](TEMPLATES.html#binary)

<a id="approved-windows-16"></a>
### can-utils · Windows / WSL · Trend Micro proposal

**Use for:** Inspect CAN IDs and payload changes in supplied logs or challenge interfaces.

**First action:** Group a supplied CAN log by arbitration ID and compare timing and payload changes. For an assigned SocketCAN interface, observe frames with candump first.

```sh
candump CAN_INTERFACE
```

**Expected:** Message IDs and changing bytes associated with the event.

**If blocked:** Check interface availability and log format; WSL does not imply SocketCAN hardware support.

**Availability:** Version: Latest · Location: installed in WSL

- Windows approval row installs in WSL; SocketCAN interface support must be checked.

[can-utils reference](https://github.com/linux-can/can-utils)

<a id="approved-windows-17"></a>
### cannelloni · Windows / WSL · Trend Micro proposal

**Use for:** Connect a challenge-provided CAN-over-Ethernet endpoint to SocketCAN.

**First action:** Confirm the installed cannelloni fork, transport and local interface; map organiser-provided remote address/ports to its local help before starting the tunnel.

**Expected:** Frames appear on the intended SocketCAN interface for candump inspection.

**If blocked:** Check interface state and matching peer settings; upstream documentation does not establish workbook-fork compatibility.

**Availability:** Version: Latest · Location: installed in WSL

- Workbook names mkschreder fork; linked mguentner upstream is not proof of installed fork compatibility.

[cannelloni reference](https://github.com/mguentner/cannelloni)

<a id="approved-windows-21"></a>
### jq · Windows / WSL · Trend Micro proposal

**Use for:** Filter JSON

**First action:** Parse JSON, inspect its object/array structure, then select the actual field; use raw string output only when needed by the next tool.

```sh
jq . ./DATA.json
```

**Expected:** Focused values without manual quote/escape removal.

**If blocked:** Check for JSON Lines, surrounding logs or truncation before blaming the filter.

**Availability:** Version: Latest · Location: installed in WSL

- Windows-list entry runs in WSL.

[jq — Filter JSON](https://jqlang.org/manual/)

**Check:** Local jq 1.7 selected the expected ID from an authored JSON document. JSON Lines were not tested.

<a id="approved-windows-4"></a>
### OpenVPN Client · Windows · Trend Micro proposal

**Use for:** Import the organiser VPN profile and inspect connection status.

**First action:** Import the organiser-provided VPN profile into the installed client; connect and inspect authentication, address and route messages.

**Expected:** A completed connection with routes for the assigned network.

**If blocked:** Check client variant, profile files and clock; connected status alone does not establish application reachability.

**Availability:** Version: Latest · Location: installed in Windows

- Confirm installed OpenVPN client variant; profiles and account details stay private.

[OpenVPN Client reference](https://openvpn.net/connect-docs/import-profile.html)

<a id="approved-windows-7"></a>
### Python 3 · Windows / WSL · Trend Micro proposal

**Use for:** Parse binary data

**First action:** Use Python for a known binary or protocol format; adapt the existing bounded parser or transport template only after inspecting the bytes.

```sh
python3 --version
```

**Expected:** Known input produces expected fields with explicit byte order and incomplete-input handling.

**If blocked:** Use an approved format parser first, or CyberChef for a simple transform, before writing new code.

**Availability:** Version: Latest 3.x — confirm exact version before install · Location: installed in WSL · Libraries may be added freely EXCEPT any AI/ML-related library (e.g. no LLM, machine-learning, or generative-AI frameworks).

- Workbook: Libraries may be added freely EXCEPT any AI/ML-related library (e.g. no LLM, machine-learning, or generative-AI frameworks). Windows-list entry runs in WSL.

[Related helper](TEMPLATES.html)

[Python 3 — Parse binary data](https://docs.python.org/3/library/struct.html)

<a id="approved-windows-8"></a>
### uv · Windows / WSL · Trend Micro proposal

**Use for:** Manage Python environments

**First action:** Check the script's Python requirement; use uv to select that interpreter and a separate environment with already available, permitted dependencies.

```sh
uv --version
```

**Expected:** The environment's interpreter and imports match the script.

**If blocked:** If offline packages are missing, use a prepared environment or standard-library route; uv does not guarantee offline installation.

**Availability:** Version: Latest · Location: installed in WSL · Same rule as Python 3 — any library OK except AI/ML-related packages

- Workbook: Same rule as Python 3 — any library OK except AI/ML-related packages Windows-list entry runs in WSL.

[Related helper](TEMPLATES.html)

[uv — Manage Python environments](https://docs.astral.sh/uv/pip/environments/)

<a id="approved-windows-6"></a>
### Windows Subsystem for Linux (WSL) · Windows · Trend Micro proposal

**Use for:** Use the installed Linux environment

**First action:** List WSL distributions from Windows, then enter the distribution containing the approved Linux tools and check its Linux paths.

```sh
wsl --list --verbose
```

**Expected:** The intended distribution can access the copied evidence.

**If blocked:** Check distribution and PATH if a tool is missing; native Windows tools are not automatically installed in WSL.

**Availability:** Version: Latest · Location: installed in Windows

[Related helper](TOOLKIT.html#setup)

[Windows Subsystem for Linux (WSL) — Use the installed Linux environment](https://learn.microsoft.com/en-us/windows/wsl/basic-commands)

<a id="approved-kali-31"></a>
### Docker Engine and Compose plugin · Kali

**Use for:** Run and inspect a local container lab

**First action:** Inspect an existing approved Compose project's services, status and logs before starting or changing its local lab.

```sh
docker compose ps
```

**Expected:** The relevant service, port mapping and failure log are identified.

**If blocked:** Missing images or dependencies can prevent offline startup; use the supplied artifact route when a container lab is unnecessary.

**Availability:** Version: 28.5.2+dfsg4

[Docker Engine and Compose plugin — Run and inspect a local container lab](https://docs.docker.com/compose/)

<a id="approved-kali-52"></a>
### GNU Wget · Kali

**Use for:** Save public files for local analysis

**First action:** Download an explicitly identified public file to a new local name, then verify its type and expected size before analysis.

```sh
wget -O ./NEW_PUBLIC_ARTIFACT 'https://PUBLIC_HOST/PUBLIC_FILE'
```

**Expected:** A local copy of the intended public artifact.

**If blocked:** An HTML error/login page is not the requested file; inspect response behavior and use the source's direct download link.

**Availability:** Version: 1.25.0

[GNU Wget — Save public files for local analysis](https://www.gnu.org/software/wget/manual/wget.html)

<a id="approved-kali-53"></a>
### Go · Kali

**Use for:** Build or run local Go utilities

**First action:** Check the installed Go version and a reviewed local project's module requirements; build using already available dependencies.

```sh
go version
```

**Expected:** A compiled utility matching the required Go toolchain.

**If blocked:** Missing modules can block offline work; use an existing binary or equivalent approved tool instead of assuming dependency fetching will succeed.

**Availability:** Version: 1.26.5

[Go — Build or run local Go utilities](https://go.dev/doc/cmd)

<a id="approved-kali-56"></a>
### GTFOBins (offline copy) · Kali

**Use for:** Look up behavior of an already identified Unix binary.

**First action:** Search the offline GTFOBins entry for a binary already present in the challenge and match its documented execution context to the observed permissions.

**Expected:** A narrowly applicable behavior and its prerequisites.

**If blocked:** A shell, SUID or sudo recipe is not interchangeable; if permissions differ, discard it rather than assuming the binary name is sufficient.

**Availability:** Version: (not captured) · Location: git (/opt/tools/GTFOBins.github.io)

- Reference collection may mention unapproved programs; its inclusion does not approve those tools or justify indiscriminate execution.

[GTFOBins (offline copy) — Interpret permitted binary functions in a CTF lab](https://gtfobins.org/)

<a id="approved-kali-58"></a>
### HackTricks (offline copy) · Kali

**Use for:** Find a technique reference after challenge triage.

**First action:** Search the offline HackTricks copy for the confirmed format, service or vulnerability primitive, then read the relevant prerequisites and examples.

**Expected:** A focused procedure that can be mapped to approved tools and observed evidence.

**If blocked:** Skip unrelated branches and unapproved dependencies; broad reference coverage does not prove a technique fits the target.

**Availability:** Version: (not captured) · Location: git (/opt/tools/hacktricks)

- Broad collection contains tools outside the approved list; keep a fallback reference, not the default route or an approval source.

[HackTricks (offline copy) — Find a technique checklist for a lab task](https://github.com/HackTricks-wiki/hacktricks)

<a id="approved-kali-68"></a>
### Impacket · Kali

**Use for:** Use SMB protocol examples to inspect a challenge share with supplied access.

**First action:** Choose Impacket's SMB client example for a supplied share and supplied access; use its local help to select the wrapper, then list only relevant shares/files.

**Expected:** An accessible path or file that answers the challenge question.

**If blocked:** Confirm protocol, domain and credentials before trying another example; Impacket's broad collection is not a reason to run unrelated credential-extraction tools.

**Availability:** Version: 0.14.0

- Example names and wrappers vary by distribution; broad credential extraction is not the default route.

[Impacket reference](https://github.com/fortra/impacket) · [Impacket SMB client example](https://github.com/fortra/impacket/blob/master/examples/smbclient.py)

<a id="approved-kali-71"></a>
### IPython · Kali

**Use for:** Explore Python objects and run small scripts

**First action:** Use IPython to inspect already loaded data types, lengths and representations, then run a small known transform with an explicit expected result.

**Expected:** Interactive values reveal encoding or parser assumptions without a full new script.

**If blocked:** Avoid executing unknown pasted code; move a confirmed repeatable transform into the existing parser template when needed.

**Availability:** Version: 9.17.1

[IPython — Explore Python objects and run small scripts](https://ipython.readthedocs.io/en/stable/interactive/tutorial.html)

<a id="approved-kali-79"></a>
### legion · Kali

**Use for:** Organize network reconnaissance visually when several services need tracking.

**First action:** Add only the assigned host(s) to Legion and inspect discovered ports/services in its GUI, using existing scan evidence when available.

**Expected:** A service inventory that can be checked with a focused tool.

**If blocked:** If GUI/helper dependencies fail, use Nmap directly; do not repeat broad scans merely to populate a dashboard.

**Availability:** Version: 0.7.0

- Overlaps direct Nmap; GUI and helper dependencies may be unavailable.

[legion reference](https://github.com/Abacus-Group-RTO/legion)

<a id="approved-kali-81"></a>
### LibreOffice · Kali

**Use for:** Convert documents to inspectable formats

**First action:** Open a copied benign document with macros disabled or use LibreOffice's documented conversion mode to a new output directory for page/text inspection.

**Expected:** A readable rendering that can be compared with the original container.

**If blocked:** Rendering can omit hidden objects or alter formatting; use oletools/qpdf for embedded content instead of enabling macros.

**Availability:** Version: 26.8.0.3

[LibreOffice — Convert documents to inspectable formats](https://help.libreoffice.org/latest/en-US/text/shared/guide/start_parameters.html)

<a id="approved-kali-88"></a>
### Metasploit Framework · Kali

**Use for:** Inspect module descriptions and requirements for an already identified service.

**First action:** Search Metasploit for the identified service/product, then read a candidate module's info, options and prerequisites before considering a targeted check.

**Expected:** An applicability hypothesis with explicit version, configuration and input requirements.

**If blocked:** Module availability is not target validation; return to observed service evidence if prerequisites are missing.

**Availability:** Version: 6.5.2-dev

- Development build; module availability is not evidence of target applicability.

[Running modules](https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html)

<a id="approved-kali-90"></a>
### Miniforge3 (conda) · Kali

**Use for:** Create a separate dependency environment

**First action:** Inspect existing conda environments and the required interpreter/library versions; select a prepared environment or create an isolated one from available permitted packages.

```sh
conda env list
```

**Expected:** The analysis script uses a known environment without changing unrelated dependencies.

**If blocked:** Offline caches may be incomplete; use a compatible existing environment or standard-library route.

**Availability:** Version: (not captured) · Location: /home/kali/miniforge3

[Miniforge3 (conda) — Create a separate dependency environment](https://github.com/conda-forge/miniforge)

<a id="approved-kali-94"></a>
### Nmap (with Ncat / Nping) · Kali

**Use for:** Identify services with Nmap; use Ncat for protocol interaction and Nping for connectivity diagnostics.

**First action:** Probe only the assigned host/port for service information, then use Ncat for one protocol-appropriate exchange; use TLS mode only when the service specifies it.

```sh
nmap -sV -p PORT ASSIGNED_HOST
ncat ASSIGNED_HOST PORT
```

**Expected:** A banner or response establishes the actual protocol and prompt.

**If blocked:** Service detection can be uncertain; compare raw behavior and supplied instructions before automating. Nping serves packet diagnostics, not application parsing.

**Availability:** Version: 7.99

- Three bundled tools have different purposes; start from the challenge host and explicit ports.

[Related helper](TEMPLATES.html#transport)

[Nmap Reference Guide](https://nmap.org/book/man.html) · [Ncat basic usage](https://nmap.org/ncat/guide/ncat-usage.html) · [Nping packet generation](https://nmap.org/nping/)

<a id="approved-kali-95"></a>
### Node.js (with npm) · Kali

**Use for:** Convert binary representations in JavaScript

**First action:** Use Node's Buffer API for a known byte representation and verify both decoded bytes and round-trip encoding before adapting a JavaScript helper.

```sh
node --version
```

**Expected:** Explicit binary/text conversion without accidental Unicode assumptions.

**If blocked:** Buffer decoding may accept malformed input differently from a strict parser; validate the source alphabet and length first.

**Availability:** Version: 24.21.0

[Node.js (with npm) — Convert binary representations in JavaScript](https://nodejs.org/docs/latest-v24.x/api/buffer.html)

<a id="approved-windows-37"></a>
### Notepad++ · Windows

**Use for:** Search structured text

**First action:** Choose normal, extended or regex search deliberately in Notepad++; use Find All for a known token and inspect surrounding records.

**Expected:** Matching lines with their file context.

**If blocked:** Use ripgrep for large text or HxD for binary data; do not normalize whitespace-steganography evidence on save.

**Availability:** Version: Latest · Location: installed in Windows · Installer (x64). A portable edition is also available.

- Workbook: Installer (x64). A portable edition is also available.

[Notepad++ — Search structured text](https://github.com/notepad-plus-plus/npp-usermanual/blob/master/content/docs/searching.md)

<a id="approved-kali-97"></a>
### Obsidian · Kali

**Use for:** Organize investigation notes with links

**First action:** Open a local Obsidian vault and keep one note per question with evidence paths, observations and linked hypotheses.

**Expected:** Notes distinguish observed facts, candidate explanations and the next check.

**If blocked:** If plugins or startup fail, use the existing Markdown editor; plain local notes are sufficient and do not require synchronization.

**Availability:** Version: (not captured) · Version not captured; startup reported that ~/.config/obsidian/obsidian.json does not exist

- Workbook: Version not captured; startup reported that ~/.config/obsidian/obsidian.json does not exist

[Obsidian — Organize investigation notes with links](https://help.obsidian.md/links)

<a id="approved-kali-113"></a>
### Python 2.7 · Kali

**Use for:** Read binary records in legacy Python scripts

**First action:** Use Python 2.7 only for a reviewed legacy script; verify byte-string, integer-division and struct assumptions with a known sample before challenge input.

```sh
python2.7 --version
```

**Expected:** The legacy interpreter reproduces the expected parser behavior.

**If blocked:** Port a small understood operation to Python 3 when practical; a Python 2 script's imports may still be missing offline.

**Availability:** Version: 2.7.18

[Python 2.7 — Read binary records in legacy Python scripts](https://docs.python.org/2.7/library/struct.html)

<a id="approved-kali-114"></a>
### Python 3.11 (via uv) · Kali

**Use for:** Select Python 3.11 through uv; workbook records no installation information

**First action:** Check whether uv already has Python 3.11 available and select it for a script that requires that version; confirm the executable actually used.

```sh
uv python find --offline --no-python-downloads 3.11
```

**Expected:** Interpreter output identifies Python 3.11 in the intended environment.

**If blocked:** The workbook has no installation evidence; if unavailable offline, use a compatible prepared interpreter or document the requirement.

**Availability:** Version: - · No installation information recorded

- Workbook: No installation information recorded

[Related helper](TEMPLATES.html)

[Python 3.11 (via uv) — Select Python 3.11 through uv; workbook records no installation information](https://docs.astral.sh/uv/guides/install-python/)

<a id="approved-kali-119"></a>
### ripgrep (rg) · Kali

**Use for:** Search text and selectively include hidden or binary files

**First action:** Search a relevant directory for a literal clue with line numbers; include hidden files only when the evidence warrants it.

```sh
rg -n -F 'KNOWN_NEEDLE' ./EVIDENCE_DIR
```

**Expected:** Matches with paths and line context for focused inspection.

**If blocked:** Ignored/hidden/binary files are normally skipped; deliberately adjust scope rather than assuming no match means absence.

**Availability:** Version: 15.2.0

[Related helper](TEMPLATES.html#file-intel)

[ripgrep (rg) — Search text and selectively include hidden or binary files](https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md)

<a id="approved-kali-123"></a>
### Rust (rustup, rustc, cargo) · Kali

**Use for:** Build and run a Rust analysis utility

**First action:** Inspect the installed Rust toolchain and a reviewed project's Cargo manifest; build using locally available dependencies when a Rust utility is required.

```sh
rustc --version
cargo --version
```

**Expected:** A compiled program matching the required edition/toolchain.

**If blocked:** Missing crates block offline builds; use an existing executable or approved equivalent rather than introducing a new dependency stack.

**Availability:** Version: 1.95.0 (2026-04-14) · Built from a source tarball

- Workbook: Built from a source tarball

[Rust (rustup, rustc, cargo) — Build and run a Rust analysis utility](https://doc.rust-lang.org/book/ch01-03-hello-cargo.html)

<a id="approved-kali-124"></a>
### rustscan · Kali

**Use for:** Discover TCP ports before targeted service identification.

**First action:** Use RustScan only when port discovery is needed for the assigned host; choose conservative batch/timeout settings, then verify selected ports with Nmap service detection.

**Expected:** A small list of reachable TCP ports with independently checked services.

**If blocked:** High concurrency can lose results or overload the environment; use direct Nmap for explicit ports or unclear results.

**Availability:** Version: 2.4.1

- Overlaps Nmap; high batch sizes can lose results or overwhelm the environment.

[RustScan usage](https://github.com/bee-san/RustScan/wiki/Usage)

<a id="approved-kali-127"></a>
### socat · Kali

**Use for:** Connect standard input to a challenge TCP service or bridge required stream types.

**First action:** Connect standard input/output to the assigned plaintext TCP endpoint with socat and send one protocol-appropriate line.

```sh
socat - TCP:ASSIGNED_HOST:PORT
```

**Expected:** A banner or response confirms stream behavior.

**If blocked:** Check address syntax and whether TLS is required; prefer Ncat for a simple interaction rather than adding unnecessary bridges/listeners.

**Availability:** Version: 1.8.1.3

- Address syntax is order-sensitive; unnecessary listeners introduce confusion.

[Related helper](TEMPLATES.html#transport)

[socat reference](https://www.kali.org/tools/socat/)

<a id="approved-kali-140"></a>
### Sublime Text · Kali

**Use for:** Search source and notes in an editor

**First action:** Open the local source/notes directory in Sublime Text and use project search for an identified symbol or clue; inspect surrounding code before editing a copy.

**Expected:** Relevant definitions and call sites with file context.

**If blocked:** Use ripgrep for large trees or unsupported encodings; an editor search does not parse binary formats.

**Availability:** Version: Build 4215

[Sublime Text — Search source and notes in an editor](https://www.sublimetext.com/docs/)

<a id="approved-kali-150"></a>
### Visual Studio Code · Kali

**Use for:** Search and edit analysis code

**First action:** Open the local analysis folder in VS Code with untrusted-workspace restrictions appropriate to unknown code; search the input handling and edit only reviewed scripts.

**Expected:** Definitions, call sites and the intended interpreter/build context are visible.

**If blocked:** Do not accept automatic tasks/extensions from an unknown repository; use plain text search when code execution is unnecessary.

**Availability:** Version: 1.141.2

[Visual Studio Code — Search and edit analysis code](https://code.visualstudio.com/docs/editor/codebasics)

<a id="approved-kali-156"></a>
### VS Code extension: Python (ms-python.python) · Kali

**Use for:** Select a Python interpreter for analysis scripts

**First action:** Select the intended Python environment through the VS Code Python extension and confirm the displayed interpreter matches a terminal version check before debugging a reviewed script.

**Expected:** Imports and breakpoints use the same interpreter as the command-line workflow.

**If blocked:** If imports differ, fix interpreter selection rather than installing duplicates globally; verify extension availability offline.

**Availability:** Version: (not captured) · Location: VS Code extension (ms-python.python)

[VS Code extension: Python (ms-python.python) — Select a Python interpreter for analysis scripts](https://code.visualstudio.com/docs/python/environments)

<a id="approved-kali-159"></a>
### zip · Kali

**Use for:** Package files into ZIP archives

**First action:** Package only the intended harmless files into a new ZIP, then list/test it and compare member names before transferring or keeping it as a fixture.

```sh
zip ./NEW_ARCHIVE.zip ./FILE_ONE.txt ./FILE_TWO.txt
```

**Expected:** An archive with the selected files and unchanged originals.

**If blocked:** Check relative paths and accidental sensitive files; use an existing archive tool rather than a new packaging script.

**Availability:** Version: (not captured) · Installed; version not captured

- Workbook: Installed; version not captured

[zip — Package files into ZIP archives](https://infozip.sourceforge.net/Zip.html)
