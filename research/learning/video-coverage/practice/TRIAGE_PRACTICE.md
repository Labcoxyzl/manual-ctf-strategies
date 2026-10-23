# Bytes, encodings and PDF streams

These two authored inputs give short tools a concrete workflow instead of a separate video course. Run from this directory on copies. No file contains JavaScript, macros or a malicious payload.

## strings and xxd: choose the encoding and verify the offset

Read GNU's [strings options](https://sourceware.org/binutils/docs/binutils/strings.html), especially `-a`, `-n`, `-t` and `-e`. Use [triage.bin](triage.bin):

```sh
strings -a -t x triage.bin
strings -a -e l -t x triage.bin
xxd -s 0x10 -l 16 triage.bin
xxd -s 0x40 -l 38 triage.bin
```

**Task:** Explain why the default scan misses the second message, whether printed offsets are decimal or hexadecimal, and how the bytes confirm the proposed encoding. Increase minimum length with `-n` and predict which messages disappear. A printable URL/path is not evidence that a program used it.

**Answer:** ASCII `route=/clue.txt` starts at hex offset `10`; UTF-16LE `destination=harbor` starts at hex offset `40`. The latter has alternating character and zero bytes. `-e l` selects 16-bit little-endian text, not a decryption algorithm. Both strings commands were executed and the expected offsets checked. The xxd commands are byte-inspection instructions; their GUI equivalent is an approved hex viewer. Paper route: use the given offsets and encoding to predict the bytes before checking the file.

<a id="qpdf-a-rendered-page-is-only-one-view"></a>
## qpdf: a rendered page is only one view

Read the [qpdf inspection options](https://qpdf.readthedocs.io/en/stable/cli.html#pdf-inspection). The benign [stream-demo.pdf](stream-demo.pdf) has one page and a compressed content stream at object 4. With qpdf already installed:

```sh
qpdf stream-demo.pdf --show-pages
qpdf stream-demo.pdf --show-object=4
qpdf stream-demo.pdf --show-object=4 --filtered-stream-data
```

**Task:** Identify the page's content object, distinguish its dictionary from its decoded bytes, and explain why `--raw-stream-data` would differ. Do not combine unrelated inspection modes into the raw-byte output. No output PDF argument is needed for these inspection operations.

**Answer:** The page references object `4 0`; its dictionary names `/FlateDecode`. Decoded bytes are `BT /F1 12 Tf 50 100 Td (CTF refresher) Tj ET` followed by a newline. The page displays `CTF refresher`; raw stream bytes are compressed. Selecting an object is not executing its content, and another PDF may use unsupported filters or a different object layout. This is an inspection exercise, not a promise to detect every malicious PDF.

The PDF structure, displayed text extraction and decompressed stream were checked with the already installed pypdf library; qpdf CLI was unavailable and was not installed. Paper route: choose the correct option for dictionary/raw/decoded output and compare with these known answers. [Recorded checks](triage-pdf-check.json). For a separate worked nested-document investigation with approved Didier Stevens tools, use the collection's Matryoshka lesson; it is not a qpdf demonstration.
