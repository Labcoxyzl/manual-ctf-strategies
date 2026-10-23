# Bundled tools and troubleshooting routes

These routes distinguish capabilities hidden inside broad workbook rows. They do not add standalone tools to the approved list. Shell examples target a prepared Linux/Kali practice environment; the organiser's platform distinctions still apply. No account, purchase or remote target is needed for the included checks.

<a id="ncat-and-nping"></a>
## Nmap, Ncat and Nping do different jobs

Keep the existing Nmap port/service/output lesson for discovery. Use the official [Ncat basic guide](https://nmap.org/ncat/guide/ncat-usage.html) for client/listener byte streams. Nping is a conditional packet/probe troubleshooting tool; read the [Nping reference](https://nmap.org/book/nping-man.html), especially TCP Connect Mode, count limits and interpreting sent/received probes.

**Ncat local check:** In one terminal, start `ncat --recv-only --listen 127.0.0.1 19001`. In another, run `printf 'hello from study\n' | ncat --send-only 127.0.0.1 19001`. Choose another unused port if needed. The first terminal should receive exactly the seventeen bytes `hello from study` plus newline, then exit after the connection closes. Explicit loopback binding avoids the guide's all-interface default. This client/listener pattern was tested on an ephemeral local port; [result](ncat-check.json).

For a protocol-aware check, reuse [worksheet 7's local HTTP server](../../../../PRACTICE_WORKSHEETS.md#block-7). Connect with `ncat -C 127.0.0.1 8765`, enter `GET /clue.txt HTTP/1.0`, then a blank line. Expect a 200 response and `CTF-refresher` body. `-C` converts typed line endings to CRLF. This HTTP variation is documented, but was not separately executed in this pass.

**Nping disposition:** Do not repeat a general Nmap scan or run unbounded packet generation. When connection/probe behavior itself matters, select the documented unprivileged TCP-connect mode and a bounded count, such as `nping --tcp-connect -c 1 -p 8765 127.0.0.1` against the prepared local server. Nping was unavailable here and was not installed or run. Raw packet modes can require privileges; echo-mode and header-crafting are specialist branches, not prerequisites for this collection.

**Paper check:** Which tool fits (a) discovering service versions, (b) sending a chosen HTTP request as bytes, and (c) measuring a bounded connection probe? Answer: Nmap, Ncat, Nping. A missing response alone does not distinguish filtering, an absent service, a wrong target or a local setup problem. Keep the raw observation separate from the explanation.

<a id="oletools-suite"></a>
## oletools is more than olevba

The [author's tool index](https://github.com/decalage2/oletools#tools) describes the suite's distinct roles. Keep the existing detailed olevba lesson for VBA analysis, and use the following routes only when the input calls for them.

| Component | Use and learning disposition |
| --- | --- |
| olevba | Existing workflow: extract macros, inspect decoded strings and distinguish indicators from a verdict. |
| oleid | First-pass container characteristics and macro/encryption indicators; a routing aid, not proof of maliciousness. |
| oleobj | Embedded OLE/Office object extraction; use the concrete check below. Its wiki Usage section is a placeholder, so consult the [actual CLI source](https://github.com/decalage2/oletools/blob/master/oletools/oleobj.py) and installed help. |
| rtfobj | RTF-specific parsing and numbered embedded-object extraction, including obfuscated RTF handling. See [documented options and output](https://github.com/decalage2/oletools/wiki/rtfobj). |
| mraptor | Conditional macro-heuristic triage, overlapping part of olevba; inspect the matching macro instead of treating a heuristic result as confirmation. |
| msodde | Conditional detection/extraction of DDE/DDEAUTO links in matching document formats; this is separate from VBA extraction. Inspect links without activating them. |
| olemeta | Standard OLE metadata; values may be edited and do not alone establish authorship. |
| oletimes | Storage/stream timestamps; distinguish these from filesystem times and do not infer execution from them. |
| pyxswf | Specialist embedded Flash/SWF extraction when that format is actually present; no SWF execution or separate long Flash course is required here. |

**Known-answer extraction:** The bundled [embedded-note.ole](embedded-note.ole) and [embedded-note.rtf](embedded-note.rtf) are authored benign containers holding only `note.txt`. They contain no macro or script. From the repository root, use a new output directory:

```sh
ctf_extract_dir="$(mktemp -d)"
python3 -m oletools.oleobj -d "$ctf_extract_dir" research/learning/video-coverage/practice/embedded-note.ole
python3 -m oletools.rtfobj research/learning/video-coverage/practice/embedded-note.rtf
python3 -m oletools.rtfobj -s 0 -d "$ctf_extract_dir" research/learning/video-coverage/practice/embedded-note.rtf
```

The listing step lets you select object zero intentionally. Check the extracted bytes rather than launching an extracted object. Both tools should recover seventeen bytes: `hello from study` followed by newline, SHA-256 `40d59f64bc4faeef20ed99266871b5dbfb27d9ddee2780eac1701472acf79593`. Output names may include the input filename. Both extractions were executed and compared byte-for-byte; [results](bundle-extraction-check.json).

In the tested oleobj 0.60.1 implementation, return value 1 denotes a successful dump; additional bits report errors. Do not discard a successful extraction merely because this tool returned 1, or ignore genuine parsing/dump errors. Verify the report and expected bytes. Version-specific behavior still needs checking on the organiser's machine.

**Paper check:** Given an RTF object table with index 0 marked Package and index 1 another object, choose `rtfobj -s 0 -d NEW_DIR INPUT.rtf` to extract only the first. For an OLE container, choose `oleobj -d NEW_DIR INPUT.ole`; it is not an indexed RTF selector. A parser reporting no objects or macros is not proof that the whole document is safe. These distinctions close the extraction capability gap without requiring nine separate courses.

<a id="volatility-symbols"></a>
## Diagnose Volatility layer and symbol requirements

Use the official [symbol-table guide](https://volatility3.readthedocs.io/en/latest/symbol-tables.html) together with the framework's [actual requirement-error diagnostics](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/cli.html). Read the `process_unsatisfied_exceptions` and `process_exceptions` sections, not the entire source file.

1. **Classify the failure.** A missing translation layer first calls for checking the supplied file, readability and whether it is a supported, cleanly acquired memory image. Downloading random symbols cannot fix an absent or invalid input.
2. **Only then check symbols.** For Windows, match the PDB identity, including GUID and age, and the configured symbol location. The framework may download/convert a matching PDB while online. Linux/macOS need the exact identifying banner and appropriate debug information, not merely a matching marketing/version string.
3. **Check discovery and diagnostics.** Use the installed tool's help to confirm symbol paths and plugin options. In a prepared source checkout, `python3 vol.py -vvv -f memory.raw windows.info` provides local diagnostic detail; `memory.raw` is a placeholder, not a bundled dump. Keep diagnostic output local. The symbol guide describes `isfinfo` and Linux `banners` for comparing available versus required identities.
4. **Correct what the evidence supports.** Fix a bad path, supply the matching symbol table, or perform the needed online preparation before flying. If the image is incomplete, the required debug kernel is unavailable, or an error remains unexplained, retain an unresolved result. Do not rename unrelated symbols to make them appear to match, and do not claim that every failure is recoverable.

**Decision check:** (a) The supplied file does not exist: fix the input path before symbols. (b) The layer resolves but the available Windows table has the wrong GUID/age: obtain the matching table; a similar filename is insufficient. (c) A Linux banner differs only in build/compiler details: it still fails the documented exact-match requirement. (d) A plugin fails before output: this is incomplete analysis, not evidence that an artifact is absent.

The primary documentation and error-handling branches were inspected. No memory image, symbol download or Volatility execution was performed for this route. It teaches troubleshooting decisions and known prerequisite fixes, not a guarantee that a damaged or unsupported image can be analysed.
