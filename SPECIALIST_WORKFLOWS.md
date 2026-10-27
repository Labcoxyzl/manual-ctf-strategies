# Specialist task workflows

Use these notes with the [task routes](index.html#malware) when the core workflows do not cover the format or question. Keep the original artifact, work on a copy, and record the observation that justifies each next step. The procedures do not rely on AI Overview; external links are optional references. They cover the prepared routes, not every possible challenge.

[Forensics](#wireless-auth) · [Malware](#malware-executable) · [Web](#web-targeted) · [Native and managed reversing](#native-exploit) · [OSINT](#osint-source) · [Crypto](#xor-keystream-reuse)

<a id="wireless-auth"></a>
## Supplied Wi-Fi capture: check evidence before candidates

Inspect the capture for the target network and PMKID or EAPOL exchange. Keep the BSSID/ESSID and message completeness with the source packet numbers. Choose a new, nonexistent output path before `hcxpcapngtool -o NEW_capture.22000 capture.pcapng`: hcxtools can append to existing files. Read converter warnings and confirm the new records match this capture, rather than trusting a nonempty file from an earlier run. Match the output format to mode 22000, then follow the [Hashcat guide](HASHCAT.md) with a local wordlist. Exhausted covers only the candidates tested. If conversion yields no record, revisit capture and converter evidence before drawing any password conclusion.

**Check:** Relate a recovered candidate to the selected network and original capture. This workflow reads supplied files only; it does not require or justify active capture, deauthentication or uploading packets. [hcxtools](https://github.com/ZerBea/hcxtools) · [Hashcat mode 22000](https://hashcat.net/wiki/doku.php?id=example_hashes).

<a id="evtx-timeline"></a>
## Windows EVTX: keep a source-backed timeline

Choose the relevant log channel and event ID from the question. For a PowerShell script-block clue, `chainsaw search -t 'Event.System.EventID: =4104' ./logs` searches a copied EVTX directory. Record the source file, Event ID, record ID, host/account, timestamp and time zone for a hit before relating it to another event. Use rule-based Chainsaw hunting only with a local rule set and matching mapping; Hayabusa is an alternative for timeline-led work, but its command names depend on the installed version.

**Check:** Open the matching source record and explain the time ordering and the fields supporting the claim. An absent log, parser error or rule hit cannot establish absence or malicious intent. [Chainsaw search and hunt](https://github.com/WithSecureOpenSource/chainsaw) · [Hayabusa](https://github.com/Yamato-Security/hayabusa).

<a id="registry-hive"></a>
## Registry hive: keep key, hive and transaction state together

Identify the hive type and preserve its transaction logs with a working copy. In RegRipper, list installed plugins with `rip.pl -l` and select one relevant to the question. Run `rip.pl -r HIVE -p PLUGIN` from the installed tool directory, keeping the plugin name and source hive beside the output. RegRipper does not replay transaction logs automatically, so a dirty hive or missing LOG1/LOG2 can hide recently committed state. Use an approved second registry view or related artifact to corroborate a decisive value.

**Check:** Record the key/value, source hive, plugin, and exact timestamp basis. A key's last-write time does not identify the person who changed a particular value. [RegRipper CLI and transaction-log note](https://github.com/keydet89/RegRipper3.0/blob/master/rip.pl).

<a id="sqlite-artifact"></a>
## SQLite artifact: preserve WAL rows and read a copy

Collect a consistent snapshot of the database with matching `-wal` and `-shm` sidecars when present; separately copying files while an app writes can produce an inconsistent set. In a writable analysis directory, `sqlite3 -readonly COPY.db '.tables'` and `sqlite3 -readonly COPY.db '.schema TABLE'` reveal the structure without opening the database for writes. Query only the rows relevant to the clue, order them explicitly, and establish each time field's epoch and time zone before converting it. Hindsight can enrich supported browser profiles, but direct SQLite rows remain the fallback when its parser does not match the version.

**Check:** Tie a selected row to its table, database copy, sidecar state and source application. Read-only WAL access has conditions; a missing WAL or failed open is not proof that a recent row never existed. The CLI may create a working `-shm` file beside the copy. [SQLite CLI](https://www.sqlite.org/cli.html) · [SQLite WAL](https://www.sqlite.org/wal.html).

<a id="malware-executable"></a>
## Unknown executable: separate format from behavior

Start with [file_intel.py](scripts/templates/file_intel.py) or `file`, then use Detect It Easy to confirm format and architecture. For a supported native executable, `capa -v sample.bin` gives capability leads and the locations behind them. Open one relevant location in the matching disassembler; check the surrounding code or bytes before describing behavior. A decoded string, import or capability label alone does not prove that a path executes. Keep unknown programs in the intended isolated analysis environment rather than running them as a first look. [Practice the evidence distinction](PRACTICE_WORKSHEETS.md#block-6).

**Check:** Record the file type, one indicator with its offset/address, the code or bytes that support it, and one claim the evidence does *not* establish. If the packer or architecture is uncertain, resolve that before trusting a decompiler view. [capa usage](https://github.com/mandiant/capa/blob/master/doc/usage.md).

<a id="malware-document"></a>
## Office or PDF: locate code without executing it

For Office, use `olevba document.docm` to list VBA streams and inspect the extracted code. Treat reported suspicious keywords as triage hints; trace the actual macro entry point and any decoded strings. For PDF, inspect the rendered pages, then use `qpdf --check`, `qpdf --list-attachments` and `qpdf --show-pages` in the [PDF workflow](CORE_WORKFLOWS.md#pdf). Use `pdfid.py` to count noteworthy object types and `pdf-parser.py` to inspect the identified object. Do not open a recovered attachment or macro as a program merely because extraction succeeded.

**Check:** Tie any claimed code to a stream or PDF object number and explain whether it is embedded, referenced, or actually invoked. A count or keyword by itself is not an execution trace. [olevba reference](https://github.com/decalage2/oletools/wiki/olevba) · [qpdf command reference](https://qpdf.readthedocs.io/en/stable/cli.html).

<a id="malware-bundle"></a>
## Bundles: identify before choosing an extractor

Confirm PyInstaller, ASAR or UPX from the file structure and the [bundle route](index.html#route-bundle-extraction). Extract into a new directory with the matching approved tool. Keep the original and note the reported runtime or entry point. For PyInstaller, check the reported Python version before using a bytecode decompiler; for ASAR, inspect `package.json` and the named entry file. UPX decompression changes the file under examination, so compare hashes and paths before switching analysis to the unpacked copy.

**Check:** Identify the output file that contains the next code path and why. Extraction does not establish that decompiled source is complete or that the extracted program is safe to run. [PyInstaller extractor](https://github.com/pyinstxtractor/pyinstxtractor-ng) · [ASAR usage](https://github.com/electron/asar) · [UPX documentation](https://github.com/upx/upx/blob/devel/doc/upx-doc.txt).

<a id="web-endpoints"></a>
## Endpoint discovery: distinguish a hit from a wildcard

Request one invented path on the assigned host and save its status, size, body and redirect target. Run the bounded [endpoint route](index.html#route-endpoint-discovery) with a short local list. Compare candidate paths with the invented path, then verify a promising candidate in a browser or Repeater. [http_probe.py](scripts/templates/http_probe.py) can record one unauthenticated response without following redirects; use Repeater for cookies, CSRF or a multi-request flow.

**Check:** Show a response difference beyond the path string itself. Equal status codes can still have different bodies; different status codes can be authentication redirects rather than an exposed endpoint. [ffuf reference](https://github.com/ffuf/ffuf).

<a id="web-targeted"></a>
## Targeted web test: keep the hypothesis and control together

Begin with a working request to the assigned service. Send it unchanged twice in Burp Repeater, noting changing cookies, CSRF values and response content. Name the suspected input and vulnerability class from observed behavior. Change only that input, then send a nearby negative control and restore the baseline. The local PayloadsAllTheThings copy can supply syntax once its prerequisites match the observed parser or rendering context; it is a lookup, not evidence that a payload worked.

**Check:** Record the original, changed and negative-control responses and any downstream state. A status change, error message or reflected payload alone may leave multiple explanations; choose the next observation that separates them. Keep credentials and challenge content local. [Repeater guide](https://portswigger.net/burp/documentation/desktop/tools/repeater).

<a id="sqli-differential"></a>
## Suspected SQL input: compare paired conditions

Start with a working request and replay it unchanged twice in Burp Repeater. Change one suspected parameter with a syntax probe, then compare a condition expected to be true with a closely matched false condition appropriate to the actual input type and quote context. Keep a non-SQL negative control and refresh expiring sessions or CSRF values. A single quote error or changed HTTP status can also come from validation or a generic exception; seek a repeatable body or state difference that follows the condition. Only then consult the matching offline PayloadsAllTheThings topic or target one saved request and parameter with approved sqlmap.

**Check:** State the original, true, false and negative-control observations and why SQL evaluation explains them better than cache, session or input validation. Do not treat an automated report as independent proof without an application-level check. [PortSwigger SQLi detection](https://portswigger.net/web-security/sql-injection).

<a id="server-fetch"></a>
## URL input: distinguish server fetch from browser navigation

For a URL-like field, observe the unchanged request first: a browser redirect and a server-side fetch have different evidence. Substitute one benign destination within the assigned scope that returns a unique marker, plus a malformed or blocked destination as a control. Use Repeater to compare responses and a challenge-provided request log if one exists. A reflected URL, redirect, or status change alone does not prove that the application server made the request; asynchronous jobs and caching also change what you can see.

**Check:** Identify the marker or logged request, its destination and the server-side step that produced it. If no such observation exists, keep SSRF as a hypothesis and do not probe arbitrary internal addresses or external callback services. [PortSwigger SSRF](https://portswigger.net/web-security/ssrf).

<a id="object-authorization"></a>
## Object reference: compare two known owners

Use two permitted principals with objects whose ownership is already known. Capture A's normal object request and B's own-object request in separate sessions. Under B's authenticated session, change only the reference to A's object; compare the full content or state with B's own object and a nonexistent-object control. A generic 200 page or public/shared record is not a cross-owner read. Keep tokens private and avoid random ID enumeration as a substitute for ownership evidence.

**Check:** Name the intended access rule, both object owners, the session used for each request, and the data or action the server actually allowed. Without a second principal or reliable ownership evidence, report the authorization question as untested. [PortSwigger IDOR](https://portswigger.net/web-security/access-control/idor).

<a id="web-jwt"></a>
## JWT: decoded claims are not trusted claims

Save one token from a working request in a private local file. Run the read-only [jwt_inspect.py](scripts/templates/jwt_inspect.py) to display its header and payload without sending it anywhere. This parses a three-part JSON Web Signature token; it does not verify its signature, expiry, audience or server acceptance. Keep the original request, then use the approved JWT and Repeater tools to compare server responses to one relevant changed token and a negative control. An edited role claim visible in a decoder is only edited text until the server accepts it in the intended action.

**Check:** State what the server did with the original and changed token, and whether authentication, authorization or a separate application condition explains the result. Do not paste live tokens into online decoders or commit the private file. [JWT attacks and token structure](https://portswigger.net/web-security/jwt).

<a id="native-exploit"></a>
## Native crash: establish control before a payload

Confirm the executable format and architecture, then run the installed `checksec --file=./challenge` form for an ELF. Reproduce the supplied input path under GDB and compare one crashing input with a nearby noncrashing control. A cyclic pattern helps measure an offset only after the crash shows your bytes in a relevant control value; `cyclic_find` must use the same subsequence size and byte order as the generated pattern. Record the measured offset and the actual overwrite or leak. Search with ROPgadget only for a gadget required by that established primitive, and recheck its address against PIE/ASLR and the loaded build. The [plain TCP starter](scripts/templates/README.md#transport) is a transport scaffold, not proof of an exploit.

**Check:** State which input bytes controlled which runtime value, and which mitigation or unknown still blocks the next step. A protection listing or gadget address alone establishes neither exploitability nor success. [checksec 2.6.0](https://raw.githubusercontent.com/slimm609/checksec/2.6.0/checksec) · [pwntools cyclic](https://docs.pwntools.com/en/stable/util/cyclic.html) · [ROPgadget](https://github.com/JonathanSalwan/ROPgadget).

<a id="reverse-android"></a>
## APK or DEX: trace the validation path

For an APK, use its manifest and resources in JADX to identify the screen or entry point. For a raw DEX, start from the class tree and strings because there is no APK manifest. Search for a prompt or success string and follow usages into the input check. Write the actual value flow: input source, transforms, comparisons and success branch. JADX can leave incomplete or incorrect Java output; inspect the related bytecode/smali or another view when a branch or type does not make sense. Avoid installing an unknown APK merely to learn its format.

**Check:** Derive one candidate from the code and one near miss, then compare them in an isolated runtime only if execution is needed and permitted. A readable Java view alone is not proof of accepted input. [JADX documentation](https://github.com/skylot/jadx).

<a id="reverse-dotnet"></a>
## .NET: compare C# with IL at the deciding branch

Open the assembly in dnSpyEx, find the entry point or a visible success/failure string, and follow its references. Read the C# view for the broad flow, then use the IL view where the exact comparison, conversion or branch direction matters. Record the input source, expected type, comparison operands and return path. If you execute the assembly, do so in the intended isolated environment and retain a rejected control.

**Check:** Explain why the chosen input reaches the success branch and what a one-byte or one-character near miss does. A decompiler display is a hypothesis until it agrees with IL or observed behavior. [dnSpyEx project](https://github.com/dnSpyEx/dnSpy).

<a id="reverse-source"></a>
## PYC, Java or JavaScript: choose the source view by format

For PYC, establish the Python bytecode version before `pycdc module.pyc`; compare uncertain output with `pycdas module.pyc`. For Java class/JAR files, use the prepared Fernflower route and inspect the generated class that handles input. For JavaScript, format a copy with `js-beautify` and trace the handler, transforms and final comparison. Formatting does not undo semantic obfuscation; reconstructed source may omit or misrender details.

**Check:** Name the exact function and branch that decide success, then verify a candidate and near miss against the supplied checker when safe. If a decompiler fails on the bytecode version, record that limit and switch to disassembly rather than guessing missing logic. [pycdc](https://github.com/zrax/pycdc) · [Fernflower](https://github.com/JetBrains/fernflower/blob/master/README.md) · [js-beautify](https://github.com/beautifier/js-beautify).

<a id="osint-source"></a>
## Public source: retain the claim and its date context

Search only public clues, such as a distinctive quoted phrase. Open the source page, not just the result snippet. Record the URL, page title, displayed publication/update date, access date and the short passage that bears on the clue. A page date is not automatically the date of the event described. Seek an independent source for the decisive claim; two pages repeating the same original report are not independent corroboration.

**Check:** State the claim, the two source URLs, what each actually supports and any unresolved date or identity ambiguity. Do not upload private challenge material to a search service. [Search operators](https://support.google.com/websearch/answer/2466433?hl=en).

<a id="osint-domain"></a>
## Public domain: keep provider provenance

Use a domain explicitly supplied for public-source research. The [domain route](index.html#route-public-domain) writes Subfinder JSONL with `-oJ -cs`, retaining the providers reported for each hostname. Shortlist names relevant to the clue, then inspect the cited public source and its date. Passive results can be stale or empty because of provider coverage or missing keys. A discovered name is not an asset inventory or permission to scan it.

**Check:** Report the candidate hostname, provider/source, observation date and independent corroboration. Zero results is a coverage limit, not proof that no hostname exists. [Subfinder usage](https://docs.projectdiscovery.io/opensource/subfinder/usage).

<a id="xor-keystream-reuse"></a>
## XOR or reused stream: align bytes before inferring text

Convert each input to raw bytes and keep the original offsets. If two ciphertext positions used the same keystream byte, `C1 XOR C2 = P1 XOR P2`; this relation alone does not identify either plaintext. An independently known plaintext segment yields keystream bytes only at its aligned positions. Apply those bytes to the other ciphertext at matching positions. XORing a proposal back to the ciphertext checks arithmetic only; independent evidence must support the proposed text and shared-stream assumption. The local [known-key XOR helper](scripts/README.md#xor) is useful once a key and its repetition pattern are established; it does not recover unknown keys.

**Check:** Record the byte representation, alignment, known-plaintext source, recovered positions, arithmetic check and separate format or checker evidence. Leave unobserved positions unknown. A short segment should not be repeated across the file unless repeating-key XOR is evidenced. CTR can reuse keystream only where its counter blocks actually match. [NIST CTR uniqueness](https://csrc.nist.gov/pubs/sp/800/38/a/final) · [Cryptopals fixed-nonce exercise](https://www.cryptopals.com/sets/3/challenges/20).

<a id="aes-declared-parameters"></a>
## Declared AES: distinguish authentication from plausible output

Determine the exact bytes represented by the key and ciphertext and collect the mode's other inputs. GCM needs nonce, tag and any AAD; CBC needs its IV and padding rule; CTR needs the full initial counter block and layout. Use the matching approved tool or the bounded [declared-parameter helper](scripts/README.md#setup) with secrets in a private hints file. `openssl enc` does not support GCM. A GCM result is validated only after its tag verifies. CBC and CTR outputs remain candidates until an independent MAC, known plaintext, strong format check or the challenge's checker supports them. Re-encrypting with the same parameters checks implementation consistency only; readable text and valid CBC padding do not authenticate plaintext.

**Check:** Preserve the mode, key size, representation, IV/nonce, tag/AAD or padding assumption and the independent result. Missing inputs mean the transform is unverified; do not silently try unrelated modes. [NIST confidentiality modes](https://csrc.nist.gov/pubs/sp/800/38/a/final) · [NIST GCM](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf) · [OpenSSL enc limitations](https://docs.openssl.org/3.5/man1/openssl-enc/).

<a id="zip-known-plaintext"></a>
## ZipCrypto: prove the known bytes match the stored stream

Run `7z l -slt archive.zip` and inspect the selected member's Encrypted and Method fields. The simple bkcrack case is ZipCrypto with a stored member and at least 11 supplied plaintext bytes, including eight contiguous; bkcrack adds one inferred ZIP header check byte for 12 total. Write the exact supplied bytes to a local file without an accidental newline. For a deflated member, the bytes to match are compressed data, so a familiar uncompressed file header may not apply. Use the [bkcrack 1.8.1 tutorial](https://github.com/kimci86/bkcrack/blob/v1.8.1/example/tutorial.md) command form only after the preconditions hold. Decrypt the selected member with `-d` and validate its bytes; a deflated result still needs decompression. Use `-D` to make a passwordless archive, then `7z t`, only when all entries share the same keys. Internal keys are not necessarily the original password.

**Check:** Record the member, encryption and compression methods, exact known-byte source, recovered-key output, and independent member validation. ZIP AES or a wrong plaintext offset belongs on a different route; a candidate-password search can use the [Hashcat guide](HASHCAT.md) when its format and candidate evidence fit.
