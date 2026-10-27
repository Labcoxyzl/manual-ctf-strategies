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

<a id="browser-profile-timeline"></a>
## Browser profile: trace a selected visit

Use a coherent copy of one supplied Chrome/Chromium or Firefox profile. Keep `History` or `places.sqlite` with any matching `-wal` and `-shm` files; note whether the browser was running when copied. Record the browser/profile version and source path. If the **installed** Hindsight help lists `--only`, run `hindsight.py -i PROFILE_DIR -o PRIVATE_OUT --only history` (`-b Firefox` only if detection needs it). Keep the output private and inspect the parse/skip/error report. Older Hindsight without the filter can also parse cookies and passwords, so use the SQLite fallback below rather than a default full-profile export.

Check the copied schema first: `sqlite3 -readonly COPY/History '.schema urls' '.schema visits'` or `sqlite3 -readonly COPY/places.sqlite '.schema moz_places' '.schema moz_historyvisits'`. Then select a small, evidenced URL set, replacing `MARKER` locally:

```sh
sqlite3 -readonly COPY/History "SELECT v.id,u.url,v.visit_time,datetime((v.visit_time-11644473600000000)/1000000,'unixepoch') FROM visits v JOIN urls u ON u.id=v.url WHERE u.url LIKE '%MARKER%' ORDER BY v.visit_time,v.id LIMIT 20;"
sqlite3 -readonly COPY/places.sqlite "SELECT h.id,p.url,h.visit_date,datetime(h.visit_date/1000000,'unixepoch') FROM moz_historyvisits h JOIN moz_places p ON p.id=h.place_id WHERE p.url LIKE '%MARKER%' ORDER BY h.visit_date,h.id LIMIT 20;"
```

Use only the query matching the source browser and confirmed schema. Keep raw times alongside UTC conversions; check the time basis before relying on a displayed date. SQLite may create a working `-shm` beside the copy. Compare a decisive row with a separate known log or download record and preserve the exact profile/database path. A stored visit may come from sync, import or another browser action; it does not identify a human viewer. A missing row can also mean a different profile, absent WAL, filtered output, unsupported schema or parser error. [Hindsight CLI](https://github.com/RyanDFIR/hindsight/blob/main/README.md) · [Chromium visits](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/history/core/browser/visit_database.cc) · [Chromium time](https://chromium.googlesource.com/chromium/src/+/bf34def0e76d2c8581f107759b0ec607a89fe2a6/base/time/time.h) · [Firefox Places](https://firefox-source-docs.mozilla.org/browser/places/architecture-overview.html) · [Firefox visit source](https://raw.githubusercontent.com/mozilla-firefox/firefox/main/toolkit/components/places/History.cpp).

<a id="android-preferences"></a>
## Android app data: inspect one preference key

Require a supplied, accessible app-data extraction; an APK does not contain a user's private app state. Preserve the original and record the Android user, package, source path and file hash before copying one evidenced SharedPreferences XML file **and any matching `.bak`**. Android may restore that backup on load, so compare both copies if present; an extraction made during a write may not identify one active value. App versions and users can have different files. If a complete extraction and the approved ALEAPP build are available, check its local help, create a private output directory first, then run `aleapp -t fs -i EXTRACTION_DIR -o PRIVATE_OUT` (or the installed `python3 aleapp.py` equivalent). Keep its version, module errors and source-file references; a report row is a lead, not proof that another file or user had the same state.

For a **copied regular UTF-8 XML file of at most 1 MiB**, select one named string, boolean or decimal int/long key locally with approved Python. Do not dump every preference:

```sh
python3 - COPY.xml KEY <<'PYCODE'
import os, re, stat, sys
from xml.etree import ElementTree as ET
if len(sys.argv) != 3:
    raise SystemExit('supply a copied XML file and one key')
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd, 'rb') as source:
    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
        raise SystemExit('not a regular file')
    data = source.read(1024 * 1024 + 1)
if len(data) > 1024 * 1024 or b'\x00' in data:
    raise SystemExit('large or non-UTF-8 XML is unsupported')
try:
    data.decode('utf-8')
except UnicodeDecodeError:
    raise SystemExit('non-UTF-8 XML is unsupported') from None
if b'<!DOCTYPE' in data.upper():
    raise SystemExit('DTD-bearing XML is unsupported')
try:
    root = ET.fromstring(data)
except ET.ParseError:
    raise SystemExit('malformed XML') from None
rows = [item for item in root if item.get('name') == sys.argv[2]]
if root.tag != 'map' or len(rows) != 1 or len(rows[0]):
    raise SystemExit('missing, duplicate, or structured key')
item = rows[0]
if item.tag not in ('string', 'boolean', 'int', 'long'):
    raise SystemExit('unsupported preference value type')
if item.tag == 'string':
    value = item.text or ''
else:
    value = item.get('value')
    if value is None or len(value) > 64 or (item.text or '').strip():
        raise SystemExit('malformed primitive value')
    if item.tag == 'boolean' and value not in ('true', 'false'):
        raise SystemExit('invalid boolean value')
    if item.tag in ('int', 'long'):
        if not re.fullmatch(r'-?[0-9]+', value):
            raise SystemExit('invalid integer value')
        number = int(value)
        bits = 32 if item.tag == 'int' else 64
        if not -(1 << (bits - 1)) <= number < (1 << (bits - 1)):
            raise SystemExit('integer exceeds Android type range')
print(item.tag, repr(str(value)[:160]))
PYCODE
```

**Check:** Tie the selected key, stored type and value to the copied XML and an independent app/configuration clue, database row, log or known case observation. For an app database, follow the [SQLite/WAL workflow](#sqlite-artifact) with its matching sidecars. A numeric preference has no universal time epoch. Missing keys, conflicting XML/`.bak`, non-UTF-8 or unsupported value types, malformed XML, a different Android user, unavailable/unsupported ALEAPP modules or an incomplete extraction leave absence inconclusive. Keep private values out of shared notes. [Android SharedPreferences](https://developer.android.com/training/data-storage/shared-preferences) · [AOSP XML implementation](https://android.googlesource.com/platform/frameworks/base/+/main/core/java/android/app/SharedPreferencesImpl.java) · [ALEAPP CLI](https://github.com/abrignoni/ALEAPP/blob/main/README.md) · [Python XML security](https://docs.python.org/3.12/library/xml.html).

<a id="android-datastore-preferences"></a>
## Android Preferences DataStore: select one key from a copy

An accessible app-data extraction may contain `files/datastore/*.preferences_pb` instead of SharedPreferences XML. An APK alone does not contain the user's stored preferences. Record the Android user, app package, original path and hash; work on a stable copy. Check that the file is **Preferences DataStore**. App-defined Proto DataStore files need their own schema and are outside this reader's scope.

For one exact key, run the bundled standard-library reader from the offline kit in a private session:

```sh
python3 scripts/templates/datastore_pref.py COPY.preferences_pb KEY
```

It accepts one regular file up to 1 MiB and reports the selected key's stored boolean, int32, int64 or string value. It validates every map entry, rejects duplicates and truncated or ambiguous wire data, and does not print other keys. Valid float, double, string-set and byte-array values on *other* keys do not block selection; a requested key of those types needs another parser. A missing key means only that it was absent from this copy. Keep selected values out of shared notes.

**Check:** Match the reported key, type and source path to independent app code, configuration, log or case evidence. A numeric value has no universal timestamp unit. If ALEAPP is installed, use its source-file reference and parser version as a lead, then confirm the decisive value against the copied file. Another Android user, app version, file, incomplete extraction or an unsupported selected type remains possible. [Android DataStore](https://developer.android.com/topic/libraries/architecture/datastore) · [AndroidX Preferences schema](https://android.googlesource.com/platform/frameworks/support/+/refs/heads/androidx-main/datastore/datastore-preferences-proto/src/main/proto/preferences.proto).

<a id="ios-plist"></a>
## iOS plist: inspect one named field

Work on a copy of a supplied XML or binary plist. Record its original path, application/container context and hash. The approved Python standard library reads both formats without an added dependency. Inspect a **named** key path, rather than dumping a whole potentially private file. Pass each nested dictionary key or list index as a separate argument:

```sh
python3 - COPY.plist APP KEY <<'PYCODE'
import datetime, plistlib, sys
with open(sys.argv[1], 'rb') as source:
    data = plistlib.load(source)
if len(sys.argv) < 3:
    raise SystemExit('supply at least one key')
value = data
for part in sys.argv[2:]:
    value = value[int(part)] if isinstance(value, list) else value[part]
scalar = isinstance(value, (str, int, float, bool, datetime.datetime))
print('/'.join(sys.argv[2:]), type(value).__name__, str(value)[:160] if scalar else '[structured or binary value]')
PYCODE
```

A missing key or out-of-range index raises an error; inspect the actual structure and field definition before choosing another path. If a complete extracted filesystem is supplied and approved iLEAPP is available, check its local help, create a private output directory, then run `ileapp -t fs -i EXTRACTION_DIR -o PRIVATE_OUT`. The output directory must already exist. Tie a selected report field back to its original plist and independent app or case context. Numeric times need their field-specific epoch and units before conversion. Encrypted/incomplete backups, unsupported keyed archives, malformed plists and parser errors leave absence inconclusive. Do not paste private report values into shared notes. [Python plistlib](https://docs.python.org/3/library/plistlib.html) · [iLEAPP CLI](https://github.com/abrignoni/iLEAPP/blob/main/README.md).

<a id="git-history"></a>
## Git history: recover the exact source revision

Work on a copy of the supplied repository. `git -C REPO status --short` separates working-tree files from committed history; `git -C REPO log --all --oneline --decorate` shows the refs actually present without fetching anything. For a known path, `git -C REPO log --all --follow --oneline -- PATH` can trace simple renames. Choose a commit that contains the file and inspect its exact blob with `git -C REPO show COMMIT:PATH`. If the clue points to a deletion commit, select the parent in which the path still existed; do not assume the current branch has the only relevant history.

**Check:** Keep the commit ID, path, blob bytes and source ref together. A Gitleaks match can guide a focused inspection but is not proof that a historical credential is valid. Avoid broad terminal dumps and do not copy recovered secrets into shared notes. Missing objects in a shallow or incomplete repository leave the question open. [Git log](https://git-scm.com/docs/git-log) · [Git show](https://git-scm.com/docs/git-show) · [Gitleaks](https://github.com/gitleaks/gitleaks).

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

<a id="web-output-context"></a>
## Reflected input: separate output from execution

Start with a working request to the **assigned** application. Replay it unchanged twice in Burp Repeater so redirects, session state and changing response fields are visible. Change one input to a unique inert marker and save the request, `Content-Type` and relevant raw response bytes. Locate the marker in its exact HTML text, quoted attribute, URL, script or other context. [http_probe.py](scripts/templates/http_probe.py) can record a single stateless request; use Repeater when cookies, CSRF or multi-request state matter.

On the selected Repeater response, use **Show response in browser** and open the unique URL in Burp’s browser or Chrome configured through Burp. Burp serves the selected main response without forwarding a new request to the application; page assets may still generate requests. Compare its raw source with the parsed DOM and console; note enforced `Content-Security-Policy` separately from Report-Only. If a script-execution check is justified for the observed context, use a harmless local DOM marker and no cookie access or external request. For a plain HTML text insertion **only**, one candidate is `<script>document.documentElement.dataset.ctfProbe='case-marker'</script>`; other contexts need different syntax. Check that the marker appears in the DOM only for the changed request, then repeat the unchanged request and a nearby negative control. A reflected string or injected element without the expected effect is not proof of script execution. A CSP block is evidence about that test and policy, not a universal safety result.

**Check:** Keep the source request, raw response, parsed context, browser/CSP observation and negative control together. If the value is missing or the response changed, recheck redirects, cache, encoding, session and client-side rendering before drawing a conclusion. Do not spray payload lists or access secrets. [OWASP reflected XSS testing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting/) · [OWASP output contexts](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) · [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP) · [Burp response in browser](https://portswigger.net/burp/documentation/desktop/tools/message-editor).

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

<a id="path-traversal-read"></a>
## File path input: verify an outside-root read

Use a file-serving request on the **assigned** service and establish its intended serving root. Choose one allowed file, one missing filename, and one permitted benign file known to be **outside** that root with bytes known independently from the HTTP response. If the outside file's location or bytes are unknown, record a path-traversal lead rather than a confirmed read. Save the unchanged request and its raw response. In Burp Repeater, repeat the allowed-file request, send the missing-file control, then change only the file input to one relative traversal path reaching the known outside file. Preserve the other fields and session; inspect and retain the exact query bytes sent, including the chosen path encoding. Keep the request count small and within the assigned scope. The optional [WEB05 selected-input check](TOOLKIT.html#web-leads) compares a candidate marker against two missing-file controls; it preserves untouched raw query fields but re-encodes the selected value and does not establish file provenance.

**Check:** Compare raw response body bytes with the independently known outside file, and confirm that this file lies beyond the intended root and was not deliberately served through that endpoint. Repeat the selected request only if session or cache behavior needs calibration. A reflected path, familiar filename, generic 200, error text, redirect, or WEB05 lead alone is inconclusive; a body wrapper or transformation needs an independently justified byte comparison. Do not request unrelated private files or widen into recursive path spraying. [OWASP directory traversal testing](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/01-Directory_Traversal_File_Include/) · [PortSwigger path traversal](https://portswigger.net/web-security/file-path-traversal) · [Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater).

<a id="web-cross-site-state"></a>
## Cross-site request: establish a state change

Use only a permitted test account and a reversible action with a fresh state readout. In Chrome, perform one legitimate same-site action and capture its method, `Content-Type`, body, session cookie attributes, CSRF token, `Origin`, and `Sec-Fetch-Site` in Burp. Record the state before and after with a unique marker. A response status or echoed value is transport evidence, not the state result.

Copy the [one-click form template](scripts/templates/cross_site_form.html), match its GET/POST method and form encoding, replace its placeholder action and fields, and serve it from a **different site** on loopback with approved Python. A different port alone changes the origin but may leave the site the same. In the same disposable browser session, click once and inspect the browser request. Record whether the session cookie was attached and whether the server received the intended fields. Compare against an unauthenticated or invalid-token control; use a new marker or restore the state between attempts. A plain form cannot reproduce other HTTP methods, JSON/custom headers, or obtain a fresh target-only CSRF token.

**Check:** Read the application state independently after each attempt and tie any change to the cross-site request, its cookie/session and a control that did not change state. A blocked CORS read, 200, redirect or `SameSite` label alone is inconclusive. If the browser omitted the cookie or the action had no observable state, report that limit rather than inferring a universal CSRF defense. [OWASP CSRF testing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery/) · [MDN CSRF](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF) · [MDN SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie).

<a id="web-jwt"></a>
## JWT: decoded claims are not trusted claims

Save one token from a working request in a private local file. Run the read-only [jwt_inspect.py](scripts/templates/jwt_inspect.py) to display its header and payload without sending it anywhere. This parses a three-part JSON Web Signature token; it does not verify its signature, expiry, audience or server acceptance. Keep the original request, then use the approved JWT and Repeater tools to compare server responses to one relevant changed token and a negative control. An edited role claim visible in a decoder is only edited text until the server accepts it in the intended action.

**Check:** State what the server did with the original and changed token, and whether authentication, authorization or a separate application condition explains the result. Do not paste live tokens into online decoders or commit the private file. [JWT attacks and token structure](https://portswigger.net/web-security/jwt).

<a id="native-exploit"></a>
## Native crash: establish control before a payload

Confirm the executable format and architecture, then run the installed `checksec --file=./challenge` form for an ELF. Reproduce the supplied input path under GDB and compare one crashing input with a nearby noncrashing control. A cyclic pattern helps measure an offset only after the crash shows your bytes in a relevant control value; `cyclic_find` must use the same subsequence size and byte order as the generated pattern. Record the measured offset and the actual overwrite or leak. Search with ROPgadget only for a gadget required by that established primitive, and recheck its address against PIE/ASLR and the loaded build. The [plain TCP starter](scripts/templates/README.md#transport) is a transport scaffold, not proof of an exploit.

**Check:** State which input bytes controlled which runtime value, and which mitigation or unknown still blocks the next step. A protection listing or gadget address alone establishes neither exploitability nor success. [checksec 2.6.0](https://raw.githubusercontent.com/slimm609/checksec/2.6.0/checksec) · [pwntools cyclic](https://docs.pwntools.com/en/stable/util/cyclic.html) · [ROPgadget](https://github.com/JonathanSalwan/ROPgadget).

<a id="symbolic-elf-checker"></a>
## Linux ELF checker: bound the symbolic input

First identify one supplied Linux x86/x86-64 ELF and the path by which it reads the proposed answer. Use the [manual checker route](index.html#route-native-checker) to establish a concrete argv or stdin length and a success string, failure string or verified branch address. Make a private hints file with only those observations. For a five-byte argv checker that prints `accepted` or `rejected`, an example model is:

```json
{"checker":{"channel":"argv","length":5,"find":{"stdout":"accepted"},"avoid":{"stdout":"rejected"}}}
```

Replace these values for the actual checker. On an isolated analysis machine with angr installed, check `python3 scripts/autosolve.py doctor --profiles reversing --self-test` and inspect the **checker** operation and angr engine; the overall doctor result can be partial because of other tools. Then run:

```sh
python3 scripts/autosolve.py analyze ./checker --category reversing --hints ./checker.json --execute-local
```

This opts in to bounded symbolic search of one selected ELF; it does not run the binary concretely or establish an accepted challenge answer. The [toolkit command guide](scripts/README.md#checker) lists limits and output meanings. If local execution is permitted, request a separate concrete replay only in an isolated environment:

```sh
python3 scripts/autosolve.py resume RUN_DIR --hints ./checker.json --replay-checker
```

The run must have started with `--execute-local`. Replay uses a private snapshot, a reduced environment and resource limits, but it is **not a filesystem or network sandbox**. For `validated_input`, the checker must exit zero and print one complete line exactly equal to the declared success marker; a substring such as `accepted` inside `not accepted` fails this check. A reached address remains a candidate. Compare one nearby rejected input using the original checker, and keep the executable, hints and reports private. If search is incomplete, times out or returns `unsat_under_model`, inspect the input model and branch evidence rather than claiming impossibility. [angr symbolic execution](https://docs.angr.io/en/latest/core-concepts/symbolic.html) · [Simulation managers](https://docs.angr.io/en/latest/core-concepts/pathgroups.html).

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

<a id="cbc-padding-oracle"></a>
## CBC padding oracle: establish the signal before recovery

Use this only for an assigned endpoint that accepts an editable CBC ciphertext. Record the exact byte encoding, block size, IV location, HTTP method, session and unchanged baseline response. CBC decryption changes a plaintext block when its preceding ciphertext block (or IV for the first block) changes. A padding oracle exists only if otherwise comparable requests reveal whether the final plaintext padding is valid. An error from a malformed length, MAC, AEAD tag, session rejection or application parser does not establish that signal.

On a copy of one sample, repeat the unchanged request, one prior-block mutation expected to disturb the final padding, and a control mutation outside the padding bytes where that position is known. Keep every other request field fixed; compare response status and body class rather than timing alone. Repeat each class to rule out transient behavior. A mutation can accidentally produce valid padding, so use more than one; stop if the responses are generic, unstable or rate-limited. For a one-block ciphertext with a prepended IV and a known one-byte PKCS#7 pad, flipping the IV's last byte by `0x01` forces a zero final byte, while flipping its first byte leaves that padding byte untouched. This is a calibration example, not an assumption about an unknown challenge.

The approved tool sends a **two-block payload** for each guess: an editable first block followed by the target block. Before using it, repeat the valid/invalid comparison with that shortened, two-block shape in the exact request field it would replace. Also try an arbitrary first block and check that it reaches the same padding-error class as the known invalid mutation; the tool starts its guessed block from zero bytes. A full-length sample can leak padding errors while the shortened probes fail an application length or format check. The command below applies when the endpoint accepts a prepended IV and ciphertext together in one field. If IV and ciphertext occupy separate fields, or the service requires an unchanged prefix or fixed length, verify the installed tool can express that layout; otherwise stop at manual calibration.

Only after this preflight, check `padding-oracle-attacker --help` on the approved Kali machine. The upstream CLI's positional arguments are URL, encoded ciphertext, block size and the observed error status or body substring. Replace every placeholder below with your own observed values; `{POPAYLOAD}` marks the single injection point. Use one concurrent request and disable its response cache:

```bash
padding-oracle-attacker decrypt 'https://ASSIGNED/decrypt?ciphertext={POPAYLOAD}' 'hex:IV_AND_CIPHERTEXT_HEX' 16 'OBSERVED_PADDING_ERROR' -c 1 --disable-cache
```

If the endpoint needs POST, a cookie or another encoding, use the installed CLI's `-X`, `-H`, `-d` and `-e` options after checking its help; do not guess their values. The upstream default is 128 concurrent requests and a local cache file. A benign one-block local exercise took 2,350 requests, so estimate the request count for the selected blocks and respect the assigned service's limits before running recovery. Keep ciphertext, session values and output in private local files. Recovered bytes are candidates until independent known plaintext, a strong source format, a valid MAC or the challenge checker supports them. On a generic-response control, this CLI even exited successfully with false plaintext; its exit status is not proof. Re-encryption and valid padding alone only check consistency.

**Check:** Record repeated response classes for both the original and two-block shape, the exact error marker and injected byte location, the candidate bytes and the separate evidence supporting them. The approved tool's installed version and availability are not guaranteed. [Tool CLI](https://github.com/KishanBagaria/padding-oracle-attacker) · [NIST CBC mode](https://csrc.nist.gov/pubs/sp/800/38/a/final) · [PKCS#7 padding rule](https://datatracker.ietf.org/doc/html/rfc5652#section-6.3).

<a id="zip-known-plaintext"></a>
## ZipCrypto: prove the known bytes match the stored stream

Run `7z l -slt archive.zip` and inspect the selected member's Encrypted and Method fields. The simple bkcrack case is ZipCrypto with a stored member and at least 11 supplied plaintext bytes, including eight contiguous; bkcrack adds one inferred ZIP header check byte for 12 total. Write the exact supplied bytes to a local file without an accidental newline. For a deflated member, the bytes to match are compressed data, so a familiar uncompressed file header may not apply. Use the [bkcrack 1.8.1 tutorial](https://github.com/kimci86/bkcrack/blob/v1.8.1/example/tutorial.md) command form only after the preconditions hold. Decrypt the selected member with `-d` and validate its bytes; a deflated result still needs decompression. Use `-D` to make a passwordless archive, then `7z t`, only when all entries share the same keys. Internal keys are not necessarily the original password.

**Check:** Record the member, encryption and compression methods, exact known-byte source, recovered-key output, and independent member validation. ZIP AES or a wrong plaintext offset belongs on a different route; a candidate-password search can use the [Hashcat guide](HASHCAT.md) when its format and candidate evidence fit.
