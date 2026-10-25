# Python challenge scripts

[File preview](#file-intel) · [Timed arithmetic](#timed-math) · [Pwntools blocks](#transport) · [Binary parsing](#binary) · [HTTP](#http)

The file preview runs unchanged. Adapt the other scripts to the challenge format. Transport and arithmetic clients require pwntools; file preview, binary parsing and HTTP use only the Python standard library.

<a id="file-intel"></a>
## File intel: run before editing a parser

Run [file_intel.py](file_intel.py) on a challenge file without changing the
script:

```bash
python3 scripts/templates/file_intel.py challenge.bin
```

It reports size, examined bytes, the first 64 bytes as hex, and up to 20
printable ASCII strings with exact byte offsets. Reads stop at the first
1 MiB; each string preview is limited to 100 displayed characters. It marks
sampling and display limits explicitly. It accepts regular files, never
executes, extracts, or modifies them, and makes no flag or file-format claims.

For file type and supported archive/image metadata, use the existing
[inspect command](../README.md#inspect):

```bash
python3 scripts/ctf.py inspect --file challenge.bin
```

<a id="timed-math"></a>
## Timed arithmetic: 100 questions

[math_client.py](math_client.py) receives a question, calculates its answer and sends it over the same connection. It uses a bounded arithmetic parser, not `eval`. First try the harmless [math_demo.py](math_demo.py):

```bash
python3 scripts/templates/math_client.py --local python3 scripts/templates/math_demo.py
```

Expected: `Answered 100; completion: b'DONE practice-complete'`. Both scripts run locally. Use an interpreter with pwntools installed; in this workspace it is `/opt/ctf-tools/py312/bin/python`.

For an assigned service, replace HOST and PORT:

```bash
python3 scripts/templates/math_client.py --remote HOST PORT --budget 60 --max-questions 100
```

The example wire format is `Q 1: (2 + 3) * 4` followed by a newline; the client sends `20` and a newline. Question IDs start at 1 and increase by one. After the final answer, it waits for `DONE message` before reporting completion. Edit `QUESTION`, the completion condition and answer formatting to match the actual service; arbitrary banners and natural-language questions are not supported.

Supported arithmetic: integer literals, parentheses, unary signs, `+`, `-`, `*`, `//`, `%`, and `/` only when the result is an exact integer. Floor division and remainder follow Python semantics. Nonintegral division, powers, calls, names, excessive expression sizes and oversized intermediate values are rejected. Timeout, unexpected EOF or protocol errors fail explicitly rather than sending a guessed answer. The 60-second budget covers connection and question processing; real network latency still matters.

For menu handshakes or prompts without LF, use the [tested replacement block](#menu-math).

Run the local tests with the same interpreter:

```bash
python3 -m unittest discover -s tests -p test_math_client.py -v
```

<a id="transport"></a>
## Pwntools transport

Copy [pwntools_starter.py](pwntools_starter.py) into your challenge directory and edit `PROMPT`,
`PAYLOAD`, and the response handling. The unchanged script waits for `> `,
sends `hello` plus a newline, and prints one newline-terminated reply as bytes.
A reply is not proof that a challenge is solved.

Use `python3` from an environment with **pwntools** installed:

```bash
python3 scripts/templates/pwntools_starter.py --local ./challenge
python3 scripts/templates/pwntools_starter.py --remote 127.0.0.1 31337 --timeout 5
```

In this workspace, replace `python3` with `/opt/ctf-tools/py312/bin/python`
to use the preinstalled environment. Check the competition laptop separately.

Replace the example endpoint with your assigned challenge host and port. Local
mode runs the binary directly with its normal ASLR settings; remote mode makes
one TCP connection. There are no retries, scans, or automatic exploit guesses.
Both close on exit. Timeout, early EOF, or a missing delimiter within 4096 bytes
returns a nonzero exit status. Each receive stage has its own total time limit.

## Editing the payload

Keep protocol data as `bytes`. If the challenge expects raw binary data,
replace `sendline` with `send`. Adjust prompt and response delimiters to the
actual protocol. For addresses, choose packing explicitly after checking the
binary's architecture and byte order:

```python
from pwn import p32, p64

# Packing examples only; these are not challenge addresses.
assert p32(0x12345678, endian="little") == b"\x78\x56\x34\x12"
assert p64(0x12345678, endian="little") == b"\x78\x56\x34\x12\x00\x00\x00\x00"
# Once independently established: PAYLOAD = b"A" * offset + p64(address, endian="little")
```

Offsets, addresses, leaks, and the final success condition must come from your
challenge analysis. This starter does not assume an overflow, architecture,
libc version, or a shell. Its single-line exchange must be edited for menus,
length-prefixed messages, TLS, or multi-stage challenges.

Reference: [pwntools tubes](https://docs.pwntools.com/en/stable/tubes.html),
[process](https://docs.pwntools.com/en/stable/tubes/processes.html), and
[remote](https://docs.pwntools.com/en/stable/tubes/sockets.html).

Run the harmless process and loopback checks from the repository root:

```bash
/opt/ctf-tools/py312/bin/python -m unittest discover -s tests -p test_templates.py -v
```

<a id="binary"></a>
## Binary parsing

Copy [binary_parser.py](binary_parser.py) and edit `RECORD`, `MAGIC`, the
unpacked fields, and validation for your format. This read-only example parses
one synthetic eight-byte record: `CTF!` followed by a little-endian unsigned
32-bit integer. It accepts regular files and checks the offset and available length before unpacking; pipes and devices are rejected.
It does not identify arbitrary formats.

Create a disposable sample and parse it:

```bash
python3 -c 'import struct; from pathlib import Path; p = Path("sample-record.bin"); p.open("xb").write(struct.pack("<4sI", b"CTF!", 42))'
python3 scripts/templates/binary_parser.py sample-record.bin --offset 0x0
```

`<` selects little endian; use `>` for big endian. Avoid native `@` layouts
unless the format explicitly requires host alignment. This template needs
only Python's standard library.

<a id="http"></a>
## HTTP request/response experiments

Copy [http_probe.py](http_probe.py) and edit `HEADERS` or the request/response
handling for your challenge. It needs only Python's standard library. These
examples require your own local challenge service on port 8000:

```bash
python3 scripts/templates/http_probe.py http://127.0.0.1:8000/ --timeout 5
python3 scripts/templates/http_probe.py http://127.0.0.1:8000/echo --data 'hello'
```

It sends one GET, or a POST with UTF-8 `text/plain` content when `--data` is
supplied. Change `Content-Type` when your body uses another format. It prints
the HTTP status, up to 40 escaped response headers (512 characters per value), and a byte representation of at most 64 KiB of body; a larger
body is marked truncated and returns nonzero. Redirects are reported without
following them, so edited headers are never forwarded to a redirect target.
HTTP errors, redirects, incomplete declared bodies, connection failures, and timeouts also return nonzero. A Server header is a clue to investigate, not proof of a product version or vulnerability.
A 2xx response is transport evidence, not proof that a challenge is solved.

The timeout applies to blocking socket operations, not a total elapsed-time
budget; a slowly streaming service can take longer. HTTPS uses normal
certificate verification. The template has no retry loop, cookie session,
authentication helper, or scanner. Keep challenge credentials out of committed
copies and command-line arguments.

Standard-library references: [struct](https://docs.python.org/3/library/struct.html)
and [urllib.request](https://docs.python.org/3/library/urllib.request.html).

## Common pwntools blocks

Use these inside your copied starter; `receive_until` is the bounded helper
already defined there. Choose one transport per run:

```python
from pwn import process, remote

# Local executable:
with process(["./challenge"], timeout=5) as io:
    receive_until(io, b"> ", 5)
    io.sendline(b"hello")  # Adds a newline.
    reply = receive_until(io, b"\n", 5)
    print(repr(reply))

# Or remote TCP (replace with your assigned endpoint):
with remote("127.0.0.1", 31337, timeout=5) as io:
    receive_until(io, b"data: ", 5)
    io.send(b"ABCD")  # Exactly four bytes; no newline added.
    reply = io.recvn(4, timeout=5)
    if len(reply) != 4:
        raise TimeoutError("expected four reply bytes")
    print(repr(reply))
```

`recvn` can return an empty value on timeout and raise `EOFError` when the
peer closes early. Keep these blocks inside the starter's error handling;
do not treat empty or partial input as a completed reply. Delimiters and
lengths must match the challenge protocol.

<a id="menu-math"></a>
## Adapt to a menu and prompts without newlines

First record the actual banner, menu, question boundary, answer prompt and completion message. The default arithmetic client reads LF-terminated questions; a prompt ending in `: ` or `= ` needs delimiter-based receiving.

Copy `math_client.py` and `pwntools_starter.py` together. Remove the old `QUESTION` definition and replace `exchange()` with the following block, including its import and constants. Keep `solve`, `remaining`, `read_line`, the CLI and error handling. This example selects menu option 1 and requires 100 recognised answers plus the service's terminal token; edit its protocol literals for your challenge.

```python
from pwntools_starter import receive_until

QUESTION = re.compile(rb"Round ([0-9]{3})/100: (?:evaluate|calculate) (.+)\r\n")
TOKEN = re.compile(rb"token: ([a-z0-9-]{1,128})\r\n")


def exchange(tube, deadline, max_questions):
    receive_until(tube, b"choice: ", remaining(deadline))
    tube.settimeout(remaining(deadline))
    tube.sendline(b"1")
    answered = 0
    while True:
        line = read_line(tube, deadline)
        if line == b"RESULT ok 100/100\r\n":
            if answered != 100:
                raise ValueError("completion before 100 answered rounds")
            token = TOKEN.fullmatch(read_line(tube, deadline))
            if not token:
                raise ValueError("missing terminal token")
            print(f"Answered {answered}; token: {token[1]!r}")
            return
        match = QUESTION.fullmatch(line)
        if not match:
            raise ValueError(f"unexpected protocol line: {line!r}")
        if answered >= max_questions:
            raise ValueError("question limit exceeded; expected RESULT")
        if int(match[1]) != answered + 1:
            raise ValueError("question IDs must start at 1 and increase by one")
        answer = solve(match[2].decode("ascii"))
        if receive_until(tube, b"answer = ", remaining(deadline)) != b"answer = ":
            raise ValueError("unexpected answer prompt")
        tube.settimeout(remaining(deadline))
        tube.sendline(str(answer).encode("ascii"))
        answered += 1
```

The existing `--remote HOST PORT --budget 60` options still apply. Each receive/send uses the remaining session budget. An unexpected banner, a changed expression format or premature completion is an error, not permission to send a guessed answer.

<a id="binary-frame"></a>
## Read a length-prefixed binary reply

Place this block inside the transport starter's error handling after the request. This example protocol uses a two-byte big-endian length and a 512-byte cap; use the actual protocol's byte order and limit.

```python
prefix = io.recvn(2, timeout=5)
if len(prefix) != 2:
    raise TimeoutError("expected two-byte reply length")
length = int.from_bytes(prefix, "big")
if not 1 <= length <= 512:
    raise ValueError("invalid reply length")
body = io.recvn(length, timeout=5)
if len(body) != length:
    raise TimeoutError("incomplete reply body")
```

`recvn` handles fragmented delivery; timeout may return empty bytes and early closure may raise `EOFError`. For a whole-session deadline, pass the remaining budget to each stage.

<a id="http-session"></a>
## Keep HTTP cookies across an explicit flow

For a challenge requiring session state, replace the one-request opener with one shared cookie opener. Retain the template's redirect policy and bounded body/status checks:

```python
from http.cookiejar import CookieJar
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, build_opener

opener = build_opener(NoRedirect(), HTTPCookieProcessor(CookieJar()))
# Reuse opener for the selected requests, applying the existing response checks.
# After obtaining and validating the expected nonce from the first response:
request = Request(url, data=urlencode({"nonce": nonce}).encode("ascii"),
                  headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"})
# opener.open(request, timeout=5)
```

Cookie storage does not provide the login sequence, nonce parser or success condition. Those are explicit edits. Match form versus JSON content types, and require the actual terminal response before claiming the flow succeeded.
