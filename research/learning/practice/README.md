# Tiny local practice inputs

All files here were authored for this refresher. They are not organiser challenges, user traffic or malware. Instructions and answer checks are in [the worksheets](../../../PRACTICE_WORKSHEETS.md).

- `http-demo.pcap`: 541-byte synthetic capture, five Ethernet/IPv4/TCP packets, one HTTP request/response. Documentation IPs `192.0.2.10` and `192.0.2.20`; no live connection needed. TShark extraction and stream reassembly checked locally.
- `check_input.c`: benign argument/strcmp exercise. GCC compilation, all three output/exit cases and basic GDB execution checked locally; compile on the intended machine. No executable is distributed.
- `http/clue.txt`: static text for the loopback-only Python HTTP exercise. Python server and curl 200/404 behavior checked locally.
- `match.txt`, `near-miss.txt`, `training.yar`: harmless YARA exercise and answer rule. CLI execution untested because YARA was not on the research PATH; nothing was installed.

No local tool check establishes the organiser's installation or the travel laptop's readiness. No downloaded forensic image, video collection or malware set is included.
