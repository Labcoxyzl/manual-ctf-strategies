# Wireshark and Burp GUI acceptance attempt

## Result

Neither desktop interaction was verified. The task environment has no `Xvfb`, `Xorg`, `Xephyr`, `Xwayland`, `xdotool`, or `wmctrl` executable. `DISPLAY=:0` is the shared WSLg desktop, so opening a normal GUI there would risk taking focus. No app GUI was opened, no screenshot was captured, and no HTTP request was routed through Burp. The instructions in the guide therefore remain source-guided for these two GUIs.

## Wireshark

- Windows Wireshark is installed: `Wireshark 4.6.2`; see [wireshark-version.txt](wireshark-version.txt). `Wireshark.exe -v` exited without opening the GUI.
- The installed Windows `tshark.exe` read `examples/core/http.pcap` and ran `--export-objects http,<task-owned-directory>`. The resulting [report.txt](wireshark-export/report.txt) is exactly 51 bytes and `cmp` matched `examples/core/expected.txt`. Both have SHA-256 `45ccc5cf7b56c0d158ad7920dc13d203b363fad7a7e13be0da5da5969374d963`. The input PCAP SHA-256 is `11cf6e464e880a8164eb0fb0eff6607030aa76b878877e838ecbcdcabb09cee0`.
- This confirms the installed Windows dissector's export on the authored fixture. It does not confirm opening the PCAP in Wireshark, using Follow TCP Stream, Export Objects through the GUI, or inspecting a screenshot.

## Burp Community

- The installed launcher jar reports `2026.10-54643 Burp Suite`; see [burp-version.txt](burp-version.txt). The jar SHA-256 is `a43a499aef4b464fd2769e503712160dad9f4ebf0caf7145a99b12aa0350213a`.
- With `DISPLAY=` and Java headless mode, I ran it against a task-owned `--data-dir=<absolute path>` and `--project-file=<absolute path>`, with `-Duser.home=<task-owned path>`, `--disable-auto-update`, and `--use-defaults`. [burp-startup.log](burp-startup.log) ends at `Do you accept the license agreement? (y/n)`; EOF produced exit status `11` ([burp-startup.exit](burp-startup.exit)). No project file or proxy listener was created. I did not accept the license terms for the user.
- Startup unpacked a bundled browser into the isolated profile (668 MB). The jar itself contains `chromium-linux64-154.0.8037.97.zip` (203,876,021 bytes); the extracted `chrome` was 532,671,736 bytes. This is consistent with local extraction, and I saw no evidence of a network download. Automatic approval review rejected removal of the task-owned temporary profile; it remains in `gui-apps/burp-profile/` and is ignored by Git.
- A task-owned Python HTTP server bound only to `127.0.0.1` on ephemeral port `41353`. Direct `curl` requests to `/clue?mode=baseline` and `/clue?mode=changed` both returned HTTP 200 with distinct `baseline\n` (9 bytes) and `changed\n` (8 bytes). See [server.log](server.log), [baseline.body](baseline.body), and [changed.body](changed.body). The server was stopped. These direct requests establish a local target, not Burp Proxy history or Repeater behavior.

## Guide implication

Keep the existing Burp and Wireshark steps labeled as source-guided. The Burp practice worksheet's claim that its Python server/curl pair was tested remains supported; its explicit Burp GUI limitation remains accurate. A later GUI pass needs a user-authorized license acceptance and an isolated desktop with controllable GUI windows before the Proxy/Repeater and Wireshark menu steps can be claimed as tested.
