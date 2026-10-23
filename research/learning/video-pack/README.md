# Caption-reviewed CTF video watch list

> **Download update:** all 17 videos are now local. [Open the full download index](DOWNLOAD_INDEX.md); new files are 09–17 in the same `videos/` folder. The original eight-video review below is retained as history.

> **Starter pack only:** these eight videos total1:43:34, not twelve hours. For the complete200-row coverage audit and deeper instruction, use the [expanded learning collection](../../../TOOL_LEARNING_COLLECTION.md). The original recommendations below are short refreshers or narrow workflows, not comprehensive tool coverage.

**Start with videos 1–6.** They teach concrete approved-tool workflows. Videos 7–8 are optional context; the RSA video is math rather than RsaCtfTool instruction, and the audio video depends heavily on online decoders.

All eight runtimes total **103:34**; the six core videos total **88:21**. Suggested core sections total about **63:27**, before pausing/practice. These are actual metadata runtimes and selected intervals, not the earlier study-time estimates.

English caption files were fetched with the installed yt-dlp; full extracted text was read. Automatic captions can misspell commands and this is not a full audiovisual review. All original VTT files and cleaned timestamped transcripts are saved below.

| Order | Video / approved-tool focus | Runtime | Suggested sections | Decision |
| --- | --- | --- | --- | --- |
| 1 | [Burp Repeater](https://www.youtube.com/watch?v=_Wifm2g9ugg) — PortSwigger | 06:30 | 00:20–02:25, 04:15–06:20 | Watch first |
| 2 | [CyberChef](https://www.youtube.com/watch?v=UtqmiI7k9lU) — Level Effect | 07:17 | 01:10–03:25, 03:25–06:35 | Watch first |
| 3 | [Ghidra](https://www.youtube.com/watch?v=fTGTnrgjuGA) — stacksmashing | 11:30 | 01:00–03:15, 06:00–11:25 | Watch first |
| 4 | [GDB / control flow](https://www.youtube.com/watch?v=VroEiMOJPm8) — LiveOverflow | 09:03 | 01:00–08:00 | Watch first |
| 5 | [MFTECmd / Timeline Explorer](https://www.youtube.com/watch?v=_qElVZJqlGY) — 13Cubed | 22:01 | 00:00–05:55, 10:33–20:50 | Watch first |
| 6 | [Volatility 3](https://www.youtube.com/watch?v=Uk3DEgY5Ue8) — DFIRScience | 32:00 | 05:50–19:30, 20:00–23:30, 24:30–30:20 | Watch first |
| 7 | [RSA with Python / Sage](https://www.youtube.com/watch?v=20K1ctFzu2Y) — Almond Force | 05:44 | 00:35–05:05 | Optional theory refresher |
| 8 | [Audio stego / Sonic Visualiser / ExifTool](https://www.youtube.com/watch?v=pJYyyz6HPbQ) — John Hammond | 09:29 | 00:45–02:15, 04:30–08:10 | Optional; lowest priority |

## 1. Burp Repeater

[How to resend individual requests with Burp Repeater](https://www.youtube.com/watch?v=_Wifm2g9ugg)

A focused request-edit-send-compare demonstration, including response history, redirects and reusable tabs. Directly useful for manual web challenges.

**Caveat:** Older UI; use Community manual features. The included local HTTP worksheet provides a target.

[Timestamped caption text](transcripts/_Wifm2g9ugg.md) · [Original selected captions](captions/_Wifm2g9ugg.en-orig.vtt)


## 2. CyberChef

[Cryptography   Lab 5   Cooking with the Cyberchef](https://www.youtube.com/watch?v=UtqmiI7k9lU)

Shows recipe ordering, reversible transformations, Magic suggestions and a layered deobfuscation workflow. More instructive than a list of operations.

**Caveat:** The second example uses a course-provided file; watch the reasoning or recreate your own data. Encoding heuristics are clues, not proof.

[Timestamped caption text](transcripts/UtqmiI7k9lU.md) · [Original selected captions](captions/UtqmiI7k9lU.en-orig.vtt)


## 3. Ghidra

[Ghidra quickstart & tutorial: Solving a simple crackme](https://www.youtube.com/watch?v=fTGTnrgjuGA)

Shows import/analysis, the decompiler, correcting function types, renaming, comments and recovering a simple input condition. Strong first-tool walkthrough.

**Caveat:** 2019 interface. Skip the historical scrolling patch; use the bundled benign C program for practice.

[Timestamped caption text](transcripts/fTGTnrgjuGA.md) · [Original selected captions](captions/fTGTnrgjuGA.en-orig.vtt)


## 4. GDB / control flow

[Reversing and Cracking first simple Program - bin 0x05](https://www.youtube.com/watch?v=VroEiMOJPm8)

Builds a control-flow sketch, uses breakpoints and instruction stepping, then tests the comparison by changing a register. Strong reasoning complement to Ghidra.

**Caveat:** Addresses are example-specific. Hopper/IDA appear only as comparisons, not required approved tools. Creator caption track runs beyond the video; use the saved automatic track.

[Timestamped caption text](transcripts/VroEiMOJPm8.md) · [Original selected captions](captions/VroEiMOJPm8.en-orig.vtt)


## 5. MFTECmd / Timeline Explorer

[Introduction to MFTECmd - NTFS MFT and Journal Forensics](https://www.youtube.com/watch?v=_qElVZJqlGY)

Connects MFT/journal concepts to CSV parsing, timestamp interpretation and tracing a file through renames and deletion. Especially relevant to the forensic worksheet.

**Caveat:** Skip 06:00–10:30 KAPE acquisition: that separate tool is not added to approval. Historical lack of $LogFile support is outdated; group by entry and sequence to avoid reuse confusion.

[Timestamped caption text](transcripts/_qElVZJqlGY.md) · [Original selected captions](captions/_qElVZJqlGY.en-orig.vtt)


## 6. Volatility 3

[Introduction to Memory Forensics with Volatility 3](https://www.youtube.com/watch?v=Uk3DEgY5Ue8)

A substantial process→handles→file extraction investigation, followed by command lines, network relationships and registry artifacts. Best breadth among the selected memory videos.

**Caveat:** Skip old installation steps. Commands in automatic captions are unreliable; verify current plugin spelling/help. IP/name correlations are leads, not attribution proof.

[Timestamped caption text](transcripts/Uk3DEgY5Ue8.md) · [Original selected captions](captions/Uk3DEgY5Ue8.en-orig.vtt)


## 7. RSA with Python / Sage

[CTFlearn: RSA Beginner](https://www.youtube.com/watch?v=20K1ctFzu2Y)

Explains factoring a weak modulus, totient, modular inverse, decryption and byte conversion. Useful when rusty on the math.

**Caveat:** Not a demonstration of RsaCtfTool. Uses online SageCell; use the bundled local toy example instead of uploading event data.

[Timestamped caption text](transcripts/20K1ctFzu2Y.md) · [Original selected captions](captions/20K1ctFzu2Y.en-orig.vtt)


## 8. Audio stego / Sonic Visualiser / ExifTool

[MORSE CODE Steganography (2/2) BsidesCT CTF 2018](https://www.youtube.com/watch?v=pJYyyz6HPbQ)

Shows correcting an initial audio hypothesis and using metadata, then recognizing layered encodings. Useful as a thought-process example.

**Caveat:** Most decoding uses online services and exploratory detours. Not a focused Sonic Visualiser tutorial or a directly reproducible offline workflow; skip the outro.

[Timestamped caption text](transcripts/pJYyyz6HPbQ.md) · [Original selected captions](captions/pJYyyz6HPbQ.en-orig.vtt)

## Files and delivery

**All eight MP4s are saved locally: 706,460,852 bytes (706 MB / 674 MiB), plus English VTT subtitles.** Video and audio streams, durations and three short decoded samples per file passed verification. This is not full end-to-end viewing. [Open the playlist](videos/watch-order.m3u).

| Order | MP4 | Resolution | Video codec |
| --- | --- | --- | --- |
| 1 | [Burp Repeater](videos/01_Burp_Repeater__Wifm2g9ugg.mp4) | 1920 × 1080 | h264 |
| 2 | [CyberChef](videos/02_CyberChef_UtqmiI7k9lU.mp4) | 1920 × 1080 | h264 |
| 3 | [Ghidra](videos/03_Ghidra_fTGTnrgjuGA.mp4) | 2880 × 1800 | av1 |
| 4 | [GDB / control flow](videos/04_GDB_VroEiMOJPm8.mp4) | 1920 × 1080 | h264 |
| 5 | [MFTECmd / Timeline Explorer](videos/05_MFTECmd__qElVZJqlGY.mp4) | 3840 × 2160 | av1 |
| 6 | [Volatility 3](videos/06_Volatility3_Uk3DEgY5Ue8.mp4) | 1920 × 1080 | av1 |
| 7 | [RSA with Python / Sage](videos/07_OPTIONAL_RSA_20K1ctFzu2Y.mp4) | 2560 × 1440 | vp9 |
| 8 | [Audio stego / Sonic Visualiser / ExifTool](videos/08_OPTIONAL_Audio_Stego_pJYyyz6HPbQ.mp4) | 1920 × 1080 | h264 |

All audio streams are AAC. Original high-resolution video codecs were retained: some files use AV1/VP9, so MP4 container support alone does not guarantee playback on every device. Target-device playback and Instagram compatibility were not tested. See `media-verification.json` for the exact checks.

For transfer, copy this `video-pack` folder (or just `videos/` plus this list). Captions and transcripts are included; the original broader guide links below point outside this folder.

The compiled list was delivered to the configured Hermes Telegram home target (successful receipt saved locally). Instagram is not configured, so the videos remain local for transfer. No passwords or bot tokens were read or copied.

The LiveOverflow creator track extends past the actual runtime; the automatic track is used instead. This is why raw captions and metadata are retained rather than treating a transcript title as enough evidence.

The underlying [24-hour guide](../../../LEARNING_RESOURCES.md) and [practice worksheets](../../../PRACTICE_WORKSHEETS.md) remain the learning path. Videos supplement them; they do not expand organiser approval.
