# Tool instruction catalog

Use the [prioritized collection](TOOL_LEARNING_COLLECTION.md) to choose a workflow. These entries are alternatives and depth options, not a mandate to complete every lesson. Exact approval/platform/version details remain in the [200-row matrix](TOOL_COVERAGE_MATRIX.md).

Depth labels describe the selected content: **intro** = orientation/simple example; **workflow** = input→operations→interpretation/checks; **deep** = several nontrivial cases or mechanisms; **targeted** = a bounded operation or interpretation, not a complete workflow. Neither caption inspection nor reading establishes proficiency.

<a id="media-1"></a>

## zsteg: detection and extraction examples

[Open resource](https://github.com/zed-0xff/zsteg) · guide · workflow

**Approved rows:** windows-12. **Learn:** Refresh PNG/BMP LSB scanning, channel/bit-order selection, and extracting a specific candidate with -E. Read Usage and Examples; distinguish candidate signatures from validated payloads.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Only PNG/BMP techniques shown; validate extracted files and do not trust every file signature.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save the page with images or print to PDF before flying; local tools and any practice files must already be available.

<a id="media-2"></a>

## Binwalk: file analysis and extraction

[Open resource](https://github.com/ReFirmLabs/binwalk/wiki/File-Analysis-and-Extraction) · guide · targeted

**Approved rows:** windows-13. **Learn:** Refresh scan, extraction and recursive extraction; interpret confidence rather than trusting every signature. Use installed help to confirm major-version options.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Save the page with images or print to PDF before flying; local tools and any practice files must already be available. Extraction also depends on locally installed helper programs.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save the page with images or print to PDF before flying; local tools and any practice files must already be available. Extraction also depends on locally installed helper programs.

<a id="media-3"></a>

## ExifTool: application documentation and reading examples

[Open resource](https://exiftool.org/exiftool_pod.html#READING-EXAMPLES) · guide · targeted

**Approved rows:** windows-14. **Learn:** Refresh metadata reading syntax and the distinction between reading and assignment-based writing; skim Reading Examples and retain a local copy for tag lookup.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Save the page with images or print to PDF before flying; local tools and any practice files must already be available.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save the page with images or print to PDF before flying; local tools and any practice files must already be available.

<a id="media-4"></a>

## Stegseek: wordlist mode, seed mode and steghide compatibility

[Open resource](https://github.com/RickdeJager/stegseek) · guide · workflow

**Approved rows:** kali-134, kali-135. **Learn:** Refresh wordlist extraction versus seed detection. Seed mode can recover an unencrypted payload; it does not generally bypass encryption. Compare steghide command syntax with stegseek --command syntax.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Seed mode is not universal encrypted-payload recovery; failed wordlist does not prove no content.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save the page with images or print to PDF before flying; local tools and any practice files must already be available. Save any intended wordlist beforehand; no wordlist or binaries downloaded here.

<a id="media-5"></a>

## Audacity: Spectrogram View

[Open resource](https://manual.audacityteam.org/man/spectrogram_view.html) · guide · workflow

**Approved rows:** kali-10. **Learn:** Refresh switching from waveform to spectrogram, frequency limits, gain/range, and window size. Understand the time-versus-frequency resolution tradeoff before interpreting a blank or blurred image.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Teaches spectral inspection rather than a full CTF solve. Use own known tone/click sample to verify settings and preserve original audio.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save the page with images or print to PDF before flying; local tools and any practice files must already be available.

<a id="media-6"></a>

## FFmpeg: stream selection and streamcopy

[Open resource](https://ffmpeg.org/ffmpeg.html) · guide · targeted

**Approved rows:** kali-40. **Learn:** Skim Description, Streamcopy and Stream selection. Refresh input/output option ordering and explicit -map selection so an audio or secondary stream is not missed during media extraction.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Save the page with images or print to PDF before flying; local tools and any practice files must already be available. Check available codecs and installed help before departure.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save the page with images or print to PDF before flying; local tools and any practice files must already be available. Check available codecs and installed help before departure.

<a id="media-7"></a>

## AperiSolve: local deployment and analyzer overview

[Open resource](https://github.com/Zeecka/AperiSolve) · guide · targeted

**Approved rows:** kali-7. **Learn:** Recognize which individual tools and bit-layer views the platform combines. Read Key features and Quick start to understand local operation; direct tools remain useful when a deployment is unavailable.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Save README. Offline use requires an already working local deployment and dependencies; a git checkout alone is insufficient. Never upload event challenge files to the public service.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save README. Offline use requires an already working local deployment and dependencies; a git checkout alone is insufficient. Never upload event challenge files to the public service.

<a id="media-8"></a>

## MORSE CODE Steganography (2/2) BsidesCT CTF 2018

[Open resource](https://www.youtube.com/watch?v=pJYyyz6HPbQ) · video · workflow

**Approved rows:** kali-128, windows-14. **Learn:** Watch an audio investigation using Sonic Visualiser and ExifTool to distinguish tone timing from other encodings; note how metadata redirects the investigation. Skim the later encoding detour if familiar.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Use YouTube-supported offline saving where available and test playback before flying. The walkthrough uses online decoders: retain the reasoning, but do not copy challenge-file uploads at this event.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Use YouTube-supported offline saving where available and test playback before flying. The walkthrough uses online decoders: retain the reasoning, but do not copy challenge-file uploads at this event.; free_reading_alternative: https://www.sonicvisualiser.org/doc/reference/5.2.1/en/; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 9:29; selected 0:45–2:15, 4:30–8:10. Role: optional_refresher. Full length includes skipped material.

<a id="web-network-5"></a>

## Wireshark: display filters and following protocol streams

[Open resource](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html) · guide · targeted

**Approved rows:** windows-2. **Learn:** Refresh protocol/field filters, equality and logical operators; then follow a stream and inspect each direction using the linked official stream guide.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Save display-filter guide and https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html with figures. Free text; no account. Saved-PCAP practice requires an installed Wireshark and downloaded sample.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save display-filter guide and https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html with figures. Free text; no account. Saved-PCAP practice requires an installed Wireshark and downloaded sample.

<a id="web-network-6"></a>

## TShark manual: saved captures and display filters

[Open resource](https://www.wireshark.org/docs/man-pages/tshark.html) · guide · targeted

**Approved rows:** windows-36. **Learn:** Focus on -r to read a PCAP, -Y for Wireshark display filters and -T fields/-e for repeatable field extraction. Distinguish display filters from capture filters.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Do not apply capture-filter syntax as display-filter syntax. SavedPCAP exercise does not prove livecapture privileges.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save manual and sample PCAP; run locally after checking TShark is installed. No live network needed for saved-capture analysis.

<a id="web-network-7"></a>

## Zeek quick start: turn a PCAP into correlated logs

[Open resource](https://docs.zeek.org/en/current/quickstart.html) · practice · workflow

**Approved rows:** windows-18. **Learn:** Use the supplied quickstart.pcap to produce conn.log, http.log and weird.log, then correlate them by uid. Stop before the live-traffic section for airplane practice.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Save the guide and linked quickstart.pcap in advance; verify Zeek in WSL and local analysis before departure. The live-traffic exercise uses external HTTP and is not flight practice.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save the guide and linked quickstart.pcap in advance; verify Zeek in WSL and local analysis before departure. The live-traffic exercise uses external HTTP and is not flight practice.

<a id="web-network-8"></a>

## Wireshark http.cap: match one HTTP request to its response

[Open resource](https://wiki.wireshark.org/SampleCaptures#hypertext-transport-protocol-http) · practice · workflow

**Approved rows:** windows-2, windows-36. **Learn:** Use the named http.cap sample, not the whole catalog: find a request, record endpoints/method/host/URI, follow its TCP stream, identify response status, and reproduce selected fields with TShark. Optional transfer exercise after the bundled synthetic capture; no download is required for the core block.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Save http.cap from https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap plus official filter/stream pages before travel. No account or lab server is required. Artifact was not downloaded or executed during this review.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save http.cap from https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap plus official filter/stream pages before travel. No account or lab server is required. Artifact was not downloaded or executed during this review.

<a id="forensics-1"></a>

## Sleuth Kit: list files and recover by metadata address

[Open resource](https://www.sleuthkit.org/sleuthkit/man/fls.html) · guide · targeted

**Approved rows:** windows-23. **Learn:** Use mmls to identify a filesystem start sector, pass that sector to fls -o, and pass a discovered metadata address to icat -o. Distinguish a sector offset from a byte offset.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Save fls plus https://www.sleuthkit.org/sleuthkit/man/mmls.html and https://www.sleuthkit.org/sleuthkit/man/icat.html . The supplied paper drill needs no disk image. Executing requires an installed Sleuth Kit and a separately staged compatible image.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save fls plus https://www.sleuthkit.org/sleuthkit/man/mmls.html and https://www.sleuthkit.org/sleuthkit/man/icat.html . The supplied paper drill needs no disk image. Executing requires an installed Sleuth Kit and a separately staged compatible image.

<a id="forensics-2"></a>

## Autopsy Quick Start Guide

[Open resource](https://www.sleuthkit.org/autopsy/docs/user-docs/4.22.0/quick_start_guide.html) · guide · workflow

**Approved rows:** windows-34. **Learn:** Choose image versus logical source; Select ingest modules intentionally; Search keywords and inspect text hex and images; Pivot hits to original directory; Extract results; Open timelines and interpret partial ingest results

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Create a case from a prepared image or harmless logical-file folder; choose ingest deliberately, pivot a keyword hit to its original location, and compare an exported known file with its original. Reading/GUI execution are separate.

**Limits:** Save the 4.22.0 guide with screenshots. The required recall exercise uses no image; optional hands-on work can use a newly created folder of harmless text files as a logical data source. Installed Autopsy and sufficient local case storage are required for execution.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save the 4.22.0 guide with screenshots. The required recall exercise uses no image; optional hands-on work can use a newly created folder of harmless text files as a logical data source. Installed Autopsy and sufficient local case storage are required for execution.

<a id="forensics-3"></a>

## Volatility 3: Windows Tutorial

[Open resource](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html) · guide · workflow

**Approved rows:** windows-31. **Learn:** Understand plugin syntax and compare pslist with pstree to reconstruct processes and parent-child relationships in a Windows memory dump.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Introductory plugin walkthrough; preserve symbol/network prerequisites; deep anomaly interpretation remains further study.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save the page. Stage the memory image and resolve its symbols while online, then test the chosen commands offline: Windows symbol files may otherwise require Microsoft downloads. Volatility does not acquire memory.

<a id="forensics-4"></a>

## Introduction to Memory Forensics with Volatility 3

[Open resource](https://www.youtube.com/watch?v=Uk3DEgY5Ue8) · video · workflow

**Approved rows:** windows-31. **Learn:** See the workflow from memory information to processes, handles, connections, extracted files and registry artifacts; use the official Windows tutorial for current command spelling.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Save using a permitted platform offline feature and confirm playback before departure; availability can depend on account and region. Save the companion notes at https://dfir.science/2022/02/Introduction-to-Memory-Forensics-with-Volatility-3 . Its practice-image link is optional and was not downloaded or tested.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save using a permitted platform offline feature and confirm playback before departure; availability can depend on account and region. Save the companion notes at https://dfir.science/2022/02/Introduction-to-Memory-Forensics-with-Volatility-3 . Its practice-image link is optional and was not downloaded or tested.; free_reading_alternative: https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 32:00; selected 5:50–19:30, 20:00–23:30, 24:30–30:20. Role: retained_narrow_workflow. Full length includes skipped material.

<a id="forensics-5"></a>

## Introduction to MFTECmd - NTFS MFT and Journal Forensics

[Open resource](https://www.youtube.com/watch?v=_qElVZJqlGY) · video · workflow

**Approved rows:** windows-39. **Learn:** Learn what $MFT and $UsnJrnl can reveal about file creation, deletion and renaming; follow MFTECmd CSV parsing at 10:33 and Timeline Explorer analysis at 13:00.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Save through a permitted platform offline feature and check playback. For practice, bring already extracted $MFT/$J files and the required Zimmerman tools/runtime. Skip the 06:00 KAPE acquisition chapter unless that separate tool is independently confirmed approved.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save through a permitted platform offline feature and check playback. For practice, bring already extracted $MFT/$J files and the required Zimmerman tools/runtime. Skip the 06:00 KAPE acquisition chapter unless that separate tool is independently confirmed approved.; free_reading_alternative: https://github.com/EricZimmerman/MFTECmd; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 22:01; selected 0:00–5:55, 10:33–20:50. Role: retained_narrow_workflow. Full length includes skipped material.

<a id="forensics-6"></a>

## qpdf: PDF inspection options

[Open resource](https://qpdf.readthedocs.io/en/stable/cli.html#pdf-inspection) · guide · targeted

**Approved rows:** windows-26. **Learn:** Move beyond visible page text: inspect PDF objects and attachments, distinguish compressed stream bytes from decoded stream data, and recognize the inspection-mode invocation.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Syntax and interpretation are covered; worked document case supplied separately by reverse lane. Valid syntax does not establish harmless content; normal rewrites remove orphaned objects.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save the PDF Inspection section. Hands-on use needs installed qpdf and local sample PDFs; retain original files and use inspection operations. Unsupported stream filters may prevent decoding.

<a id="forensics-7"></a>

## Chainsaw: searching and hunting Windows event logs

[Open resource](https://github.com/WithSecureOpenSource/chainsaw#examples) · guide · workflow

**Approved rows:** kali-20. **Learn:** Search EVTX files by string or event field, then compare those results with Sigma-based hunting using a mapping file and time filters. Start with search before loading a large ruleset.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** README search prose mistypes4014; actual command uses correct4104. Rules need supplied mappings. Detections require review; not proof by label. No event sample was executed.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save README examples and, for a local exercise, stage a small EVTX set plus matching rules and mapping files. Check the installed 2.16.5 help against the current README. No hosted backend is needed for the documented local-file workflow.

<a id="forensics-8"></a>

## SQLite command-line shell: inspect schema and records

[Open resource](https://sqlite.org/cli.html) · guide · workflow

**Approved rows:** kali-131. **Learn:** Read Getting Started, dot-commands, output formats and Querying the database schema; use .tables and .schema before querying an unfamiliar artifact database.

**Prerequisites:** Approved tool and compatible local input; use the stated focus sections.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Do not use destructive .open --new on evidence. Timestamp epochs and WAL recovery need artifact-specific knowledge, not generic schema inspection.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public source. Save these sections, not the whole manual as a study assignment. Use a local copy of a database and preserve any supplied WAL/SHM companions. This is SQLite CLI instruction, not deleted-record recovery or SQLCipher decryption.

<a id="forensics-mmls"></a>

## TSK partition layout and sector units

[Open resource](https://www.sleuthkit.org/sleuthkit/man/mmls.html) · guide · targeted

**Approved rows:** windows-23. **Learn:** Choose image type and sector size; Read partition layout and unallocated ranges; Distinguish partition offset from filesystem metadata address

**Prerequisites:** Disk image and worksheet3.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** A reference plus exact examples, not an end-to-end disk case. Pair existing fls/icat resources and worksheet.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public reading; no account required; page can be saved for offline reference.

<a id="forensics-pecmd"></a>

## PECmd input selection and exports

[Open resource](https://github.com/EricZimmerman/PECmd) · guide · targeted

**Approved rows:** windows-39. **Learn:** Choose individual prefetch versus recursive directory; Export CSV and JSON; Inspect compressed Windows prefetch bytes; Interpret optional VSS/ADS platform limitations

**Prerequisites:** Prefetch files and artifact interpretation from 13Cubed Windows lesson.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Newer README options may not exist in organiser build. Current docs are not evidence that --ads or .NET10 is installed; check local help. Prefetch theory in the 2017 video uses another tool: apply concepts using PECmd here.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public reading; no account required; page can be saved for offline reference.

<a id="forensics-jlecmd"></a>

## JLECmd current options companion

[Open resource](https://github.com/EricZimmerman/JLECmd) · guide · targeted

**Approved rows:** windows-39. **Learn:** Parse automatic/custom destinations; Export tabular records; Include detailed LNK fields; Extract contained LNKs for LECmd; Interpret application-ID mapping

**Prerequisites:** LNK/JumpList creator lesson and sample artifacts.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Use installed help; older video calls output TSV whereas current --csv is CSV. Do not infer file open intent from a single timestamp.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public reading; no account required; page can be saved for offline reference.

<a id="forensics-current-worksheets"></a>

## Local closed-note forensic and packet cases

[Open resource](PRACTICE_WORKSHEETS.md) · practice · workflow

**Approved rows:** windows-23, windows-39, windows-31, windows-2, windows-36, kali-131. **Learn:** Keep disk coordinates separate; Group NTFS journal identities correctly; Interpret memory facts without overclaiming; Query synthetic database; Reconstruct packet conversation

**Prerequisites:** Read relevant primary guide, then cover answers.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Synthetic teaching evidence, not a forensic disk or RAM capture. Disk/Autopsy/MFTECmd execution unperformed. Packet input and prior local checks are documented separately.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Local free reading; included http-demo.pcap is offline.

<a id="forensics-deeper-video-1"></a>

## SF19US - 22 Analyzing Windows malware traffic w/ Wireshark Part 1

[Open resource](https://www.youtube.com/watch?v=eQItiKZpuSc) · video · workflow

**Approved rows:** windows-2. **Learn:** Custom HTTP-host/TLS-SNI columns and display filters; DHCP/NetBIOS/Kerberos host and user identification; follow TCP stream to inspect LokiBot POST contents and deceptive HTTP404 replies; Azorult infection-chain analysis and executable recognition. This is a guided multi-PCAP workshop, not merely a tool tour.

**Prerequisites:** Basic tool familiarity and local practice material if following along.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** 2019 malware and UI examples; verify current field names.; PCAPs may contain real malware; static packet analysis only for study.; Does not teach TShark automation; that gap remains.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for public metadata/captions; video playback not tested.; offline: No additional video downloaded. Public streaming is distinct from offline-video availability; save the free reading alternative instead if needed.; free_reading_alternative: https://www.wireshark.org/docs/wsug_html_chunked/ChapterWork.html; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 1:28:53; selected 5:11–12:36, 25:11–30:59, 36:21–1:06:12, 1:09:46–1:28:53. Role: deeper_selected_sections. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](research/learning/video-coverage/candidates/eQItiKZpuSc.en-orig.vtt)

<a id="forensics-deeper-video-2"></a>

## Introduction to Windows Forensics

[Open resource](https://www.youtube.com/watch?v=VYROU-ZwZX8) · video · workflow

**Approved rows:** windows-39. **Learn:** Loads offline hives in Registry Explorer; explains MRUs, UserAssist and persistence locations; uses ShellBags Explorer to locate a deleted path; links USB serial numbers across SYSTEM and SOFTWARE hives, resolves active ControlSet via Select, maps volume identifiers and mount letter. These demonstrated correlations add real breadth beyond MFTECmd.

**Prerequisites:** Basic tool familiarity and local practice material if following along.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Use supplied/pre-extracted hives. Skip FTK Imager dependency mention03:30–03:40 and acquisition22:46–23:28; FTK is not approved by this matrix. Selected viewing also stops before overlapping LNK and unapproved NirSoft WinPrefetchView. Use approved PECmd reading for Prefetch parsing.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for public metadata/captions; video playback not tested.; offline: No additional video downloaded. Public streaming is distinct from offline-video availability; save the free reading alternative instead if needed.; free_reading_alternative: https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 1:04:33; selected 2:55–3:30, 3:40–22:46, 23:28–53:29. Role: deeper_selected_sections. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](research/learning/video-coverage/candidates/VYROU-ZwZX8.en-orig.vtt)

<a id="forensics-deeper-video-3"></a>

## LNK Files and Jump Lists

[Open resource](https://www.youtube.com/watch?v=wu4-nREmzGM) · video · workflow

**Approved rows:** windows-39, windows-14, kali-42. **Learn:** ExifTool reads LNK metadata, LECmd recursively exports records, then JLECmd and JumpListExplorer examine embedded streams. Distinguishes source and target timestamps, identifies volume serial and AppID; demonstrates metadata preserved after target deletion.

**Prerequisites:** Basic tool familiarity and local practice material if following along.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** 2018 interface and TSV export wording; current CLI is separate companion.; Other tools are mentioned: retain approved ExifTool and Zimmerman sections only.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for public metadata/captions; video playback not tested.; offline: No additional video downloaded. Public streaming is distinct from offline-video availability; save the free reading alternative instead if needed.; free_reading_alternative: https://github.com/EricZimmerman/JLECmd; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 26:59; selected 1:04–26:59. Role: deeper_selected_sections. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](research/learning/video-coverage/candidates/wu4-nREmzGM.en-orig.vtt)

<a id="forensics-artifact-interpretation"></a>

## Microsoft Incident Response: artifact facts, pitfalls and applications

[Open resource](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf) · guide · targeted

**Approved rows:** windows-39, kali-131. **Learn:** Separate Amcache/modern Shimcache presence from execution; Interpret cache position versus file modification timestamp; Recognize Amcache partial-file SHA1 limitation; Correlate Prefetch, ShellBags and browser records without overclaiming

**Prerequisites:** Registry and artifact parser workflows from selected lessons; a known OS version.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Conceptual reference, not CLI instruction. Read selected Amcache, Shimcache, Prefetch, ShellBags and browser pages, not the entire collection. Treat timing/rename interpretations as hypotheses to corroborate; no single artifact proves intent.

**Access/offline:** cost: Free public resource; no purchase made.; registration: No account used for inspected content; execution conditions below.; offline: Free public downloadable PDF; no account required.

<a id="reverse-depth-video-1"></a>

## HackadayU: Reverse Engineering with Ghidra Class 3

[Open resource](https://www.youtube.com/watch?v=RFG5FuqY0CE) · video · workflow

**Approved rows:** windows-22. **Learn:** Study the selected concepts in content_evidence; pause and explain the next analysis step before following the demonstration.

**Prerequisites:** Basic shell and binary/file-format awareness.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Substantive creator syllabus verified, not full transcript. Full runtime now verified against direct local YouTube metadata. Course calls itself introductory, but this session is materially deeper than the existing crackme. 2020 patch/export and debugger statements are historical; do not apply to current Ghidra.

**Access/offline:** cost: Free streaming; no account used for metadata retrieval.; offline: No additional video downloaded. Public streaming is distinct from offline-video availability; save the free reading alternative instead if needed.; playback: Not tested.; free_reading_alternative: https://wrongbaud.github.io/posts/ghidra-training/; registration: No account used for public metadata/captions; video playback not tested.; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 1:00:39; selected 8:03–51:02. Role: deeper_selected_sections. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](https://hackaday.io/course/172292/log/180316-class-3-video) · [Source 2](https://wrongbaud.github.io/posts/ghidra-training/) · [Source 3](research/learning/video-coverage/candidates/RFG5FuqY0CE.en-orig.vtt)

<a id="reverse-depth-video-2"></a>

## HackadayU: Reverse Engineering with Ghidra Class 4

[Open resource](https://www.youtube.com/watch?v=5QBXNF7FKxM) · video · workflow

**Approved rows:** windows-22. **Learn:** Study the selected concepts in content_evidence; pause and explain the next analysis step before following the demonstration.

**Prerequisites:** Basic shell and binary/file-format awareness.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Target sections to avoid setup overhead. Breadth beyond starter, not advanced mastery of all features. Old Eclipse/Jython setup may differ from current Ghidra; not a BinDiff demonstration.

**Access/offline:** cost: Free streaming; no account used for metadata retrieval.; offline: No additional video downloaded. Public streaming is distinct from offline-video availability; save the free reading alternative instead if needed.; playback: Not tested.; free_reading_alternative: https://wrongbaud.github.io/posts/ghidra-training/; registration: No account used for public metadata/captions; video playback not tested.; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 52:42; selected 3:14–25:39, 45:00–52:42. Role: deeper_selected_sections. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](https://wrongbaud.github.io/posts/ghidra-training/) · [Source 2](research/learning/video-coverage/candidates/5QBXNF7FKxM.en-orig.vtt)

<a id="reverse-depth-video-3"></a>

## Unpacking Redaman Malware & Basics of Self-Injection Packers - ft. OALabs

[Open resource](https://www.youtube.com/watch?v=YXnNO3TipvM) · video · workflow

**Approved rows:** windows-33. **Learn:** Study the selected concepts in content_evidence; pause and explain the next analysis step before following the demonstration.

**Prerequisites:** Basic shell and binary/file-format awareness.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Selected x64dbg demonstrations only. Exclude IDA Pro and PE-Bear sections; do not generalize the video’s A/W wrapper or packer-frequency claims. Input must already be the demonstrated stage; actual malware execution is not a required exercise.

**Access/offline:** cost: Free streaming; no account used for metadata retrieval.; offline: No additional video downloaded. Public streaming is distinct from offline-video availability; save the free reading alternative instead if needed.; playback: Not tested.; free_reading_alternative: https://liveoverflow.com/unpacking-buhtrap-malware-basics-of-self-injection-packers-ft-oalabs-2/; registration: No account used for public metadata/captions; video playback not tested.; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 26:18; selected 1:25–4:55, 5:45–10:02, 19:33–21:53. Role: deeper_selected_sections. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](https://liveoverflow.com/unpacking-buhtrap-malware-basics-of-self-injection-packers-ft-oalabs-2/) · [Source 2](research/learning/video-coverage/candidates/YXnNO3TipvM.en-orig.vtt)

<a id="reverse-depth-gdb"></a>

## GDB memory examination and watchpoint exercises

[Open resource](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Memory.html) · guide · workflow

**Approved rows:** windows-9. **Learn:** Interpret x/nfu sizes/formats; inspect stack and strings; correlate x/i with current PC; watch changing memory rather than guessing a code location.

**Prerequisites:** Basic shell and binary/file-format awareness.

**Practice/check:** Reuse research/learning/practice/check_input.c: compile with symbols, break main, inspect argv with x/s and byte format; explain the difference. On a benign local variable, set a dereferenced watchpoint and identify its changing instruction; do not reuse tutorial absolute addresses.

**Limits:** Reading inspected; commands and practice not executed.

**Access/offline:** cost: Free public reading; no account required for inspected pages.; offline: Save HTML with figures or source Markdown before travel; linked samples/VMs are separate and were not fetched.; verification: Substantive text fetched through Exa 2026-10-23.

**Read these companions:** [GDB watchpoints: syntax and hardware/software limits](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Set-Watchpoints.html) — watch versus rwatch/awatch; dereferenced addresses; expression scope and hardware limits.

<a id="reverse-depth-android"></a>

## Android App RE: JADX entry points, DEX logic and JNI

[Open resource](https://maddiestone.github.io/AndroidAppRE/) · guide · deep

**Approved rows:** kali-72, windows-22. **Learn:** Choose entry points from manifest/API usage; follow DEX data/control flow across components; identify native-library boundaries; reconstruct string deobfuscation.

**Prerequisites:** Java/C reading; native-library sections additionally require assembly.

**Practice/check:** Do exercises 1–3 then 7; write entry-point→sensitive-call evidence chain before viewing solutions. JNI section only if native methods appear. No exploitation of live devices is part of this study.

**Limits:** Static-only workshop; no dynamic instrumentation lesson. VM is historical Ubuntu 18.04, not a required install. Exercise 7 solution is Python 2 and needs syntax/integer-division adaptation for Python 3; inspect algorithm without executing malicious app.

**Access/offline:** cost: Free public reading; no account required for inspected pages.; offline: Save HTML with figures or source Markdown before travel; linked samples/VMs are separate and were not fetched.; verification: Substantive text fetched through Exa 2026-10-23.

<a id="reverse-depth-apktool"></a>

## Apktool 2.x: choose resource and DEX decoding modes

[Open resource](https://apktool.org/docs/2.x/cli-parameters/) · guide · targeted

**Approved rows:** kali-8. **Learn:** Use apktool d on an APK; distinguish skipping DEX disassembly with -s from preserving compiled resources with -r, and inspect the resulting artifacts alongside JADX.

**Prerequisites:** Basic shell and binary/file-format awareness.

**Practice/check:** For a benign APK or paper scenario, choose -s to skipDEX disassembly and -r to leavecompiledresources untouched. Explain why neither yields original Java source and why -f can delete existing output. Use the AndroidAppRE workflow for interpretation.

**Limits:** The organiser lists2.7.0-dirty. This2.x documentation includes later minor-version flags; use only the common d/-s/-r operations here and confirm installed help. The unversioned page now documents3.x. This is a supporting decoding operation, not a complete Android course or a guarantee of successful rebuild.

**Access/offline:** cost: Free public reading; no account required for inspected pages.; offline: Save HTML with figures or source Markdown before travel; linked samples/VMs are separate and were not fetched.; verification: DirectHTTP200 and substantive official2.x option text verified; no APK execution.

<a id="reverse-depth-dotnet"></a>

## AsyncRAT: trace settings and reconstruct configuration decoding

[Open resource](https://eln0ty.github.io/malware%20analysis/asyncRAT/) · guide · workflow

**Approved rows:** windows-38. **Learn:** Follow initialization to settings, reconstruct Base64→PBKDF2→AES-CBC data flow, distinguish HMAC/IV/ciphertext fields, compare recovered config with subsequent branches.

**Prerequisites:** Basic .NET methods/classes; use the linked dnSpyEx navigation reference for entry points, callers and debugger panes. Start with the supplied/already-unpacked assembly.

**Practice/check:** Without running malware, label inputs and output boundaries in the shown settings routine; explain which values control persistence and connection behavior. Pair with the linked dnSpyEx navigation reference. For a supplied/pre-extracted stage, the separate selected managed-memory lesson teaches a bounded dump workflow; arbitrary obfuscators still require case-specific analysis.

**Limits:** Use only Initialization through Config Decryption on an already-unpacked assembly or shown code. Online unpacker step is excluded by event rules. This is not a complete dnSpy debugger/unpacking course. Author extractor omits HMAC verification; treat output as hypothesis and compare code/structure. Do not adopt imprecise anti-analysis claims as Windows documentation.

**Access/offline:** cost: Free public reading; no account required for inspected pages.; offline: Save HTML with figures or source Markdown before travel; linked samples/VMs are separate and were not fetched.; verification: Substantive text fetched through Exa 2026-10-23.

**Read these companions:** [dnSpyEx navigation/debugger reference](https://github.com/dnSpyEx/dnSpy) — Entry points, callers, debugger panes and locals; no unavailable reverse-8 lesson prerequisite.

<a id="reverse-depth-python"></a>

## PyInstaller extraction to version-aware bytecode analysis

[Open resource](https://github.com/pyinstxtractor/pyinstxtractor-ng) · guide · workflow

**Approved rows:** kali-111, kali-110, kali-145. **Learn:** Read archive metadata and entry candidates; extract with approved pyinstxtractor-ng; read the linked worked output to distinguish bootstrap from application; choose pycdc/pycdas or uncompyle6 using their linked version/usage documentation, and preserve unsupported-opcode errors.

**Prerequisites:** Python source reading and shell basics.

**Practice/check:** Using an already-owned benign PyInstaller executable, record detected Python version and entry candidates, extract, compare recovered application logic with known behavior; record any unsupported opcode as unresolved rather than deleting it.

**Limits:** Use approved ng executable; upstream classic extractor is explanatory context only. Its matching-Python requirement does not apply to ng. pycdc goal of all-version support is not a guarantee; uncompyle6 runtime support is not bytecode support. Do not execute recovered files.

**Access/offline:** cost: Free public reading; no account required for inspected pages.; offline: Save HTML with figures or source Markdown before travel; linked samples/VMs are separate and were not fetched.; verification: Substantive text fetched through Exa 2026-10-23.

**Read these companions:** [pycdc / pycdas usage](https://github.com/zrax/pycdc) — Decompiler versus disassembler, stdout/stderr, raw marshal input needs explicit version. · [uncompyle6 bytecode compatibility and usage](https://github.com/rocky/python-uncompyle6) — Supported input bytecode1.0–3.8 is distinct from the interpreter that runs the tool. · [Worked extraction output and decompiler handoff](https://github.com/extremecoders-re/pyinstxtractor) — Read the printed Python36/bootstrap/test.pyc example only; use the approved ng extractor for execution, not the separate classic script.

<a id="reverse-depth-capa"></a>

## capa: interpret matches and test the evidence

[Open resource](https://github.com/mandiant/capa) · guide · workflow

**Approved rows:** kali-19. **Learn:** Compare default/-v/-vv, nested capability matches and evidence addresses; pivot to relevant functions in Ghidra; recognize packed/installer and wrapper-function false-negative limits.

**Prerequisites:** Basic shell and binary/file-format awareness.

**Practice/check:** Explain why each listed API supports the example shell capability, and one reason no-match does not prove absence. For a prepared sample, inspect the -vv address in Ghidra and confirm the control-flow relationship.

**Limits:** Use CLI and approved Ghidra only; ignore cloud/web upload and commercial backend paths. New options must be checked against installed capa 9.4.0.

**Access/offline:** cost: Free public reading; no account required for inspected pages.; offline: Save HTML with figures or source Markdown before travel; linked samples/VMs are separate and were not fetched.; verification: Substantive text fetched through Exa 2026-10-23.

<a id="reverse-depth-floss"></a>

## FLOSS: string categories, offsets and targeted decoding

[Open resource](https://github.com/mandiant/flare-floss/blob/master/doc/usage.md) · guide · workflow

**Approved rows:** kali-43. **Learn:** Separate static/stack/tight/decoded strings; select one type, inspect verbose function offsets, constrain decoding functions and choose sc32/sc64 when raw shellcode is known.

**Prerequisites:** Basic shell and binary/file-format awareness.

**Practice/check:** For prepared benign sample compare ordinary strings with FLOSS categories, then trace one recovered string address to the relevant decode function. Explain why changing minimum length can both remove noise and miss data.

**Limits:** Current upstream includes newer summary/tag/HTML features not assumed in approved build. Focus established default, types, -v, -n and function targeting, confirming local help. Strings are clues, not demonstrated execution.

**Access/offline:** cost: Free public reading; no account required for inspected pages.; offline: Save HTML with figures or source Markdown before travel; linked samples/VMs are separate and were not fetched.; verification: Substantive text fetched through Exa 2026-10-23.

<a id="reverse-depth-yara"></a>

## YARA rule semantics and positive/negative checks

[Open resource](https://yara.readthedocs.io/en/stable/writingrules.html) · guide · workflow

**Approved rows:** kali-157. **Learn:** Write text/hex patterns and conditions; choose nocase/wide only when encoding warrants it; constrain specificity and verify a near miss.

**Prerequisites:** Basic shell and binary/file-format awareness.

**Practice/check:** Use PRACTICE_WORKSHEETS.md YARA exercise and supplied positive/negative files; change one byte and explain resulting match. Add an unrelated benign negative before trusting a broader rule.

**Limits:** Stable docs version and installed 4.5.8 can differ; no execution performed here.

**Access/offline:** cost: Free public reading; no account required for inspected pages.; offline: Save HTML with figures or source Markdown before travel; linked samples/VMs are separate and were not fetched.; verification: Substantive text fetched through Exa 2026-10-23.

<a id="reverse-depth-documents"></a>

## Nested PDF→Office payload analysis

[Open resource](https://blog.didierstevens.com/2017/04/20/malicious-documents-the-matryoshka-edition/) · guide · workflow

**Approved rows:** kali-30. **Learn:** Triage /OpenAction /JavaScript /EmbeddedFile, select object and decompress stream, extract nested Office data, then inspect macros without launching document.

**Prerequisites:** Basic shell and binary/file-format awareness.

**Practice/check:** Before reading each next step, predict which object to inspect and why. Explain why keyword presence alone cannot prove maliciousness; distinguish stream extraction from execution.

**Limits:** Historical mitigation/UI descriptions are not current advice. Read analysis portion only; no active document opening. Commands using re-search are optional and its row approval must be checked separately.

**Access/offline:** cost: Free public reading; no account required for inspected pages.; offline: Save HTML with figures or source Markdown before travel; linked samples/VMs are separate and were not fetched.; verification: Substantive text fetched through Exa 2026-10-23.

<a id="reverse-depth-olevba"></a>

## olevba: extraction, decoded strings and triage interpretation

[Open resource](https://github.com/decalage2/oletools/wiki/olevba) · guide · workflow

**Approved rows:** kali-98. **Learn:** Choose single-file detailed versus bulk triage output; read macro source, autoexec indicators and decoded strings; distinguish IOC/suspicious keyword from proof.

**Prerequisites:** Basic shell and binary/file-format awareness.

**Practice/check:** Explain differences among Normal_Document.doc, Normal_Document_Macro.doc and suspicious flags in example output. Given extracted benign VBA text, predict strings before running --decode; do not open unknown Office documents.

**Limits:** Docs contain historical API examples and inconsistent old encrypted-document wording; use modern CLI section and verify installed help. Not every oletools subcommand is covered.

**Access/offline:** cost: Free public reading; no account required for inspected pages.; offline: Save HTML with figures or source Markdown before travel; linked samples/VMs are separate and were not fetched.; verification: Substantive text fetched through Exa 2026-10-23.

<a id="reverse-depth-upx"></a>

## UPX list, test and decompress boundaries

[Open resource](https://github.com/upx/upx/blob/devel/doc/upx-doc.txt) · guide · workflow

**Approved rows:** kali-149. **Learn:** Use -l/-t/-d and explicit output/backup; distinguish decompression integrity from malware verdict.

**Prerequisites:** Basic shell and binary/file-format awareness.

**Practice/check:** On an already-owned benign UPX-packed executable, preserve original, list/test and decompress to another path; compare file properties and behavior with known source.

**Limits:** devel docs newer than approved 4.2.4. Parser security context matters; work in prepared lab. Modified/non-UPX packers require separate debugging.

**Access/offline:** cost: Free public reading; no account required for inspected pages.; offline: Save HTML with figures or source Markdown before travel; linked samples/VMs are separate and were not fetched.; verification: Substantive text fetched through Exa 2026-10-23.

<a id="reverse-depth-die"></a>

## Detect It Easy CLI: file identity, entropy and heuristic comparison

[Open resource](https://www.kali.org/tools/detect-it-easy/) · guide · workflow

**Approved rows:** kali-27. **Learn:** Run diec target; use -i for file information, -e for entropy, -j for JSON and -u for heuristic scan; corroborate format/architecture against binary headers before choosing a reversing workflow.

**Prerequisites:** Basic shell and binary/file-format awareness.

**Practice/check:** Choose an already-owned benign executable. Compare diec target, diec -i target, diec -e target, diec -j target and diec -u target. Record type/architecture and compare with objdump/header inspection. Explain any heuristic difference; do not label a file malicious solely because it is packed or high entropy.

**Limits:** Official Kali page documents diec 3.21; approval does not guarantee this version or working installation. Check installed --help. Signature/heuristic hits and high entropy are investigative leads, not malware proof. No separate GUI course is required for this triage capability.

**Access/offline:** cost: Free public reading; no account required for inspected pages.; offline: Save HTML with figures or source Markdown before travel; linked samples/VMs are separate and were not fetched.; verification: Substantive text fetched through Exa 2026-10-23.

**Supporting sources/checks:** [Source 1](https://github.com/horsicq/Detect-It-Easy)

<a id="reverse-depth-dotnet-dynamic"></a>

## Malware Analysis - Unpacking NetWiredRC With DnSpy

[Open resource](https://www.youtube.com/watch?v=dLIbkg_8O68) · video · workflow

**Approved rows:** windows-38. **Learn:** Trace a managed decrypt-to-Assembly.Load path; break after decryption, inspect Locals, show byte array in memory and save selected payload without executing the recovered stage.

**Prerequisites:** Supplied/pre-extracted managed stage, C# reading, basic dnSpyEx navigation, prepared isolated lab if practicing.

**Practice/check:** On a benign pre-existing managed loader, predict the point at which decoded bytes become available. Pause before loading the payload, inspect array length/header, and explain why successful byte dumping does not prove a valid or safe executable.

**Limits:** Only13:00–16:30 on a supplied/pre-extracted.NET stage. Skip PEStudio/PortEx/VisualStudio/de4dot steps. Use dnSpyEx cautiously with old dnSpy UI; never adopt the claim that disconnecting internet alone makes malware execution safe.

**Access/offline:** cost: Free streaming; no new account used for metadata/captions.; offline: No additional video downloaded. Public streaming is distinct from offline-video availability; save the free reading alternative instead if needed.; playback: Untested; metadata and captions inspected.; free_reading_alternative: https://docs.bepinex.dev/articles/advanced/debug/assemblies_dnSpy.html#using-dnspys-module-view; registration: No account used for public metadata/captions; video playback not tested.; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 27:05; selected 13:00–16:30. Role: deeper_selected_sections. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](research/learning/video-coverage/candidates/dLIbkg_8O68.en-orig.vtt)

<a id="reverse-depth-dotnet-modules"></a>

## dnSpy module view and module-load breakpoints

[Open resource](https://docs.bepinex.dev/articles/advanced/debug/assemblies_dnSpy.html#using-dnspys-module-view) · guide · workflow

**Approved rows:** windows-38. **Learn:** In debug mode open Debug > Windows > Modules; open an already-loaded module; use Module Breakpoints to pause on named module loading.

**Prerequisites:** An existing debug session with a benign managed process or prepared isolated lab.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Assign only Using dnSpy's module view. Do not follow BepInEx installation/configuration or Mono/game-specific setup. Module inspection is a useful free reading alternative but not a verbatim replacement for the byte-array dump demonstration.

**Access/offline:** cost: Free public reading without login.; offline: Save selected section with figures.; verification: Fetched substantive section through Exa 2026-10-23.

<a id="web-network-1"></a>

## Burp: reissue requests and investigate unexpected input

[Open resource](https://portswigger.net/burp/documentation/desktop/getting-started/reissuing-http-requests) · guide · workflow

**Approved rows:** windows-20. **Learn:** Move a request from Proxy history into Repeater; change one parameter, compare responses and recognize useful error disclosure. Follow the linked Proxy/scope prerequisites first.

**Prerequisites:** HTTP request/response basics; for execution, Burp Community, prepared browser proxy and reachable Academy lab.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Content inspected; local execution not performed.

**Access/offline:** viewing: Public text accessible without sign-in.; cost: Free reading.; registration: None for reading. Hosted Academy exercise requires a free account.; offline: Save substantive pages and figures, then verify with networking disabled; saving an index does not save its children. Hosted lab execution cannot run from saved HTML.; free_alternative_url: https://portswigger.net/burp/documentation/desktop/getting-started/reissuing-http-requests

**Supporting sources/checks:** [Source 1](https://portswigger.net/burp/communitydownload)

<a id="web-network-2"></a>

## How to resend individual requests with Burp Repeater

[Open resource](https://www.youtube.com/watch?v=_Wifm2g9ugg) · video · intro

**Approved rows:** windows-20. **Learn:** Short demonstration of the manual request-edit-send-compare loop, history, redirects and tabs. Pair with the current written tutorial because the 2020 interface differs.

**Prerequisites:** Basic HTTP; reading resource 1 is sufficient without playback.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Not watched; metadata runtime is distinct from study estimate.

**Access/offline:** viewing: Public YouTube page/transcript retrieved; playback not tested.; cost: Ordinary viewing is public; official desktop offline workflow requires paid YouTube Premium. No purchase needed for curriculum.; registration: No account created; download workflow requires signed-in Premium account.; offline: Free offline video entitlement not established; use free saved reading instead.; free_alternative_url: https://portswigger.net/burp/documentation/desktop/getting-started/reissuing-http-requests; free_reading_alternative: https://portswigger.net/burp/documentation/desktop/getting-started/reissuing-http-requests; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 6:30; selected 0:20–2:25, 4:15–6:20. Role: optional_refresher. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](https://support.google.com/youtube/answer/11977233)

<a id="web-network-3"></a>

## Everything curl: Command line HTTP

[Open resource](https://everything.curl.dev/http/) · guide · workflow

**Approved rows:** kali-23. **Learn:** Read the Customize headers and Cookies subsections: reproduce HTTP requests, replace headers and retain session state with a cookie jar. Useful when a browser hides request details.

**Prerequisites:** Know method, URL, headers and body; execution requires curl and a prepared target.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Content inspected; local execution not performed.

**Access/offline:** viewing: Public text accessible without sign-in.; cost: Free reading.; registration: None for reading.; offline: Save [Customize headers](https://everything.curl.dev/http/modify/headers.html), [Writing cookies](https://everything.curl.dev/http/cookies/writing.html), [Simple POST](https://everything.curl.dev/http/post/simple.html) and [Responses](https://everything.curl.dev/http/response.html) before departure. Reading works offline; HTTP execution needs a previously prepared local service.; free_alternative_url: https://everything.curl.dev/http/

**Supporting sources/checks:** [Source 1](https://everything.curl.dev/http/modify/headers.html) · [Source 2](https://everything.curl.dev/http/cookies/writing.html) · [Source 3](https://everything.curl.dev/http/post/simple.html) · [Source 4](https://everything.curl.dev/http/response.html)

<a id="web-network-4"></a>

## ffuf upstream examples: discovery, filters and bounded runs

[Open resource](https://github.com/ffuf/ffuf) · guide · workflow

**Approved rows:** kali-41, kali-126. **Learn:** Place FUZZ in a path, Host header or parameter; filter uninteresting sizes/statuses and bound runs. SecLists supplies candidate input, but learning response comparison matters more than collecting more wordlists.

**Prerequisites:** Complete manual-request work first; local wordlist and reachable target for execution.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Content inspected; local execution not performed.

**Access/offline:** viewing: Public text accessible without sign-in.; cost: Free reading.; registration: None for reading.; offline: Save substantive pages and figures, then verify with networking disabled; saving an index does not save its children.; free_alternative_url: https://github.com/ffuf/ffuf

**Supporting sources/checks:** [Source 1](https://github.com/ffuf/ffuf/wiki) · [Source 2](https://github.com/adamtlangley/ffufme)

<a id="web-network-9"></a>

## Nmap reference: interpret ports, services and saved results

[Open resource](https://nmap.org/book/man.html) · guide · workflow

**Approved rows:** kali-94. **Learn:** Read port states, service/version detection and output sections. Learn what open, closed and filtered do and do not establish before selecting a service-specific tool.

**Prerequisites:** Basic TCP ports; actual scanning requires a prepared authorized local target.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Content inspected; local execution not performed.

**Access/offline:** viewing: Public text accessible without sign-in.; cost: Free reading.; registration: None for reading.; offline: Save substantive pages and figures, then verify with networking disabled; saving an index does not save its children.; free_alternative_url: https://nmap.org/book/man.html

**Supporting sources/checks:** [Source 1](https://nmap.org/book/man-version-detection.html) · [Source 2](https://nmap.org/book/man-output.html)

<a id="crypto-foundations-1"></a>

## CyberChef: how recipes work and worked examples

[Open resource](https://github.com/gchq/CyberChef) · guide · workflow

**Approved rows:** windows-1. **Learn:** Learn the input/recipe/output workflow; follow Base64, hexdump, compression and nested-encoding examples. Start here before trying random operations.

**Prerequisites:** Comfort with encodings versus encryption; local CyberChef needed only for interactive practice.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** No installed-tool execution or full video playback; only the explicitly listed Python fixture checks were executed.

**Access/offline:** viewing: Public primary documentation fetched without authentication.; cost: Free reading; local software is free/open source for this selection.; registration: None for reading.; offline: Save selected text before departure. Reading a saved page is free; running examples also requires a working local tool and dependencies.; free_alternative_url: https://github.com/gchq/CyberChef

<a id="crypto-foundations-2"></a>

## Cryptography Lab 5: Cooking with the Cyberchef

[Open resource](https://www.youtube.com/watch?v=UtqmiI7k9lU) · video · intro

**Approved rows:** windows-1. **Learn:** A short visual introduction to reversible recipes, Base64, octal and a multi-step obfuscation exercise. The simple typed-text example can be recreated without the course.

**Prerequisites:** None beyond the CyberChef basics; later course lab file not supplied.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** No installed-tool execution or full video playback; only the explicitly listed Python fixture checks were executed.

**Access/offline:** viewing: Publicly accessible creator video; metadata/transcript inspected, playback not tested.; cost: Free streaming; desktop offline feature is paid YouTube Premium.; registration: No course registration needed for the selected viewing; signed-in Premium required for documented desktop downloads.; offline: Video offline availability for this exact item was not tested. Do not buy anything for this pack; use the linked free reading alternative and embedded exercise.; free_alternative_url: https://github.com/gchq/CyberChef; free_reading_alternative: https://github.com/gchq/CyberChef; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 7:17; selected 1:10–3:25, 3:25–6:35. Role: optional_refresher. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](https://support.google.com/youtube/answer/11977233)

<a id="crypto-foundations-3"></a>

## CTFlearn: RSA Beginner

[Open resource](https://www.youtube.com/watch?v=20K1ctFzu2Y) · video · intro

**Approved rows:** windows-7, kali-114, kali-125. **Learn:** Follow n, e and c through factorization, totient, modular inverse and Python byte conversion. This explains the prerequisites behind automated RSA tools.

**Prerequisites:** Integer arithmetic and Python pow; Sage optional for the tiny fixture.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** No installed-tool execution or full video playback; only the explicitly listed Python fixture checks were executed.

**Access/offline:** viewing: Publicly accessible creator video; metadata/transcript inspected, playback not tested.; cost: Free streaming; desktop offline feature is paid YouTube Premium.; registration: No course registration needed for the selected viewing; signed-in Premium required for documented desktop downloads.; offline: Video offline availability for this exact item was not tested. Do not buy anything for this pack; use the linked free reading alternative and embedded exercise.; free_alternative_url: https://doc.sagemath.org/html/en/tutorial/tour_numtheory.html; free_reading_alternative: https://doc.sagemath.org/html/en/tutorial/tour_numtheory.html; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 5:44; selected 0:35–5:05. Role: optional_refresher. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](https://support.google.com/youtube/answer/11977233)

<a id="crypto-foundations-4"></a>

## RsaCtfTool: usage and attack prerequisites

[Open resource](https://github.com/RsaCtfTool/RsaCtfTool) · guide · workflow

**Approved rows:** windows-30. **Learn:** Learn public-key inspection, selected attacks and decryption inputs; distinguish close-prime, small-exponent and shared-factor situations from unfactorable keys.

**Prerequisites:** Basic RSA n/e/c/p/q/phi/d; local Python 3.9+ and tool dependencies if executing; Sage only for supported attacks that need it.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** No installed-tool execution or full video playback; only the explicitly listed Python fixture checks were executed.

**Access/offline:** viewing: Public primary documentation fetched without authentication.; cost: Free reading; local software is free/open source for this selection.; registration: None for reading.; offline: Save selected text before departure. Reading a saved page is free; running examples also requires a working local tool and dependencies.; free_alternative_url: https://github.com/RsaCtfTool/RsaCtfTool

<a id="crypto-foundations-5"></a>

## SageMath tutorial: number theory

[Open resource](https://doc.sagemath.org/html/en/tutorial/tour_numtheory.html) · guide · workflow

**Approved rows:** kali-125. **Learn:** Work through modular rings, gcd, factor, inverse_mod and CRT examples. Compare Sage syntax with the provided Python equivalents.

**Prerequisites:** Modular arithmetic; local Sage for Sage commands. Python pow(...,-1,...) can cover the small RSA exercise without Sage.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** No installed-tool execution or full video playback; only the explicitly listed Python fixture checks were executed.

**Access/offline:** viewing: Public primary documentation fetched without authentication.; cost: Free reading; local software is free/open source for this selection.; registration: None for reading.; offline: Save selected text before departure. Reading a saved page is free; running examples also requires a working local tool and dependencies.; free_alternative_url: https://doc.sagemath.org/html/en/tutorial/tour_numtheory.html

<a id="crypto-foundations-6"></a>

## hashcat: dictionary attacks with a tiny wordlist

[Open resource](https://hashcat.net/wiki/doku.php?id=dictionary_attack) · guide · workflow

**Approved rows:** kali-59, kali-120. **Learn:** Read dictionary Description and the first command. Use -m 0 (raw MD5) with -a 0 and a three-word list; compare with -a 3 and a constrained mask. Use local help for installed-version flags; skip page suggestions for newer modes.

**Prerequisites:** Hash format identification; working hashcat backend for execution, otherwise use the Python known-answer fallback.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** No installed-tool execution or full video playback; only the explicitly listed Python fixture checks were executed.

**Access/offline:** viewing: Public primary documentation fetched without authentication.; cost: Free reading; local software is free/open source for this selection.; registration: None for reading.; offline: Save selected text before departure. Reading a saved page is free; running examples also requires a working local tool and dependencies.; free_alternative_url: https://hashcat.net/wiki/doku.php?id=dictionary_attack

<a id="crypto-foundations-7"></a>

## John the Ripper: usage examples

[Open resource](https://www.openwall.com/john/doc/EXAMPLES.shtml) · guide · workflow

**Approved rows:** kali-73, kali-120. **Learn:** Learn single mode, wordlist rules and --show; understand why selecting candidates matters more than immediately running exhaustive incremental search.

**Prerequisites:** John Jumbo for raw-md5; no real account files needed. Verify the local format is present before flight.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** No installed-tool execution or full video playback; only the explicitly listed Python fixture checks were executed.

**Access/offline:** viewing: Public primary documentation fetched without authentication.; cost: Free reading; local software is free/open source for this selection.; registration: None for reading.; offline: Save selected text before departure. Reading a saved page is free; running examples also requires a working local tool and dependencies.; free_alternative_url: https://www.openwall.com/john/doc/EXAMPLES.shtml

<a id="crypto-foundations-8"></a>

## bkcrack 1.8.1: stored-plaintext ZIP recovery

[Open resource](https://github.com/kimci86/bkcrack/blob/v1.8.1/example/tutorial.md) · practice · workflow

**Approved rows:** kali-13. **Learn:** Read archive metadata, stored-file known plaintext, internal-key recovery and password removal. Work from the printed metadata if the sample archive was not prepared.

**Prerequisites:** ZipCrypto versus AES; stored versus deflated members; local bkcrack 1.8.1 plus public example only if executing.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** No installed-tool execution or full video playback; only the explicitly listed Python fixture checks were executed.

**Access/offline:** viewing: Public primary documentation fetched without authentication.; cost: Free reading; local software is free/open source for this selection.; registration: None for reading.; offline: Save selected text before departure. Reading a saved page is free; running examples also requires a working local tool and dependencies.; free_alternative_url: https://github.com/kimci86/bkcrack/blob/v1.8.1/example/tutorial.md

<a id="web-depth-access"></a>

## Access control: concepts and request-level failure cases

[Open resource](https://portswigger.net/web-security/access-control) · guide · workflow

**Approved rows:** windows-20. **Learn:** Distinguish identity, session and authorization; test horizontal/vertical controls, method/header discrepancies and leakage before redirects.

**Prerequisites:** Basic HTTP and shell.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Community Proxy/Repeater suffices; skip Pro scanner prompts. Hosted labs need an account.

**Access/offline:** viewing: Public text fetched without login.; cost: Free reading.; registration: None for reading.; offline: Save substantive text; execution requires prepared tools and inputs.

<a id="web-depth-idor"></a>

## Burp lab: controlled ID parameter

[Open resource](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter) · practice · workflow

**Approved rows:** windows-20. **Learn:** Baseline own account request, send to Repeater, change ID, inspect another account response.

**Prerequisites:** Basic HTTP and shell.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Reading inspected; execution not performed.

**Access/offline:** viewing: Public lab instructions and complete solution.; cost: Free.; registration: Free Academy account required for hosted execution; none for reading.; offline: Saved solution remains readable; hosted target does not work offline.

<a id="web-depth-reset"></a>

## Burp lab: password reset broken logic

[Open resource](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic) · practice · workflow

**Approved rows:** windows-20. **Learn:** Trace reset workflow, remove token from URL and body, verify missing validation, change account parameter and verify resulting login.

**Prerequisites:** Basic HTTP and shell.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Reading inspected; execution not performed.

**Access/offline:** viewing: Public lab instructions and complete solution.; cost: Free.; registration: Free Academy account required for hosted execution; none for reading.; offline: Saved solution remains readable; hosted target does not work offline.

<a id="web-depth-sqlmap"></a>

## sqlmap request preservation and result comparison

[Open resource](https://github.com/sqlmapproject/sqlmap/wiki/Usage) · guide · workflow

**Approved rows:** kali-132. **Learn:** Load raw HTTP request with -r, retain cookies and POST body, constrain parameters, compare stable true/false markers, enumerate only relevant tables.

**Prerequisites:** Basic HTTP and shell.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Moving wiki includes newer options than approved version; retain stable -r/-p/--cookie/--string/--code workflow. Requires local deliberately vulnerable target; not executed.

**Access/offline:** viewing: Public text fetched without login.; cost: Free reading.; registration: None for reading.; offline: Save substantive text; execution requires prepared tools and inputs.

<a id="web-depth-jwt"></a>

## JWT testing methodology with jwt_tool and Burp

[Open resource](https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology) · guide · workflow

**Approved rows:** kali-77, windows-20. **Learn:** Establish repeatable token-bearing request; remove and corrupt token as controls; test expiry, tamper claims and evaluate weak-key prerequisites.

**Prerequisites:** Basic HTTP and shell.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Source loosely calls HMAC symmetric encryption: it is a MAC. Do not equate a changed page with conclusive signature validation; check auth outcomes and other credentials. Trigger: application uses JWT.

**Access/offline:** viewing: Public text fetched without login.; cost: Free reading.; registration: None for reading.; offline: Save substantive text; execution requires prepared tools and inputs.

<a id="crypto-depth-openssl"></a>

## OpenSSL 3 decryption parameters and validation

[Open resource](https://docs.openssl.org/3.0/man1/openssl-enc/) · guide · workflow

**Approved rows:** windows-24. **Learn:** Choose cipher, binary/Base64 handling, raw key+IV versus password/KDF, salt compatibility and output validation.

**Prerequisites:** Symmetric encryption basics and known encryption parameters.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** enc does not support GCM/CCM; valid padding is not proof of correct plaintext. Certificate/key inspection remains a separate conditional lookup.

**Access/offline:** viewing: Public text fetched without login.; cost: Free reading.; registration: None for reading.; offline: Save substantive text; execution requires prepared tools and inputs.

<a id="crypto-depth-rules"></a>

## Hashcat rule transformations and controlled candidate generation

[Open resource](https://hashcat.net/wiki/doku.php?id=rule_based_attack) · guide · workflow

**Approved rows:** kali-59, kali-120. **Learn:** Build candidate transformations, inspect expected output, distinguish rule syntax from regex and other cracking tools.

**Prerequisites:** Known hash format, tiny wordlist, existing hashcat workflow.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Moving documentation mentions newer modes; use stable -a 0 with -r supported by installed build. Do not assume John rules are interchangeable.

**Access/offline:** viewing: Public text fetched without login.; cost: Free reading.; registration: None for reading.; offline: Save substantive text; execution requires prepared tools and inputs.

<a id="crypto-depth-common-modulus"></a>

## RSA common-modulus prerequisites and derivation

[Open resource](https://cryptohack.gitbook.io/cryptobook/untitled/common-modulus-attack) · guide · workflow

**Approved rows:** kali-125, windows-7, kali-114. **Learn:** Recognize same plaintext/modulus under coprime exponents, use Bezout coefficients and handle negative exponents with modular inverse.

**Prerequisites:** RSA and extended Euclid; local Sage/Python.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Not a Sage CLI tutorial; pair with existing Sage number theory chapter. Source conditions assume a particular coefficient sign; whichever ciphertext needs inversion must be invertible.

**Access/offline:** viewing: Public text fetched without login.; cost: Free reading.; registration: None for reading.; offline: Save substantive text; execution requires prepared tools and inputs.

<a id="crypto-depth-recover-modulus"></a>

## RSA modulus recovery: gcd and ambiguity

[Open resource](https://cryptohack.gitbook.io/cryptobook/untitled/recovering-the-modulus) · guide · workflow

**Approved rows:** kali-125, windows-7, kali-114. **Learn:** Use known plaintext/ciphertext pairs; gcd differences; recognize extra common-factor ambiguity and need more pairs.

**Prerequisites:** RSA modular arithmetic and known pairs.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Python ints already have arbitrary precision; gmpy2 is optional for this concept. Large exact powers can consume resources; start with toy pairs.

**Access/offline:** viewing: Public text fetched without login.; cost: Free reading.; registration: None for reading.; offline: Save substantive text; execution requires prepared tools and inputs.

<a id="utility-depth-jq"></a>

## jq applied JSON filtering tutorial

[Open resource](https://jqlang.org/tutorial/) · guide · workflow

**Approved rows:** windows-21. **Learn:** Read JSON arrays, select nested fields, transform objects and distinguish streams from arrays.

**Prerequisites:** Basic shell and JSON.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Use saved generic JSON for offline study; external API availability unnecessary.

**Access/offline:** viewing: Public text fetched without login.; cost: Free reading.; registration: None for reading.; offline: Save substantive text; execution requires prepared tools and inputs.

<a id="utility-depth-python-io"></a>

## Python 3.11 binary files and JSON

[Open resource](https://docs.python.org/3.11/tutorial/inputoutput.html#reading-and-writing-files) · guide · workflow

**Approved rows:** windows-7, kali-114. **Learn:** Use binary file modes, with blocks, bounded reads, seek and JSON serialization.

**Prerequisites:** Basic Python values, loops and functions.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Selected 3.11 docs match Kali row; Windows latest3.x unspecified. This is applied IO instruction, not a full programming course.

**Access/offline:** viewing: Public text fetched without login.; cost: Free reading.; registration: None for reading.; offline: Save substantive text; execution requires prepared tools and inputs.

<a id="ref:kali-119"></a>

## ripgrep (rg): focused reference

[Open resource](https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md) · guide · workflow

**Approved rows:** kali-119. **Learn:** Literal and regex searches, scoped recursive search, ignored/hidden/binary file behavior and diagnosing missing hits.

**Prerequisites:** Use only when this tool or artifact is needed.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** Source sample uses historical0.7.1 tree; stable search concepts apply. Binary output may contain control bytes. No command execution.

**Access/offline:** viewing: Public text fetched without login.; cost: Free reading.; registration: None for reading.; offline: Save substantive text; execution requires prepared tools and inputs.

<a id="reverse-2"></a>

## Ghidra quickstart & tutorial: Solving a simple crackme

[Open resource](https://www.youtube.com/watch?v=fTGTnrgjuGA) · video · intro

**Approved rows:** windows-22. **Learn:** See a complete small password-check investigation: import, analysis, decompiler, function signatures and window navigation.

**Prerequisites:** Basic C expressions, argv and zero-based indexing.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** 2026-10-22: Exa retrieved the original video title, creator and transcript covering import, analysis and decompiler navigation. Published 2019; skip the historical scrolling-patch suggestion and expect changed UI. Not watched or executed; study_minutes is a planning estimate, not video runtime.

**Access/offline:** viewing: Public page retrieved without sign-in; video playback not tested.; cost: Free online viewing; computer offline video uses paid YouTube Premium where available.; registration: No sign-in used to inspect page; Premium downloads require signed-in account.; offline: Video download eligibility/playback unverified. Use the free reading/practice alternative, saved before flying.; free_alternative_url: https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html; free_reading_alternative: https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 11:30; selected 1:00–3:15, 6:00–11:25. Role: optional_refresher. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](https://support.google.com/youtube/answer/11977233?hl=en)

<a id="reverse-3"></a>

## Reversing and Cracking first simple Program — bin 0x05

[Open resource](https://www.youtube.com/watch?v=VroEiMOJPm8) · video · intro

**Approved rows:** windows-9. **Learn:** Connect C control flow to GDB disassembly using a tiny license-check example; pair the video with its source and annotated disassembly in reverse-4.

**Prerequisites:** Basic x86-64 registers, cmp/test and conditional branches; use guide notes if rusty.

**Practice/check:** Use the source worked example or the linked collection exercise; compare with its stated output.

**Limits:** 2026-10-22: Exa fetched the original YouTube title/date; full primary-page transcript was unavailable, and web fallback failed. Inspected the creator repository and raw C/disassembly to verify the exercise and plain-GDB basis. Video content itself was not fully independently inspected. Not watched or executed; study_minutes is a planning estimate, not video runtime.

**Access/offline:** viewing: Public page retrieved without sign-in; video playback not tested.; cost: Free online viewing; computer offline video uses paid YouTube Premium where available.; registration: No sign-in used to inspect page; Premium downloads require signed-in account.; offline: Video download eligibility/playback unverified. Use the free reading/practice alternative, saved before flying.; free_alternative_url: https://github.com/LiveOverflow/liveoverflow_youtube/tree/master/0x05_simple_crackme_intro_assembler; free_reading_alternative: https://github.com/LiveOverflow/liveoverflow_youtube/tree/master/0x05_simple_crackme_intro_assembler; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 9:03; selected 1:00–8:00. Role: optional_refresher. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](https://raw.githubusercontent.com/LiveOverflow/liveoverflow_youtube/master/0x05_simple_crackme_intro_assembler/gdb_disassembly) · [Source 2](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Continuing-and-Stepping.html) · [Source 3](https://support.google.com/youtube/answer/11977233?hl=en)

<a id="video:_jz5qFWhLcg"></a>

## Broken Access Control | Complete Guide

[Open resource](https://www.youtube.com/watch?v=_jz5qFWhLcg) · video · workflow

**Approved rows:** windows-20. **Learn:** Exa fetched creator chapters and substantive transcript:02:25 identity/session/authorization distinction;22:50 finding;30:29 exploitation;34:40 mitigation. Theory complements manual labs; not itself a complete lab.

**Prerequisites:** Read the paired approved-tool guide; use existing benign/local or public exercise inputs.

**Practice/check:** Pause before the next analytical step and predict the result; verify against the lesson.

**Limits:** Full runtime and caption file now verified directly; no audiovisual playback claimed. Skip00:28–01:39 course promotion.

**Access/offline:** cost: Public video; no purchase or account used for metadata/captions.; offline: No additional video downloaded. Public streaming is distinct from offline-video availability; save the free reading alternative instead if needed.; free_reading_alternative: https://portswigger.net/web-security/access-control; registration: No account used for public metadata/captions; video playback not tested.; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 39:32; selected 2:25–34:40. Role: deeper_selected_sections. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](research/learning/video-coverage/candidates/_jz5qFWhLcg.en-orig.vtt)

<a id="video:XkLCEhEJuSI"></a>

## Password Cracking with Hashcat

[Open resource](https://www.youtube.com/watch?v=XkLCEhEJuSI) · video · workflow

**Approved rows:** kali-59, kali-120. **Learn:** Creator chapters03:00 setup;05:29 wordlist;15:45 rules;20:46 masks;27:52 benchmark. Transcript inspected includes self-created hash, mode diagnosis, --show, potfile behavior and failed simple-wordlist control before rules.

**Prerequisites:** Read the paired approved-tool guide; use existing benign/local or public exercise inputs.

**Practice/check:** Pause before the next analytical step and predict the result; verify against the lesson.

**Limits:** Skip installation and GPU comparison. Preserve existing potfiles; use isolated lab output. GPU performance is not a promise for organiser laptop. Full runtime now verified from direct metadata and original-English captions retrieved; no audiovisual playback claimed.

**Access/offline:** cost: Public video; no purchase or account used for metadata/captions.; offline: No additional video downloaded. Public streaming is distinct from offline-video availability; save the free reading alternative instead if needed.; free_reading_alternative: https://hashcat.net/wiki/doku.php?id=rule_based_attack; registration: No account used for public metadata/captions; video playback not tested.; offline_video_policy: Public streaming is not free offline access. YouTube documents computer downloads through a signed-in paid Premium account, subject to availability/reconnection limits; no purchase is needed for the linked free reading route. Target playback/download entitlement untested.

**Runtime:** full 30:39; selected 3:00–27:52. Role: deeper_selected_sections. Full length includes skipped material.

**Supporting sources/checks:** [Source 1](research/learning/video-coverage/candidates/XkLCEhEJuSI.en-orig.vtt)

<a id="practice:audio"></a>

## Resolve nearby tones in a known WAV

[Open resource](research/learning/video-coverage/practice/AUDIO_PRACTICE.md) · practice · workflow

**Approved rows:** kali-10. **Learn:** Select frequency/time windows and display range; Distinguish silence from an unhelpful display setting; Compare known frequencies with measured spectrum

**Prerequisites:** For execution, prepared Audacity; paper route and128KB WAV are bundled.

**Practice/check:** Complete the four-row frequency/time table and explain FFT bin spacing and time smearing.

**Limits:** Sample frequencies checked mathematically; Audacity GUI untested. This is spectral inspection, not SSTV decoding.

**Access/offline:** cost: Free local text and authored sample.; registration: None.; offline: All exercise inputs are bundled; save linked official pages separately.

**Supporting sources/checks:** [Source 1](https://manual.audacityteam.org/man/spectrogram_view.html) · [Source 2](research/learning/video-coverage/practice/audio-check.json)

<a id="practice:triage"></a>

## Strings, encodings and raw byte offsets

[Open resource](research/learning/video-coverage/practice/TRIAGE_PRACTICE.md) · practice · workflow

**Approved rows:** windows-11, windows-28. **Learn:** Scan full input and choose16-bitlittle-endian decoding; Locate printable evidence by byte offset; Check extracted text against bytes and avoid execution inference

**Prerequisites:** Prepared strings/xxd for execution; small binary and paper answers bundled.

**Practice/check:** Predict both messages and offsets; explain why default strings misses one.

**Limits:** GNU strings executed; no malware or file-semantic inference claimed.

**Access/offline:** cost: Free bundled exercise.; registration: None.; offline: All binary inputs and answers included.

**Supporting sources/checks:** [Source 1](https://sourceware.org/binutils/docs/binutils/strings.html) · [Source 2](research/learning/video-coverage/practice/triage-pdf-check.json)

<a id="practice:qpdf"></a>

## qpdf dictionary, raw stream and decoded stream

[Open resource](research/learning/video-coverage/practice/TRIAGE_PRACTICE.md#qpdf-a-rendered-page-is-only-one-view) · practice · workflow

**Approved rows:** windows-26. **Learn:** Follow a page to its content object; Choose dictionary versus raw/filtered stream output; Interpret compression and inspection limitations

**Prerequisites:** Prepared qpdf for execution; benign PDF and paper known answers bundled.

**Practice/check:** Choose the operation and predict object4 dictionary/decoded text; distinguish evidence from active content.

**Limits:** PDF structure/text/stream validated with existing pypdf; qpdf CLI not installed or executed. The Didier Stevens case is complementary, not a qpdf demonstration.

**Access/offline:** cost: Free local exercise.; registration: None.; offline: PDF and answers bundled; official documentation must be saved separately.

**Supporting sources/checks:** [Source 1](https://qpdf.readthedocs.io/en/stable/cli.html#pdf-inspection) · [Source 2](research/learning/video-coverage/practice/triage-pdf-check.json)

<a id="ghidra-training"></a>

## Ghidra training: reconstruct types and program structure

[Open resource](https://wrongbaud.github.io/posts/ghidra-training/) · guide · workflow

**Approved rows:** windows-22. **Learn:** C-to-assembly comparisons, structure padding, recovering/applying types and pattern searches.

**Prerequisites:** Basic C/pointers and prior Ghidra navigation.

**Practice/check:** Predict structure layout from accesses, apply a type and compare decompilation; check against instructor C examples.

**Limits:** Historical course; use current Ghidra docs for installation, scripting and patch-export UI.

**Access/offline:** cost: Free public reading.; registration: None used.; offline: Save article/images and selected source exercises; no paid video access required.

<a id="capability:nmap-bundle"></a>

## Nmap suite: discovery, Ncat byte streams and Nping probes

[Open resource](research/learning/video-coverage/practice/CAPABILITY_ROUTES.md#ncat-and-nping) · guide · workflow

**Approved rows:** kali-94. **Learn:** Distinguish discovery from client/listener communication and bounded packet/probe diagnosis; check a loopback Ncat exchange and route Nping only when packet behavior matters.

**Prerequisites:** Prepared local tool/input for execution; supplied examples and paper decisions can be studied without accounts or purchases.

**Practice/check:** Use the bounded check and answer in this route; distinguish actual executed checks from paper decisions.

**Limits:** Ncat loopback17-byte exchange tested. Nping not installed or run; raw modes may need privileges and are conditional. No external targets or stress-test exercises are prescribed.

**Access/offline:** cost: Free authored route and public primary documentation.; registration: None for selected reading or local checks.; offline: Route and benign inputs are local; save linked primary pages separately. No paid service required.

**Read these companions:** [Ncat basic usage and local examples](https://nmap.org/ncat/guide/ncat-usage.html) — Connect/listen modes, explicit address binding, one-connection lifecycle and CRLF HTTP example. · [Nping reference: TCP Connect Mode and bounded count](https://nmap.org/book/nping-man.html) — Unprivileged connect mode, -c count, SENT/RCVD interpretation and limits; no response alone is inconclusive.

<a id="capability:oletools-suite"></a>

## oletools suite: extract objects and choose the right parser

[Open resource](research/learning/video-coverage/practice/CAPABILITY_ROUTES.md#oletools-suite) · guide · workflow

**Approved rows:** kali-98. **Learn:** Keep VBA analysis separate from OLE/RTF extraction, DDE links, heuristic triage, metadata/timestamps and embedded SWF. Extract two benign known-note containers and compare bytes.

**Prerequisites:** Prepared local tool/input for execution; supplied examples and paper decisions can be studied without accounts or purchases.

**Practice/check:** Use the bounded check and answer in this route; distinguish actual executed checks from paper decisions.

**Limits:** Local oleobj/rtfobj extraction tested with0.60.1. Other suite components are explicit conditional/reference routes, not claimed executed. Wiki oleobj Usage is a placeholder; CLI source and installed help supply the operation.

**Access/offline:** cost: Free authored route and public primary documentation.; registration: None for selected reading or local checks.; offline: Route and benign inputs are local; save linked primary pages separately. No paid service required.

**Read these companions:** [Author tool-role index](https://github.com/decalage2/oletools#tools) — Distinct roles for the nine named suite components. · [oleobj actual CLI source](https://github.com/decalage2/oletools/blob/master/oletools/oleobj.py) — -d output directory, Office/OLE inputs and extraction/error return flags; local help checked. · [rtfobj documented extraction](https://github.com/decalage2/oletools/wiki/rtfobj) — Object listing, numbered -s extraction, -d destination and RTF-specific parsing.

<a id="capability:volatility-symbols"></a>

## Volatility: diagnose layer and symbol requirements

[Open resource](research/learning/video-coverage/practice/CAPABILITY_ROUTES.md#volatility-symbols) · guide · workflow

**Approved rows:** windows-31, kali-32. **Learn:** Classify layer versus symbol failure, check file integrity/readability, match Windows PDB GUID/age or exact Linux/macOS banner, correct known prerequisites and preserve unresolved failures.

**Prerequisites:** Prepared local tool/input for execution; supplied examples and paper decisions can be studied without accounts or purchases.

**Practice/check:** Use the bounded check and answer in this route; distinguish actual executed checks from paper decisions.

**Limits:** No memory image/symbol download or Volatility execution. A damaged/unsupported image or unavailable matching debug kernel may remain unresolved; this is a troubleshooting decision route, not a guarantee of repair.

**Access/offline:** cost: Free authored route and public primary documentation.; registration: None for selected reading or local checks.; offline: Route and benign inputs are local; save linked primary pages separately. No paid service required.

**Read these companions:** [Official symbol-table discovery and identity guide](https://volatility3.readthedocs.io/en/latest/symbol-tables.html) — Symbol locations/cache, Windows PDB identity, Linux/macOS exact banners, isfinfo/banners and dwarf2json prerequisites. · [Actual requirement-error diagnostics](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/cli.html) — process_unsatisfied_exceptions and process_exceptions: validate layer/input before symbol file; preserve incomplete-analysis status.

## Verification limits

Substantive source observations and caption hashes are retained in [collection.json](research/learning/video-coverage/collection.json). Some inherited tool references were last inspected in October19 research; these are labeled references, not newly endorsed deep lessons. New caption files were retrieved without downloading additional videos. No new hosted lab, GUI exercise, malware sample or video playback was executed.
