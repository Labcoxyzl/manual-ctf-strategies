# All approved tools: study and reference index

All **200 approved entries**, with documentation and lessons from the [24-hour guide](LEARNING_RESOURCES.md). Core, next and reference indicate study priority; every entry is approved.

Versions and locations come from the organiser workbook; confirm them on your machine. The PDF viewer is unspecified; its Adobe documentation is illustrative.

## Windows list (some run in WSL)

| Tool | Use it for | Study | Documentation | Organiser version / location |
| --- | --- | --- | --- | --- |
| <a id="windows-1"></a>**CyberChef** | Build a decoding recipe | core: [CyberChef recipes](LEARNING_RESOURCES.md#crypto-foundations-1), [CyberChef video](LEARNING_RESOURCES.md#crypto-foundations-2) | [Reference](https://github.com/gchq/CyberChef) | Latest (browser-based, no install) / Bookmark |
| <a id="windows-2"></a>**Wireshark** | Inspect packet conversations | core: [Wireshark filters and streams](LEARNING_RESOURCES.md#web-network-5), [HTTP capture practice](LEARNING_RESOURCES.md#web-network-8) | [Reference](https://www.wireshark.org/docs/wsug_html_chunked/ChapterWork.html) | Latest / installed in Windows |
| <a id="windows-3"></a>**PDF Viewer** | Inspect PDF text and attachments; viewer identity is unspecified | reference | [Reference](https://helpx.adobe.com/acrobat/desktop/edit-documents/use-links-and-attachments/open-attachment.html) | Any current version / installed in Windows |
| <a id="windows-4"></a>**OpenVPN Client** | Connect using an approved VPN profile | reference | [Reference](https://openvpn.net/connect-docs/import-profile.html) | Latest / installed in Windows |
| <a id="windows-5"></a>**Google Chrome** | Inspect browser requests | reference | [Reference](https://developer.chrome.com/docs/devtools/network/) | Latest / installed in Windows |
| <a id="windows-6"></a>**Windows Subsystem for Linux (WSL)** | Use the installed Linux environment | reference | [Reference](https://learn.microsoft.com/en-us/windows/wsl/basic-commands) | Latest / installed in Windows |
| <a id="windows-7"></a>**Python 3** | Parse binary data | core: [RSA beginner](LEARNING_RESOURCES.md#crypto-foundations-3) | [Reference](https://docs.python.org/3/library/struct.html) | Latest 3.x — confirm exact version before install / installed in WSL / Libraries may be added freely EXCEPT any AI/ML-related library (e.g. no LLM, machine-learning, or generative-AI frameworks).  |
| <a id="windows-8"></a>**uv** | Manage Python environments | reference | [Reference](https://docs.astral.sh/uv/pip/environments/) | Latest / installed in WSL / Same rule as Python 3 — any library OK except AI/ML-related packages |
| <a id="windows-9"></a>**gdb** | Debug native binaries | core: [GDB crackme video](LEARNING_RESOURCES.md#reverse-3), [GDB source and disassembly](LEARNING_RESOURCES.md#reverse-4) | [Reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints.html) | Latest (distro package) / installed in WSL |
| <a id="windows-10"></a>**objdump** | Inspect disassembly and sections | reference | [Reference](https://sourceware.org/binutils/docs/binutils/objdump.html) | Bundled with GNU Binutils / installed in WSL |
| <a id="windows-11"></a>**strings** | Extract readable strings | reference | [Reference](https://sourceware.org/binutils/docs/binutils/strings.html) | Bundled with GNU Binutils / installed in WSL |
| <a id="windows-12"></a>**zsteg** | Inspect PNG/BMP hidden data | core: [zsteg extraction](LEARNING_RESOURCES.md#media-1) | [Reference](https://github.com/zed-0xff/zsteg) | Latest (Ruby gem) / installed in WSL |
| <a id="windows-13"></a>**binwalk** | Locate embedded files; verify installed major version | core: [Binwalk extraction](LEARNING_RESOURCES.md#media-2) | [Reference](https://github.com/ReFirmLabs/binwalk) | Latest / installed in WSL |
| <a id="windows-14"></a>**ExifTool** | Read file metadata | core: [ExifTool metadata](LEARNING_RESOURCES.md#media-3), [Morse audio walkthrough](LEARNING_RESOURCES.md#media-8) | [Reference](https://github.com/exiftool/exiftool) | Latest / installed in WSL |
| <a id="windows-15"></a>**pdftotext (Poppler utils)** | Extract PDF text | reference | [Reference](https://manpages.debian.org/bookworm/poppler-utils/pdftotext.1.en.html) | Latest / installed in WSL |
| <a id="windows-16"></a>**can-utils** | Read CAN bus logs | reference | [Reference](https://github.com/linux-can/can-utils) | Latest / installed in WSL |
| <a id="windows-17"></a>**cannelloni** | Understand CAN tunneling | reference | [Reference](https://github.com/mguentner/cannelloni) | Latest / installed in WSL |
| <a id="windows-18"></a>**zeek** | Produce protocol logs from packet captures | next: [Zeek logs](LEARNING_RESOURCES.md#web-network-7) | [Reference](https://docs.zeek.org/en/current/quickstart.html) | Latest / installed in WSL |
| <a id="windows-19"></a>**ZBar** | Decode barcodes locally | reference | [Reference](https://github.com/mchehab/zbar) | Latest / installed in WSL |
| <a id="windows-20"></a>**Burp Suite Community Edition** | Inspect and replay web requests | core: [Burp request replay](LEARNING_RESOURCES.md#web-network-1), [Burp Repeater video](LEARNING_RESOURCES.md#web-network-2) | [Reference](https://portswigger.net/burp/documentation/desktop/tools/repeater) | 2026.4.x (confirm latest at install time) / installed in WSL |
| <a id="windows-21"></a>**jq** | Filter JSON | reference | [Reference](https://jqlang.org/manual/) | Latest / installed in WSL |
| <a id="windows-22"></a>**Ghidra** | Inspect program logic | core: [Ghidra student guide](LEARNING_RESOURCES.md#reverse-1), [Ghidra crackme video](LEARNING_RESOURCES.md#reverse-2), [GDB source and disassembly](LEARNING_RESOURCES.md#reverse-4) | [Reference](https://github.com/NationalSecurityAgency/ghidra) | 12.1.4 / installed in WSL |
| <a id="windows-23"></a>**The Sleuth Kit** | Inspect filesystem images | core: [Sleuth Kit recovery](LEARNING_RESOURCES.md#forensics-1) | [Reference](https://www.sleuthkit.org/sleuthkit/man/fls.html) | Latest / installed in WSL |
| <a id="windows-24"></a>**OpenSSL** | Understand symmetric decryption parameters | reference | [Reference](https://docs.openssl.org/3.0/man1/openssl-enc/) | Latest 3.x / installed in WSL |
| <a id="windows-25"></a>**xz** | Inspect and decompress XZ data | reference | [Reference](https://tukaani.org/xz/man/xz.1.html) | Latest / installed in WSL |
| <a id="windows-26"></a>**qpdf** | Inspect PDF objects and streams | next: [qpdf inspection](LEARNING_RESOURCES.md#forensics-6) | [Reference](https://qpdf.readthedocs.io/en/stable/cli.html) | Latest / installed in WSL |
| <a id="windows-27"></a>**llvm-mc (LLVM tools)** | Translate assembly and machine code | reference | [Reference](https://llvm.org/docs/CommandGuide/llvm-mc.html) | Latest / installed in WSL |
| <a id="windows-28"></a>**xxd** | Convert hex dumps | reference | [Reference](https://github.com/vim/vim/blob/master/runtime/doc/xxd.1) | Bundled with Vim / installed in WSL |
| <a id="windows-29"></a>**fsck.fat (dosfstools)** | Check FAT structure without repair | reference | [Reference](https://github.com/dosfstools/dosfstools/blob/master/manpages/fsck.fat.8.in) | Latest / installed in WSL |
| <a id="windows-30"></a>**RsaCtfTool** | Study RSA attack prerequisites | core: [RsaCtfTool prerequisites](LEARNING_RESOURCES.md#crypto-foundations-4) | [Reference](https://github.com/RsaCtfTool/RsaCtfTool) | Latest (GitHub script, run via Python 3) / installed in WSL |
| <a id="windows-31"></a>**volatility3** | Inspect Windows memory images | core: [Volatility 3 processes](LEARNING_RESOURCES.md#forensics-3), [Volatility 3 video](LEARNING_RESOURCES.md#forensics-4) | [Reference](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html) | Latest / installed in WSL |
| <a id="windows-32"></a>**OpenSSH-Session-Key-Recovery** | Recover SSH session keys from supported memory evidence | reference | [Reference](https://github.com/fox-it/OpenSSH-Session-Key-Recovery) | installed in volatility3 / Plugin for Volatility3 |
| <a id="windows-33"></a>**x64dbg** | Debug Windows executables | reference | [Reference](https://help.x64dbg.com/en/latest/gui/tips.html) | Latest / installed in Windows / Portable zip (snapshot_*.zip). Extract and run; no installer. |
| <a id="windows-34"></a>**Autopsy** | Inspect forensic images | core: [Autopsy quick start](LEARNING_RESOURCES.md#forensics-2) | [Reference](https://sleuthkit.org/autopsy/docs/user-docs/4.22.0/ingest_page.html) | Latest / installed in Windows / MSI installer (bundles Java and The Sleuth Kit). Administrator rights required. |
| <a id="windows-35"></a>**HxD** | Inspect bytes in a hex editor | reference | [Reference](https://mh-nexus.de/en/hxd/) | Latest / installed in Windows / Installer or portable edition. |
| <a id="windows-36"></a>**tshark** | Extract packet fields | core: [TShark fields](LEARNING_RESOURCES.md#web-network-6), [HTTP capture practice](LEARNING_RESOURCES.md#web-network-8) | [Reference](https://www.wireshark.org/docs/man-pages/tshark.html) | Latest / installed in Windows / Included in the Wireshark installer (TShark component). |
| <a id="windows-37"></a>**Notepad++** | Search structured text | reference | [Reference](https://github.com/notepad-plus-plus/npp-usermanual/blob/master/content/docs/searching.md) | Latest / installed in Windows / Installer (x64). A portable edition is also available. |
| <a id="windows-38"></a>**dnSpyEx (dnSpy)** | Inspect managed assemblies | reference: [dnSpyEx assemblies](LEARNING_RESOURCES.md#reverse-8) | [Reference](https://github.com/dnSpyEx/dnSpy) | Latest / installed in Windows / Portable zip. Use dnSpy-net-win64.zip (self-contained; no .NET installation needed). |
| <a id="windows-39"></a>**Eric Zimmerman's Tools** | Select an artifact-specific Windows parser | core: [MFTECmd journal analysis](LEARNING_RESOURCES.md#forensics-5) | [Reference](https://ericzimmerman.github.io/) | Latest / installed in Windows / Run Get-ZimmermanTools.ps1 to download the tools. Internet access and the .NET Desktop Runtime are required. |

## Kali list (best-effort availability)

| Tool | Use it for | Study | Documentation | Organiser version / location |
| --- | --- | --- | --- | --- |
| <a id="kali-1"></a>**.NET SDK** | Build and run managed projects | reference | [Reference](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet) | 6.0.400 |
| <a id="kali-2"></a>**7-Zip (7z)** | Inspect and extract archives | reference | [Reference](https://7-zip.org/) | 26.02 |
| <a id="kali-3"></a>**aircrack-ng** | Understand offline wireless capture analysis | reference | [Reference](https://www.aircrack-ng.org/doku.php?id=aircrack-ng) | 1.7 |
| <a id="kali-4"></a>**ALEAPP (Android Logs Events And Protobuf Parser)** | Parse Android forensic artifacts | reference | [Reference](https://github.com/abrignoni/ALEAPP) | - / No installation information recorded |
| <a id="kali-5"></a>**Android Studio** | Inspect Android packages | reference | [Reference](https://developer.android.com/studio/debug/apk-debugger) | - / No installation information recorded |
| <a id="kali-6"></a>**angr** | Study path constraints and symbolic execution | reference | [Reference](https://docs.angr.io/en/latest/core-concepts/pathgroups.html) | (not captured) / pipx (angr) |
| <a id="kali-7"></a>**AperiSolve** | Understand local image-analysis deployment | reference: [AperiSolve setup](LEARNING_RESOURCES.md#media-7) | [Reference](https://github.com/Zeecka/AperiSolve) | (not captured) / git (/opt/tools/AperiSolve) |
| <a id="kali-8"></a>**Apktool** | Decode Android resources and smali | reference | [Reference](https://apktool.org/docs/cli-parameters/) | 2.7.0-dirty |
| <a id="kali-9"></a>**asar (@electron/asar)** | Inspect Electron archives | reference | [Reference](https://github.com/electron/asar) | 4.3.1 |
| <a id="kali-10"></a>**Audacity** | Inspect audio frequency content | core: [Audacity spectrograms](LEARNING_RESOURCES.md#media-5) | [Reference](https://manual.audacityteam.org/man/spectrogram_view.html) | (not captured) / /usr/bin/audacity |
| <a id="kali-11"></a>**AutoIt-Ripper** | Extract compiled AutoIt scripts | reference | [Reference](https://github.com/nazywam/AutoIt-Ripper) | (not captured) / pipx (autoit-ripper) |
| <a id="kali-12"></a>**BinDiff** | Compare compiled program versions | reference | [Reference](https://www.zynamics.com/bindiff/manual/) | 8 / Build @568181968 (Sep 25 2023) |
| <a id="kali-13"></a>**bkcrack** | Understand ZIP known-plaintext recovery | next: [bkcrack ZIP recovery](LEARNING_RESOURCES.md#crypto-foundations-8) | [Reference](https://github.com/kimci86/bkcrack) | 1.8.1 (2025-10-25) |
| <a id="kali-14"></a>**bulk_extractor** | Extract forensic features from bulk data | reference | [Reference](https://github.com/simsong/bulk_extractor) | 2.1.1 |
| <a id="kali-15"></a>**bvi** | Inspect binary data | reference | [Reference](https://bvi.sourceforge.net/) | (not captured) / Interactive tool; the version check returned 'Input is not from a terminal' |
| <a id="kali-16"></a>**Bytecode Viewer** | Inspect Java bytecode | reference | [Reference](https://github.com/Konloch/bytecode-viewer) | 2.13.2 / Fat Jar |
| <a id="kali-17"></a>**bzip2** | Decompress BZip2 data | reference | [Reference](https://sourceware.org/bzip2/manual/manual.html) | 1.0.8 |
| <a id="kali-18"></a>**cabextract** | Inspect Microsoft cabinet archives | reference | [Reference](https://www.kali.org/tools/cabextract/) | 1.11 |
| <a id="kali-19"></a>**capa** | Identify executable capabilities | core: [capa capability matches](LEARNING_RESOURCES.md#reverse-5) | [Reference](https://github.com/mandiant/capa) | 9.4.0 |
| <a id="kali-20"></a>**Chainsaw** | Search Windows event logs | next: [Chainsaw event logs](LEARNING_RESOURCES.md#forensics-7) | [Reference](https://github.com/WithSecureOpenSource/chainsaw) | 2.16.5 |
| <a id="kali-21"></a>**checksec** | Identify executable protections | reference | [Reference](https://github.com/slimm609/checksec/releases) | 2.6.0 |
| <a id="kali-22"></a>**crypto-attacks** | Find mathematical attack implementations | reference | [Reference](https://github.com/jvdsn/crypto-attacks) | (not captured) / git (/opt/tools/crypto-attacks) |
| <a id="kali-23"></a>**curl** | Inspect and reproduce HTTP requests | core: [curl HTTP requests](LEARNING_RESOURCES.md#web-network-3) | [Reference](https://curl.se/docs/manpage.html) | 8.21.0 |
| <a id="kali-24"></a>**Cutter** | Inspect program control flow | reference | [Reference](https://github.com/rizinorg/cutter) | (not captured) / AppImage (/opt/tools/cutter.AppImage) / The GUI needs FUSE |
| <a id="kali-25"></a>**DB Browser for SQLite** | Inspect SQLite records | reference | [Reference](https://sqlitebrowser.org/) | 3.13.1 |
| <a id="kali-26"></a>**DBeaver Community Edition** | Query local databases | reference | [Reference](https://dbeaver.com/docs/dbeaver/SQL-Execution/) | 26.1.3 |
| <a id="kali-27"></a>**Detect It Easy (DIE)** | Identify binary formats and packers | reference | [Reference](https://github.com/horsicq/Detect-It-Easy) | 3.21 |
| <a id="kali-28"></a>**dex2jar** | Convert Android bytecode to a JAR for Java analysis. | reference | [Reference](https://github.com/pxb1988/dex2jar) | 2.1-nightly-28 |
| <a id="kali-29"></a>**Didier Stevens Beta tools (onedump.py)** | Inspect objects in a OneNote document. | reference | [Reference](https://github.com/DidierStevens/Beta/blob/master/onedump.py) | (not captured) / git (/opt/tools/Beta) |
| <a id="kali-30"></a>**Didier Stevens Suite (pdfid.py, pdf-parser.py, oledump.py and others)** | Triage Office macros and PDF objects. | reference | [Reference](https://github.com/DidierStevens/DidierStevensSuite) | (not captured) / git (/opt/tools/DidierStevensSuite) |
| <a id="kali-31"></a>**Docker Engine and Compose plugin** | Run and inspect a local container lab. | reference | [Reference](https://docs.docker.com/compose/) | 28.5.2+dfsg4 |
| <a id="kali-32"></a>**dwarf2json** | Generate Linux memory-analysis symbols. | reference | [Reference](https://github.com/volatilityfoundation/dwarf2json) | 0.9.0 |
| <a id="kali-33"></a>**Eclipse Temurin JDK (OpenJDK)** | Run Java tools and inspect class bytecode. | reference | [Reference](https://adoptium.net/temurin) | 25.0.4 (2026-07-21) / Reported as 'openjdk' |
| <a id="kali-34"></a>**ewf-tools (libewf)** | Read or export an E01 disk image. | reference | [Reference](https://github.com/libyal/libewf) | 20140816 |
| <a id="kali-35"></a>**Exploit-DB / searchsploit (offline archive)** | Search the local Exploit-DB archive. | reference | [Reference](https://www.exploit-db.com/searchsploit) | 2026-08-19 / Version is the archive date |
| <a id="kali-36"></a>**factordb-python** | Look up known integer factors. | reference | [Reference](https://github.com/ryosan-470/factordb-python) | (not captured) / pip (factordb-python) |
| <a id="kali-37"></a>**FakeNet-NG** | Observe network behavior in a malware lab. | reference | [Reference](https://github.com/mandiant/flare-fakenet-ng) | (not captured) / /opt/tools/flare-fakenet-ng (fakenet in PATH) |
| <a id="kali-38"></a>**Fernflower** | Decompile Java classes and JARs. | reference | [Reference](https://github.com/JetBrains/fernflower/blob/master/README.md) | (not captured) / /opt/tools/fernflower/build/libs/fernflower.jar (/usr/local/bin/fernflower) |
| <a id="kali-39"></a>**Feroxbuster** | Find web paths in an authorized lab. | reference | [Reference](https://github.com/epi052/feroxbuster) | 2.13.1 |
| <a id="kali-40"></a>**FFmpeg** | Extract frames or audio from media. | next: [FFmpeg stream selection](LEARNING_RESOURCES.md#media-6) | [Reference](https://ffmpeg.org/ffmpeg.html) | (not captured) / apt (ffmpeg) |
| <a id="kali-41"></a>**ffuf** | Compare web responses during controlled fuzzing. | next: [ffuf discovery](LEARNING_RESOURCES.md#web-network-4) | [Reference](https://github.com/ffuf/ffuf) | 2.1.0-dev |
| <a id="kali-42"></a>**file (libmagic)** | Identify unknown file formats. | reference | [Reference](https://github.com/file/file) | 5.47 |
| <a id="kali-43"></a>**FLOSS (FLARE Obfuscated String Solver)** | Recover obscured strings from binaries. | core: [FLOSS strings](LEARNING_RESOURCES.md#reverse-6) | [Reference](https://github.com/mandiant/flare-floss) | (not captured) / pipx (flare-floss) |
| <a id="kali-44"></a>**foremost** | Carve files from raw evidence. | reference | [Reference](https://www.kali.org/tools/foremost/) | (not captured) / Installed; version not captured |
| <a id="kali-45"></a>**FQLite** | Inspect deleted SQLite records. | reference | [Reference](https://github.com/pawlaszczyk/fqlite) | (not captured) / /opt/fqlite/bin/fqlite (symlinked to /usr/local/bin) |
| <a id="kali-46"></a>**Frida** | Observe runtime function calls. | reference | [Reference](https://frida.re/docs/javascript-api/) | 17.23.3 |
| <a id="kali-47"></a>**GCC, G++ and build tools (build-essential, make, CMake, pkg-config)** | Build small local programs with debug information. | reference | [Reference](https://gcc.gnu.org/onlinedocs/gcc/Debugging-Options.html) | 15.3.0 / Debian gcc 15.3.0-2 |
| <a id="kali-48"></a>**GEF (GDB Enhanced Features)** | Inspect register and stack state in GDB. | reference | [Reference](https://hugsy.github.io/gef/) | (not captured) / /opt/tools/gef.py / Load with: gdb -x /opt/tools/gef.py. Not auto-sourced, to avoid a clash with peda |
| <a id="kali-49"></a>**Git** | Trace file history in a local repository. | reference | [Reference](https://git-scm.com/docs/git-log) | 2.53.0 |
| <a id="kali-50"></a>**Gitleaks** | Locate exposed secrets in local repository history. | reference | [Reference](https://github.com/gitleaks/gitleaks) | (not captured) / The tool does not report a version (set at build time) |
| <a id="kali-51"></a>**G'MIC (gmic)** | Inspect image channels and contrast. | reference | [Reference](https://gmic.eu/reference/) | (not captured) / Version not captured (the command started the G'MIC interpreter) |
| <a id="kali-52"></a>**GNU Wget** | Save public files for local analysis. | reference | [Reference](https://www.gnu.org/software/wget/manual/wget.html) | 1.25.0 |
| <a id="kali-53"></a>**Go** | Build or run local Go utilities. | reference | [Reference](https://go.dev/doc/cmd) | 1.26.5 |
| <a id="kali-54"></a>**Gobuster** | Discover web directories or virtual hosts. | reference | [Reference](https://github.com/OJ/gobuster) | 3.8.2 |
| <a id="kali-55"></a>**GoReSym** | Recover symbols in a Go binary. | reference | [Reference](https://github.com/mandiant/GoReSym) | (not captured) / go install (github.com/mandiant/GoReSym@latest) |
| <a id="kali-56"></a>**GTFOBins (offline copy)** | Interpret permitted binary functions in a CTF lab. | reference | [Reference](https://gtfobins.org/) | (not captured) / git (/opt/tools/GTFOBins.github.io) |
| <a id="kali-57"></a>**gzip** | Unpack and check gzip files. | reference | [Reference](https://www.gnu.org/software/gzip/manual/gzip.html) | 1.13 |
| <a id="kali-58"></a>**HackTricks (offline copy)** | Find a technique checklist for a lab task. | reference | [Reference](https://github.com/HackTricks-wiki/hacktricks) | (not captured) / git (/opt/tools/hacktricks) |
| <a id="kali-59"></a>**hashcat** | Match hash formats and choose a recovery mode. | core: [hashcat wordlists](LEARNING_RESOURCES.md#crypto-foundations-6) | [Reference](https://hashcat.net/wiki/doku.php?id=example_hashes) | 7.1.2 |
| <a id="kali-60"></a>**hashid** | Suggest possible hash formats. | reference | [Reference](https://github.com/psypanda/hashID) | 3.1.4 |
| <a id="kali-61"></a>**Hayabusa** | Build a Windows event timeline. | reference | [Reference](https://github.com/Yamato-Security/hayabusa) | (not captured) / Version not captured (the --version option is not supported) |
| <a id="kali-62"></a>**hcxtools** | Convert captured wireless authentication data. | reference | [Reference](https://github.com/ZerBea/hcxtools) | 7.1.2 / Version of hcxpcapngtool |
| <a id="kali-63"></a>**Hindsight (pyhindsight)** | Parse a saved browser profile. | reference | [Reference](https://github.com/RyanDFIR/hindsight) | (not captured) / pipx (pyhindsight) |
| <a id="kali-64"></a>**hlextend** | Explore hash length extension with generic examples. | reference | [Reference](https://github.com/stephenbradshaw/hlextend) | (not captured) / Python module (/usr/local/lib/python3.14/dist-packages/hlextend.py) |
| <a id="kali-65"></a>**Hydra** | Understand form authentication test syntax. | reference | [Reference](https://github.com/vanhauser-thc/thc-hydra) | (not captured) / Installed; version not captured |
| <a id="kali-66"></a>**iLEAPP (iOS Logs, Events, And Plists Parser)** | Parse iOS forensic artifacts. | reference | [Reference](https://github.com/abrignoni/iLEAPP) | - / No installation information recorded |
| <a id="kali-67"></a>**ImageMagick** | Inspect image channels and properties. | reference | [Reference](https://imagemagick.org/command-line-processing/) | 7.1.2-27 |
| <a id="kali-68"></a>**Impacket** | Work with SMB and network protocol examples. | reference | [Reference](https://github.com/fortra/impacket) | 0.14.0 |
| <a id="kali-69"></a>**innoextract** | Unpack an Inno Setup installer. | reference | [Reference](https://constexpr.org/innoextract/) | dev build |
| <a id="kali-70"></a>**internet_detector** | Simulate internet services in a malware lab. | reference | [Reference](https://www.inetsim.org/) | (not captured) / apt (inetsim) / Provided by the apt package 'inetsim' |
| <a id="kali-71"></a>**IPython** | Explore Python objects and run small scripts. | reference | [Reference](https://ipython.readthedocs.io/en/stable/interactive/tutorial.html) | 9.17.1 |
| <a id="kali-72"></a>**jadx (jadx-gui)** | Inspect Android application logic. | reference: [JADX APK/DEX](LEARNING_RESOURCES.md#reverse-9) | [Reference](https://github.com/skylot/jadx) | 1.5.6 |
| <a id="kali-73"></a>**John the Ripper (jumbo)** | Prepare and recover passwords from local test data. | core: [John wordlists](LEARNING_RESOURCES.md#crypto-foundations-7) | [Reference](https://www.openwall.com/john/doc/) | 1.9.0-Jumbo-1 |
| <a id="kali-74"></a>**Jpeginfo** | Check JPEG structure and integrity. | reference | [Reference](https://github.com/tjko/jpeginfo) | 1.7.1 |
| <a id="kali-75"></a>**js-beautify** | Format compressed JavaScript for inspection. | reference | [Reference](https://github.com/beautifier/js-beautify) | 2.0.3 |
| <a id="kali-76"></a>**js-deobfuscator** | Simplify JavaScript string arrays and proxy functions. | reference | [Reference](https://github.com/ben-sb/javascript-deobfuscator) | (not captured) / npm (js-deobfuscator) |
| <a id="kali-77"></a>**jwt_tool** | Inspect and test JSON Web Tokens. | reference | [Reference](https://github.com/ticarpi/jwt_tool) | (not captured) / /opt/tools/jwt_tool (/usr/local/bin/jwt_tool) |
| <a id="kali-78"></a>**Katana** | Discover in-scope URLs and application routes. | reference | [Reference](https://docs.projectdiscovery.io/opensource/katana/usage) | (not captured) / go install (github.com/projectdiscovery/katana/cmd/katana@latest) |
| <a id="kali-79"></a>**legion** | Organize network discovery in a lab. | reference | [Reference](https://github.com/Abacus-Group-RTO/legion) | 0.7.0 |
| <a id="kali-80"></a>**libesedb tools** | Inspect Windows ESE database tables. | reference | [Reference](https://github.com/libyal/libesedb) | 20240420 / Version of esedbexport |
| <a id="kali-81"></a>**LibreOffice** | Convert documents to inspectable formats. | reference | [Reference](https://help.libreoffice.org/latest/en-US/text/shared/guide/start_parameters.html) | 26.8.0.3 |
| <a id="kali-82"></a>**lrzip** | Unpack long-range compressed files. | reference | [Reference](https://github.com/ckolivas/lrzip) | 0.660 |
| <a id="kali-83"></a>**ltrace** | Observe dynamic library calls. | reference | [Reference](https://ltrace.org/) | 0.7.91 |
| <a id="kali-84"></a>**lz4** | Unpack LZ4 data. | reference | [Reference](https://github.com/lz4/lz4) | 1.10.0 |
| <a id="kali-85"></a>**lzip** | Unpack and check lzip files. | reference | [Reference](https://www.nongnu.org/lzip/manual/lzip_manual.html) | 1.26 |
| <a id="kali-86"></a>**mac_apt** | Parse macOS artifacts from saved evidence. | reference | [Reference](https://github.com/ydkhatri/mac_apt) | (not captured) / git (/opt/tools/mac_apt) |
| <a id="kali-87"></a>**MediaInfo** | Inspect media container and codec information. | reference | [Reference](https://mediaarea.net/en/MediaInfo) | (not captured) / Version not captured |
| <a id="kali-88"></a>**Metasploit Framework** | Navigate module documentation in a local lab. | reference | [Reference](https://docs.metasploit.com/) | 6.5.2-dev |
| <a id="kali-89"></a>**mimikatz** | Understand offline Windows authentication-dump analysis. | reference | [Reference](https://github.com/gentilkiwi/mimikatz/wiki) | 2.2.0 / Wine (Windows binary) |
| <a id="kali-90"></a>**Miniforge3 (conda)** | Create a separate dependency environment. | reference | [Reference](https://github.com/conda-forge/miniforge) | (not captured) / /home/kali/miniforge3 |
| <a id="kali-91"></a>**multimon-ng** | Decode supported audio modulation formats. | reference | [Reference](https://github.com/EliasOenal/multimon-ng) | (not captured) / apt (multimon-ng) |
| <a id="kali-92"></a>**mupdf-tools (mutool)** | Inspect PDF objects and extract resources. | reference | [Reference](https://mupdf.readthedocs.io/en/latest/tools/mutool.html) | 1.27.0 |
| <a id="kali-93"></a>**NASM (Netwide Assembler)** | Assemble or inspect x86 instructions. | reference | [Reference](https://www.nasm.us/docs.html) | 3.01 |
| <a id="kali-94"></a>**Nmap (with Ncat / Nping)** | Identify services and inspect network connectivity. | next: [Nmap results](LEARNING_RESOURCES.md#web-network-9) | [Reference](https://www.kali.org/tools/nmap/) | 7.99 |
| <a id="kali-95"></a>**Node.js (with npm)** | Convert binary representations in JavaScript. | reference | [Reference](https://nodejs.org/docs/latest-v24.x/api/buffer.html) | 24.21.0 |
| <a id="kali-96"></a>**obfuscator-io-deobfuscator** | Recover readable JavaScript from Obfuscator.io output. | reference | [Reference](https://github.com/ben-sb/obfuscator-io-deobfuscator) | 1.0.6 |
| <a id="kali-97"></a>**Obsidian** | Organize investigation notes with links. | reference | [Reference](https://help.obsidian.md/links) | (not captured) / Version not captured; startup reported that ~/.config/obsidian/obsidian.json does not exist |
| <a id="kali-98"></a>**oletools (full suite: olevba, oleid, oleobj, rtfobj, mraptor, msodde, olemeta, oletimes, pyxswf)** | Inspect Office documents and extract macros or embedded objects. | reference | [Reference](https://github.com/decalage2/oletools) | (not captured) / pipx (oletools) |
| <a id="kali-99"></a>**OllyDbg** | Debug 32-bit Windows executables. | reference | [Reference](https://www.ollydbg.de/quickst.htm) | 1.10-1kali5 / Wine (Windows binary) |
| <a id="kali-100"></a>**OpenStego** | Extract data hidden using OpenStego. | reference | [Reference](https://www.openstego.com/) | (not captured) / GitHub .deb package |
| <a id="kali-101"></a>**padding-oracle-attacker** | Understand the tool's padding oracle input and response options. | reference | [Reference](https://github.com/KishanBagaria/padding-oracle-attacker) | (not captured) / Version not captured (the command printed a banner only) |
| <a id="kali-102"></a>**PARI/GP** | Explore modular arithmetic and discrete logarithms. | reference | [Reference](https://pari.math.u-bordeaux.fr/dochtml/html-stable/Arithmetic_functions.html) | 2.17.4 |
| <a id="kali-103"></a>**PayloadsAllTheThings (offline copy)** | Find a structured web vulnerability reference. | reference | [Reference](https://github.com/swisskyrepo/PayloadsAllTheThings) | (not captured) / git (/opt/tools/PayloadsAllTheThings) |
| <a id="kali-104"></a>**peda** | Inspect debugging state and cyclic-pattern offsets. | reference | [Reference](https://github.com/longld/peda) | (not captured) / /opt/tools/peda (sourced in ~/.gdbinit) |
| <a id="kali-105"></a>**peepdf-3** | Inspect PDF objects and streams. | reference | [Reference](https://github.com/digitalsleuth/peepdf-3) | (not captured) / pipx (peepdf-3) |
| <a id="kali-106"></a>**pff-tools (libpff)** | Inspect and extract Outlook personal-folder data. | reference | [Reference](https://github.com/libyal/libpff) | 20231205 / Version of pffexport |
| <a id="kali-107"></a>**Plaso (log2timeline, psort, pinfo)** | Build a forensic timeline from artifacts. | reference | [Reference](https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html) | 20260119-1kali1 |
| <a id="kali-108"></a>**pngcheck** | Inspect PNG structure and integrity. | reference | [Reference](https://github.com/pnggroup/pngcheck) | (not captured) / apt (pngcheck) |
| <a id="kali-109"></a>**pwndbg** | Inspect binary debugging state and offsets. | reference | [Reference](https://pwndbg.re/stable/commands/) | (not captured) / /opt/tools/pwndbg / setup.sh completed |
| <a id="kali-110"></a>**pycdc (Decompyle++)** | Decompile or disassemble Python bytecode. | reference | [Reference](https://github.com/zrax/pycdc) | (not captured) / Version not captured (no --version option) |
| <a id="kali-111"></a>**pyinstxtractor-ng** | Extract files bundled by PyInstaller. | reference: [PyInstaller extraction](LEARNING_RESOURCES.md#reverse-10) | [Reference](https://github.com/pyinstxtractor/pyinstxtractor-ng) | (not captured) / pipx (pyinstxtractor-ng) |
| <a id="kali-112"></a>**pypykatz** | Parse a supplied Windows memory dump. | reference | [Reference](https://github.com/skelsec/pypykatz) | 0.6.13 |
| <a id="kali-113"></a>**Python 2.7** | Read binary records in legacy Python scripts. | reference | [Reference](https://docs.python.org/2.7/library/struct.html) | 2.7.18 |
| <a id="kali-114"></a>**Python 3.11 (via uv)** | Select Python 3.11 through uv; workbook records no installation information. | core: [RSA beginner](LEARNING_RESOURCES.md#crypto-foundations-3) | [Reference](https://docs.astral.sh/uv/guides/install-python/) | - / No installation information recorded |
| <a id="kali-115"></a>**qemu-img (qemu-utils)** | Identify and convert virtual disk formats. | reference | [Reference](https://www.qemu.org/docs/master/tools/qemu-img.html) | 11.0.3 |
| <a id="kali-116"></a>**radare2** | Locate and disassemble binary functions. | reference | [Reference](https://book.rada.re/analysis/intro.html) | 6.0.5 |
| <a id="kali-117"></a>**rat-king-parser** | Extract configuration from supported RAT families. | reference | [Reference](https://github.com/jeFF0Falltrades/rat_king_parser) | 4.2.4 |
| <a id="kali-118"></a>**RegRipper** | Extract artifacts from offline Windows registry hives. | reference | [Reference](https://github.com/keydet89/RegRipper3.0) | 3.0 |
| <a id="kali-119"></a>**ripgrep (rg)** | Search text and selectively include hidden or binary files. | reference | [Reference](https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md) | 15.2.0 |
| <a id="kali-120"></a>**rockyou.txt (Kali 'wordlists' package)** | Locate the approved password dictionary. | core: [hashcat wordlists](LEARNING_RESOURCES.md#crypto-foundations-6), [John wordlists](LEARNING_RESOURCES.md#crypto-foundations-7) | [Reference](https://www.kali.org/tools/wordlists/) | (not captured) / /usr/share/wordlists/rockyou.txt |
| <a id="kali-121"></a>**ROPgadget** | Find instruction gadgets in a binary. | reference | [Reference](https://github.com/JonathanSalwan/ROPgadget) | 7.7 |
| <a id="kali-122"></a>**rtptools (rtpdump, rtpplay and others)** | Inspect or replay RTP recordings. | reference | [Reference](https://github.com/irtlab/rtptools) | (not captured) / /opt/tools/rtptools / Built from source |
| <a id="kali-123"></a>**Rust (rustup, rustc, cargo)** | Build and run a Rust analysis utility. | reference | [Reference](https://doc.rust-lang.org/book/ch01-03-hello-cargo.html) | 1.95.0 (2026-04-14) / Built from a source tarball |
| <a id="kali-124"></a>**rustscan** | Understand port discovery and scanner options. | reference | [Reference](https://github.com/RustScan/RustScan/wiki/Usage) | 2.4.1 |
| <a id="kali-125"></a>**SageMath** | Explore discrete logarithms; workbook records no installation information. | core: [RSA beginner](LEARNING_RESOURCES.md#crypto-foundations-3), [SageMath arithmetic](LEARNING_RESOURCES.md#crypto-foundations-5) | [Reference](https://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html) | - / No installation information recorded |
| <a id="kali-126"></a>**SecLists** | Select a wordlist suited to a web discovery task. | next: [ffuf discovery](LEARNING_RESOURCES.md#web-network-4) | [Reference](https://github.com/danielmiessler/SecLists) | (not captured) / /usr/bin/seclists |
| <a id="kali-127"></a>**socat** | Connect standard input to a TCP service. | reference | [Reference](https://www.kali.org/tools/socat/) | 1.8.1.3 |
| <a id="kali-128"></a>**Sonic Visualiser** | Inspect audio with spectrogram layers. | next: [Morse audio walkthrough](LEARNING_RESOURCES.md#media-8) | [Reference](https://www.sonicvisualiser.org/doc/reference/5.2.1/en/) | 5.2.1 |
| <a id="kali-129"></a>**SoX (Sound eXchange)** | Generate audio spectrograms with the workbook-reported SoX_ng build; confirm local command options. | reference | [Reference](https://codeberg.org/sox_ng/sox_ng) | 14.7.1.2 / SoX_ng build |
| <a id="kali-130"></a>**SQLCipher Community Edition — CLI** | Open a SQLCipher database with its known key and settings. | reference | [Reference](https://www.zetetic.net/sqlcipher/sqlcipher-api/) | SQLite 3.53.4 / SQLCipher 4.18.0 |
| <a id="kali-131"></a>**sqlite3** | Inspect a SQLite database without changing it. | next: [SQLite queries](LEARNING_RESOURCES.md#forensics-8) | [Reference](https://sqlite.org/cli.html) | 3.53.4 |
| <a id="kali-132"></a>**sqlmap** | Understand sqlmap options for an authorized test request. | reference | [Reference](https://github.com/sqlmapproject/sqlmap/wiki/Usage) | 1.10.8 (stable) |
| <a id="kali-133"></a>**sstv (command-line SSTV decoder)** | Decode SSTV audio; installed identity uncertain because workbook location lists the PySSTV encoder. | reference | [Reference](https://github.com/colaclanth/sstv) | (not captured) / pip (PySSTV); decoder name / PySSTV encoder installation mismatch |
| <a id="kali-134"></a>**steghide** | Inspect and extract a steghide carrier. | core: [Stegseek recovery](LEARNING_RESOURCES.md#media-4) | [Reference](https://www.kali.org/tools/steghide/) | 0.6.0 |
| <a id="kali-135"></a>**stegseek** | Recover data from steghide carriers. | core: [Stegseek recovery](LEARNING_RESOURCES.md#media-4) | [Reference](https://github.com/RickdeJager/stegseek) | 0.6 |
| <a id="kali-136"></a>**stegsnow (SNOW)** | Decode whitespace-based hidden data. | reference | [Reference](https://www.darkside.com.au/snow/) | (not captured) / apt (stegsnow) |
| <a id="kali-137"></a>**StegSolve** | Inspect image bit planes; installed StegSolve version and fork are unknown. | reference | [Reference](https://github.com/Giotino/stegsolve) | (not captured) / Version not captured (GUI tool; it was started without a display) |
| <a id="kali-138"></a>**strace** | Observe a program's file and system-call behavior. | reference | [Reference](https://strace.io/) | 7.0 |
| <a id="kali-139"></a>**Subfinder** | Collect publicly reported subdomains. | reference | [Reference](https://docs.projectdiscovery.io/tools/subfinder/usage) | 2.16.0 |
| <a id="kali-140"></a>**Sublime Text** | Search source and notes in an editor. | reference | [Reference](https://www.sublimetext.com/docs/) | Build 4215 |
| <a id="kali-141"></a>**tar** | List and extract archive members. | reference | [Reference](https://www.gnu.org/software/tar/manual/html_node/extract.html) | 1.35 |
| <a id="kali-142"></a>**tcpdump** | Inspect captured packets with filters. | reference | [Reference](https://www.tcpdump.org/manpages/tcpdump.1.html) | 4.99.6 |
| <a id="kali-143"></a>**TestDisk and PhotoRec** | Recover files from a disk image. | reference | [Reference](https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step) | 7.2 |
| <a id="kali-144"></a>**unar** | List and extract supported archive formats. | reference | [Reference](https://theunarchiver.com/command-line) | 1.10.8 |
| <a id="kali-145"></a>**uncompyle6** | Recover source from supported Python bytecode. | reference | [Reference](https://github.com/rocky/python-uncompyle6) | 3.9.3 |
| <a id="kali-146"></a>**unpyc3 (unpyc37-3.10)** | Decompile supported Python bytecode; this fork has only minimal Python 3.10 support. | reference | [Reference](https://github.com/greyblue9/unpyc37-3.10) | (not captured) / git (/opt/tools/unpyc3) |
| <a id="kali-147"></a>**unrar** | List, test and extract RAR archives. | reference | [Reference](https://www.rarlab.com/rar_add.htm) | (not captured) / /usr/bin/unrar |
| <a id="kali-148"></a>**unzip** | List and extract ZIP members. | reference | [Reference](https://infozip.sourceforge.net/UnZip.html) | 6.0-30 |
| <a id="kali-149"></a>**UPX** | Check and unpack a UPX-packed executable. | reference | [Reference](https://github.com/upx/upx/blob/devel/doc/upx-doc.txt) | 4.2.4 |
| <a id="kali-150"></a>**Visual Studio Code** | Search and edit analysis code. | reference | [Reference](https://code.visualstudio.com/docs/editor/codebasics) | 1.141.2 |
| <a id="kali-151"></a>**Volatility 2** | Identify a memory image profile and inspect processes. | reference | [Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) | (not captured) / git (/opt/tools/volatility) |
| <a id="kali-152"></a>**Volatility 2 community plugins** | Load community plugins for Volatility 2. | reference | [Reference](https://github.com/volatilityfoundation/community) | (not captured) / git (/opt/tools/community) |
| <a id="kali-153"></a>**Volatility 2 profiles (Linux and macOS)** | Match Linux or macOS profiles to memory images. | reference | [Reference](https://github.com/volatilityfoundation/profiles) | (not captured) / git (/opt/tools/profiles) |
| <a id="kali-154"></a>**Volatility 3 community plugins (community3)** | Load Volatility 3 community plugins; check each plugin against the installed release. | reference | [Reference](https://github.com/volatilityfoundation/community3) | (not captured) / git (/opt/tools/community3) |
| <a id="kali-155"></a>**VS Code extension: C/C++ (ms-vscode.cpptools)** | Configure C/C++ source debugging. | reference | [Reference](https://code.visualstudio.com/docs/cpp/cpp-debug) | (not captured) / VS Code extension (ms-vscode.cpptools) |
| <a id="kali-156"></a>**VS Code extension: Python (ms-python.python)** | Select a Python interpreter for analysis scripts. | reference | [Reference](https://code.visualstudio.com/docs/python/environments) | (not captured) / VS Code extension (ms-python.python) |
| <a id="kali-157"></a>**YARA** | Create signatures and scan sample files. | next: [YARA rules](LEARNING_RESOURCES.md#reverse-7) | [Reference](https://yara.readthedocs.io/en/stable/writingrules.html) | 4.5.8 |
| <a id="kali-158"></a>**yara-python (and YARA on Linux)** | Compile YARA rules and scan files from Python. | reference | [Reference](https://yara.readthedocs.io/en/stable/yarapython.html) | (not captured) / pip (yara-python) |
| <a id="kali-159"></a>**zip** | Package files into ZIP archives. | reference | [Reference](https://infozip.sourceforge.net/Zip.html) | (not captured) / Installed; version not captured |
| <a id="kali-160"></a>**zstd** | Inspect and decompress Zstandard data. | reference | [Reference](https://github.com/facebook/zstd/blob/dev/programs/README.md) | 1.5.7 |
| <a id="kali-161"></a>**Zui (formerly Brim)** | Explore imported network-capture data. | reference | [Reference](https://github.com/brimdata/zui) | (not captured) / Version not captured (the command only printed a startup message) |

## Specialist tool choices

### Files and media

- Use ZBar for barcodes, xxd for hex, file for format identification, and foremost for carving. Carved files may lose names and paths; check recovered content.
- Use ImageMagick/G’MIC for channel manipulation, StegSolve for bit planes, and pngcheck/jpeginfo for integrity errors. zsteg does not replace these checks; installed forks and versions matter.
- MediaInfo inspects stream metadata; SoX_ng processes audio. The SSTV entry names a decoder, but its installation note names the PySSTV encoder: verify the installed program before relying on it.
- OpenStego and SNOW handle distinct carriers; ordinary PNG LSB analysis does not cover SNOW whitespace extraction.
- AperiSolve needs a working local service stack. Public upload of event files is forbidden. Sonic Visualiser’s linked 5.2.1 guide covers audio inspection.

### Web and network

- Burp/curl replay requests; ffuf, Feroxbuster, Gobuster and Katana offer different discovery workflows. Check scope and filtering before enumeration.
- Use SQLmap for relevant SQL injection evidence and jwt_tool for JWTs. Consult PayloadsAllTheThings for the specific vulnerability.
- Nmap, RustScan and Legion help inspect services. Impacket, Metasploit and Hydra need a matching target service and prerequisites.
- CAN utilities/cannelloni need bus artifacts; RTP tools need media traffic; Aircrack/hcxtools need suitable wireless captures and protocol knowledge.
- Subfinder needs network-backed passive sources. tcpdump captures packets; Zui explores captures; OpenVPN handles VPN access; Chrome DevTools inspects browser traffic.
- Burp Community supports manual Proxy/Repeater. Professional scanner, Collaborator, full Intruder and saved project files are outside that edition. Home-practice Docker targets do not expand event approval.

### Filesystems, memory and artifacts

- Choose ALEAPP, iLEAPP or mac_apt for supplied Android, iOS or macOS extractions. Check accepted input layout and OS support before parsing.
- Use Hindsight for browser artifacts, FQLite for supported deleted-record recovery, and SQLCipher when encryption requires its keys/settings. Preserve database WAL/SHM companions; deleted records may not survive.
- Choose RegRipper for a registry hive, Plaso for cross-artifact timelines, and Chainsaw or Hayabusa for EVTX analysis. Autopsy and MFTECmd cover different artifact workflows.
- Volatility 2 profiles/plugins and Volatility 3 symbols/plugins are separate compatibility paths. Check image and plugin support, including Linux symbols and SSH-session recovery.
- EWF, qemu-img, ESE and PFF tools address specific input formats. Use filesystem-aware TSK triage before carving; use FAT checks without repair on original evidence.
- qpdf inspects PDF structure; viewer and mutool commands differ. strings extracts text. Git and Gitleaks inspect repository history and potential secrets.

### Reversing and static analysis

- Use dnSpyEx for managed assemblies; native Ghidra/GDB workflows do not cover .NET metadata and debugging.
- JADX, Apktool, dex2jar, Android Studio, Bytecode Viewer and Fernflower address different APK, DEX and Java tasks. APK modification/emulation and native JNI need a prepared lab.
- pyinstxtractor-ng extracts PyInstaller executables. Check supported bytecode versions for pycdc, uncompyle6 and unpyc3; the host Python version alone does not establish compatibility.
- Choose a debugger suited to the binary and platform: GDB, x64dbg, OllyDbg, Cutter or radare2. GEF, peda and pwndbg extend GDB.
- Use capa for capability leads, FLOSS for strings and YARA for signatures. Didier tools, oletools, FakeNet-NG, AutoIt and format-specific unpackers need matching input and an appropriate analysis environment.
- Use angr for path constraints and ROPgadget for gadgets after establishing the relevant program behavior.

### Crypto, passwords and supporting tools

- crypto-attacks provides implementations and test vectors; specialized lattice tuning is outside the 24-hour sequence. factordb-python requires a network, and approval does not authorize transmitting challenge material.
- hlextend and padding-oracle-attacker require a matching vulnerable construction or oracle. PARI/GP is useful when a solver specifically requires that runtime.
- Treat hashid output as a hypothesis; confirm the algorithm from context and format before cracking. rockyou is a wordlist; check candidate encoding and line handling.
- OpenSSL decryption requires the correct cipher, key, IV and salt parameters. multimon-ng needs a suitable recorded signal and modulation knowledge.
- Consult GTFOBins or HackTricks for the particular binary or technique. Use familiar editors, runtimes and archive tools; Python 2 does not support the Python 3.8+ modular-inverse example.
