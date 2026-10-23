# All approved tools: study and reference index

Use the [24-hour guide](LEARNING_RESOURCES.md) first. All **200 organiser-approved rows** are retained with their original per-tool references. Counts are rows, not distinct packages. Core/next/reference describe study priority, not approval status.

Version/location notes are organiser data, not verified local behavior. Existing reference link checks are from October 19; not all 200 references were re-researched. The unspecified PDF Viewer uses an illustrative Adobe reference whose earlier access probe returned HTTP 403. Curated lesson evidence is separate.

## Windows list (some run in WSL)

| Approved row / tool | Use it for | Study | Documentation | Organiser version / location |
| --- | --- | --- | --- | --- |
| windows-1: **CyberChef** | Build a decoding recipe | core: [crypto-foundations-1](LEARNING_RESOURCES.md#crypto-foundations-1), [crypto-foundations-2](LEARNING_RESOURCES.md#crypto-foundations-2) | [Reference](https://github.com/gchq/CyberChef) | Latest (browser-based, no install) / Bookmark |
| windows-2: **Wireshark** | Inspect packet conversations | core: [web-network-5](LEARNING_RESOURCES.md#web-network-5), [web-network-8](LEARNING_RESOURCES.md#web-network-8) | [Reference](https://www.wireshark.org/docs/wsug_html_chunked/ChapterWork.html) | Latest / installed in Windows |
| windows-3: **PDF Viewer** | Inspect PDF text and attachments; viewer identity is unspecified | reference | [Reference](https://helpx.adobe.com/acrobat/desktop/edit-documents/use-links-and-attachments/open-attachment.html) | Any current version / installed in Windows |
| windows-4: **OpenVPN Client** | Connect using an approved VPN profile | reference | [Reference](https://openvpn.net/connect-docs/import-profile.html) | Latest / installed in Windows |
| windows-5: **Google Chrome** | Inspect browser requests | reference | [Reference](https://developer.chrome.com/docs/devtools/network/) | Latest / installed in Windows |
| windows-6: **Windows Subsystem for Linux (WSL)** | Use the installed Linux environment | reference | [Reference](https://learn.microsoft.com/en-us/windows/wsl/basic-commands) | Latest / installed in Windows |
| windows-7: **Python 3** | Parse binary data | core: [crypto-foundations-3](LEARNING_RESOURCES.md#crypto-foundations-3) | [Reference](https://docs.python.org/3/library/struct.html) | Latest 3.x — confirm exact version before install / installed in WSL / Libraries may be added freely EXCEPT any AI/ML-related library (e.g. no LLM, machine-learning, or generative-AI frameworks).  |
| windows-8: **uv** | Manage Python environments | reference | [Reference](https://docs.astral.sh/uv/pip/environments/) | Latest / installed in WSL / Same rule as Python 3 — any library OK except AI/ML-related packages |
| windows-9: **gdb** | Debug native binaries | core: [reverse-3](LEARNING_RESOURCES.md#reverse-3), [reverse-4](LEARNING_RESOURCES.md#reverse-4) | [Reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints.html) | Latest (distro package) / installed in WSL |
| windows-10: **objdump** | Inspect disassembly and sections | reference | [Reference](https://sourceware.org/binutils/docs/binutils/objdump.html) | Bundled with GNU Binutils / installed in WSL |
| windows-11: **strings** | Extract readable strings | reference | [Reference](https://sourceware.org/binutils/docs/binutils/strings.html) | Bundled with GNU Binutils / installed in WSL |
| windows-12: **zsteg** | Inspect PNG/BMP hidden data | core: [media-1](LEARNING_RESOURCES.md#media-1) | [Reference](https://github.com/zed-0xff/zsteg) | Latest (Ruby gem) / installed in WSL |
| windows-13: **binwalk** | Locate embedded files; verify installed major version | core: [media-2](LEARNING_RESOURCES.md#media-2) | [Reference](https://github.com/ReFirmLabs/binwalk) | Latest / installed in WSL |
| windows-14: **ExifTool** | Read file metadata | core: [media-3](LEARNING_RESOURCES.md#media-3), [media-8](LEARNING_RESOURCES.md#media-8) | [Reference](https://github.com/exiftool/exiftool) | Latest / installed in WSL |
| windows-15: **pdftotext (Poppler utils)** | Extract PDF text | reference | [Reference](https://manpages.debian.org/bookworm/poppler-utils/pdftotext.1.en.html) | Latest / installed in WSL |
| windows-16: **can-utils** | Read CAN bus logs | reference | [Reference](https://github.com/linux-can/can-utils) | Latest / installed in WSL |
| windows-17: **cannelloni** | Understand CAN tunneling | reference | [Reference](https://github.com/mguentner/cannelloni) | Latest / installed in WSL |
| windows-18: **zeek** | Produce protocol logs from packet captures | next: [web-network-7](LEARNING_RESOURCES.md#web-network-7) | [Reference](https://docs.zeek.org/en/current/quickstart.html) | Latest / installed in WSL |
| windows-19: **ZBar** | Decode barcodes locally | reference | [Reference](https://github.com/mchehab/zbar) | Latest / installed in WSL |
| windows-20: **Burp Suite Community Edition** | Inspect and replay web requests | core: [web-network-1](LEARNING_RESOURCES.md#web-network-1), [web-network-2](LEARNING_RESOURCES.md#web-network-2) | [Reference](https://portswigger.net/burp/documentation/desktop/tools/repeater) | 2026.4.x (confirm latest at install time) / installed in WSL |
| windows-21: **jq** | Filter JSON | reference | [Reference](https://jqlang.org/manual/) | Latest / installed in WSL |
| windows-22: **Ghidra** | Inspect program logic | core: [reverse-1](LEARNING_RESOURCES.md#reverse-1), [reverse-2](LEARNING_RESOURCES.md#reverse-2), [reverse-4](LEARNING_RESOURCES.md#reverse-4) | [Reference](https://github.com/NationalSecurityAgency/ghidra) | 12.1.4 / installed in WSL |
| windows-23: **The Sleuth Kit** | Inspect filesystem images | core: [forensics-1](LEARNING_RESOURCES.md#forensics-1) | [Reference](https://www.sleuthkit.org/sleuthkit/man/fls.html) | Latest / installed in WSL |
| windows-24: **OpenSSL** | Understand symmetric decryption parameters | reference | [Reference](https://docs.openssl.org/3.0/man1/openssl-enc/) | Latest 3.x / installed in WSL |
| windows-25: **xz** | Inspect and decompress XZ data | reference | [Reference](https://tukaani.org/xz/man/xz.1.html) | Latest / installed in WSL |
| windows-26: **qpdf** | Inspect PDF objects and streams | next: [forensics-6](LEARNING_RESOURCES.md#forensics-6) | [Reference](https://qpdf.readthedocs.io/en/stable/cli.html) | Latest / installed in WSL |
| windows-27: **llvm-mc (LLVM tools)** | Translate assembly and machine code | reference | [Reference](https://llvm.org/docs/CommandGuide/llvm-mc.html) | Latest / installed in WSL |
| windows-28: **xxd** | Convert hex dumps | reference | [Reference](https://github.com/vim/vim/blob/master/runtime/doc/xxd.1) | Bundled with Vim / installed in WSL |
| windows-29: **fsck.fat (dosfstools)** | Check FAT structure without repair | reference | [Reference](https://github.com/dosfstools/dosfstools/blob/master/manpages/fsck.fat.8.in) | Latest / installed in WSL |
| windows-30: **RsaCtfTool** | Study RSA attack prerequisites | core: [crypto-foundations-4](LEARNING_RESOURCES.md#crypto-foundations-4) | [Reference](https://github.com/RsaCtfTool/RsaCtfTool) | Latest (GitHub script, run via Python 3) / installed in WSL |
| windows-31: **volatility3** | Inspect Windows memory images | core: [forensics-3](LEARNING_RESOURCES.md#forensics-3), [forensics-4](LEARNING_RESOURCES.md#forensics-4) | [Reference](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html) | Latest / installed in WSL |
| windows-32: **OpenSSH-Session-Key-Recovery** | Recover SSH session keys from supported memory evidence | reference | [Reference](https://github.com/fox-it/OpenSSH-Session-Key-Recovery) | installed in volatility3 / Plugin for Volatility3 |
| windows-33: **x64dbg** | Debug Windows executables | reference | [Reference](https://help.x64dbg.com/en/latest/gui/tips.html) | Latest / installed in Windows / Portable zip (snapshot_*.zip). Extract and run; no installer. |
| windows-34: **Autopsy** | Inspect forensic images | core: [forensics-2](LEARNING_RESOURCES.md#forensics-2) | [Reference](https://sleuthkit.org/autopsy/docs/user-docs/4.22.0/ingest_page.html) | Latest / installed in Windows / MSI installer (bundles Java and The Sleuth Kit). Administrator rights required. |
| windows-35: **HxD** | Inspect bytes in a hex editor | reference | [Reference](https://mh-nexus.de/en/hxd/) | Latest / installed in Windows / Installer or portable edition. |
| windows-36: **tshark** | Extract packet fields | core: [web-network-6](LEARNING_RESOURCES.md#web-network-6), [web-network-8](LEARNING_RESOURCES.md#web-network-8) | [Reference](https://www.wireshark.org/docs/man-pages/tshark.html) | Latest / installed in Windows / Included in the Wireshark installer (TShark component). |
| windows-37: **Notepad++** | Search structured text | reference | [Reference](https://github.com/notepad-plus-plus/npp-usermanual/blob/master/content/docs/searching.md) | Latest / installed in Windows / Installer (x64). A portable edition is also available. |
| windows-38: **dnSpyEx (dnSpy)** | Inspect managed assemblies | reference: [reverse-8](LEARNING_RESOURCES.md#reverse-8) | [Reference](https://github.com/dnSpyEx/dnSpy) | Latest / installed in Windows / Portable zip. Use dnSpy-net-win64.zip (self-contained; no .NET installation needed). |
| windows-39: **Eric Zimmerman's Tools** | Select an artifact-specific Windows parser | core: [forensics-5](LEARNING_RESOURCES.md#forensics-5) | [Reference](https://ericzimmerman.github.io/) | Latest / installed in Windows / Run Get-ZimmermanTools.ps1 to download the tools. Internet access and the .NET Desktop Runtime are required. |

## Kali list (best-effort availability)

| Approved row / tool | Use it for | Study | Documentation | Organiser version / location |
| --- | --- | --- | --- | --- |
| kali-1: **.NET SDK** | Build and run managed projects | reference | [Reference](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet) | 6.0.400 |
| kali-2: **7-Zip (7z)** | Inspect and extract archives | reference | [Reference](https://7-zip.org/) | 26.02 |
| kali-3: **aircrack-ng** | Understand offline wireless capture analysis | reference | [Reference](https://www.aircrack-ng.org/doku.php?id=aircrack-ng) | 1.7 |
| kali-4: **ALEAPP (Android Logs Events And Protobuf Parser)** | Parse Android forensic artifacts | reference | [Reference](https://github.com/abrignoni/ALEAPP) | - / No installation information recorded |
| kali-5: **Android Studio** | Inspect Android packages | reference | [Reference](https://developer.android.com/studio/debug/apk-debugger) | - / No installation information recorded |
| kali-6: **angr** | Study path constraints and symbolic execution | reference | [Reference](https://docs.angr.io/en/latest/core-concepts/pathgroups.html) | (not captured) / pipx (angr) |
| kali-7: **AperiSolve** | Understand local image-analysis deployment | reference: [media-7](LEARNING_RESOURCES.md#media-7) | [Reference](https://github.com/Zeecka/AperiSolve) | (not captured) / git (/opt/tools/AperiSolve) |
| kali-8: **Apktool** | Decode Android resources and smali | reference | [Reference](https://apktool.org/docs/cli-parameters/) | 2.7.0-dirty |
| kali-9: **asar (@electron/asar)** | Inspect Electron archives | reference | [Reference](https://github.com/electron/asar) | 4.3.1 |
| kali-10: **Audacity** | Inspect audio frequency content | core: [media-5](LEARNING_RESOURCES.md#media-5) | [Reference](https://manual.audacityteam.org/man/spectrogram_view.html) | (not captured) / /usr/bin/audacity |
| kali-11: **AutoIt-Ripper** | Extract compiled AutoIt scripts | reference | [Reference](https://github.com/nazywam/AutoIt-Ripper) | (not captured) / pipx (autoit-ripper) |
| kali-12: **BinDiff** | Compare compiled program versions | reference | [Reference](https://www.zynamics.com/bindiff/manual/) | 8 / Build @568181968 (Sep 25 2023) |
| kali-13: **bkcrack** | Understand ZIP known-plaintext recovery | next: [crypto-foundations-8](LEARNING_RESOURCES.md#crypto-foundations-8) | [Reference](https://github.com/kimci86/bkcrack) | 1.8.1 (2025-10-25) |
| kali-14: **bulk_extractor** | Extract forensic features from bulk data | reference | [Reference](https://github.com/simsong/bulk_extractor) | 2.1.1 |
| kali-15: **bvi** | Inspect binary data | reference | [Reference](https://bvi.sourceforge.net/) | (not captured) / Interactive tool; the version check returned 'Input is not from a terminal' |
| kali-16: **Bytecode Viewer** | Inspect Java bytecode | reference | [Reference](https://github.com/Konloch/bytecode-viewer) | 2.13.2 / Fat Jar |
| kali-17: **bzip2** | Decompress BZip2 data | reference | [Reference](https://sourceware.org/bzip2/manual/manual.html) | 1.0.8 |
| kali-18: **cabextract** | Inspect Microsoft cabinet archives | reference | [Reference](https://www.kali.org/tools/cabextract/) | 1.11 |
| kali-19: **capa** | Identify executable capabilities | core: [reverse-5](LEARNING_RESOURCES.md#reverse-5) | [Reference](https://github.com/mandiant/capa) | 9.4.0 |
| kali-20: **Chainsaw** | Search Windows event logs | next: [forensics-7](LEARNING_RESOURCES.md#forensics-7) | [Reference](https://github.com/WithSecureOpenSource/chainsaw) | 2.16.5 |
| kali-21: **checksec** | Identify executable protections | reference | [Reference](https://github.com/slimm609/checksec/releases) | 2.6.0 |
| kali-22: **crypto-attacks** | Find mathematical attack implementations | reference | [Reference](https://github.com/jvdsn/crypto-attacks) | (not captured) / git (/opt/tools/crypto-attacks) |
| kali-23: **curl** | Inspect and reproduce HTTP requests | core: [web-network-3](LEARNING_RESOURCES.md#web-network-3) | [Reference](https://curl.se/docs/manpage.html) | 8.21.0 |
| kali-24: **Cutter** | Inspect program control flow | reference | [Reference](https://github.com/rizinorg/cutter) | (not captured) / AppImage (/opt/tools/cutter.AppImage) / The GUI needs FUSE |
| kali-25: **DB Browser for SQLite** | Inspect SQLite records | reference | [Reference](https://sqlitebrowser.org/) | 3.13.1 |
| kali-26: **DBeaver Community Edition** | Query local databases | reference | [Reference](https://dbeaver.com/docs/dbeaver/SQL-Execution/) | 26.1.3 |
| kali-27: **Detect It Easy (DIE)** | Identify binary formats and packers | reference | [Reference](https://github.com/horsicq/Detect-It-Easy) | 3.21 |
| kali-28: **dex2jar** | Convert Android bytecode to a JAR for Java analysis. | reference | [Reference](https://github.com/pxb1988/dex2jar) | 2.1-nightly-28 |
| kali-29: **Didier Stevens Beta tools (onedump.py)** | Inspect objects in a OneNote document. | reference | [Reference](https://github.com/DidierStevens/Beta/blob/master/onedump.py) | (not captured) / git (/opt/tools/Beta) |
| kali-30: **Didier Stevens Suite (pdfid.py, pdf-parser.py, oledump.py and others)** | Triage Office macros and PDF objects. | reference | [Reference](https://github.com/DidierStevens/DidierStevensSuite) | (not captured) / git (/opt/tools/DidierStevensSuite) |
| kali-31: **Docker Engine and Compose plugin** | Run and inspect a local container lab. | reference | [Reference](https://docs.docker.com/compose/) | 28.5.2+dfsg4 |
| kali-32: **dwarf2json** | Generate Linux memory-analysis symbols. | reference | [Reference](https://github.com/volatilityfoundation/dwarf2json) | 0.9.0 |
| kali-33: **Eclipse Temurin JDK (OpenJDK)** | Run Java tools and inspect class bytecode. | reference | [Reference](https://adoptium.net/temurin) | 25.0.4 (2026-07-21) / Reported as 'openjdk' |
| kali-34: **ewf-tools (libewf)** | Read or export an E01 disk image. | reference | [Reference](https://github.com/libyal/libewf) | 20140816 |
| kali-35: **Exploit-DB / searchsploit (offline archive)** | Search the local Exploit-DB archive. | reference | [Reference](https://www.exploit-db.com/searchsploit) | 2026-08-19 / Version is the archive date |
| kali-36: **factordb-python** | Look up known integer factors. | reference | [Reference](https://github.com/ryosan-470/factordb-python) | (not captured) / pip (factordb-python) |
| kali-37: **FakeNet-NG** | Observe network behavior in a malware lab. | reference | [Reference](https://github.com/mandiant/flare-fakenet-ng) | (not captured) / /opt/tools/flare-fakenet-ng (fakenet in PATH) |
| kali-38: **Fernflower** | Decompile Java classes and JARs. | reference | [Reference](https://github.com/JetBrains/fernflower/blob/master/README.md) | (not captured) / /opt/tools/fernflower/build/libs/fernflower.jar (/usr/local/bin/fernflower) |
| kali-39: **Feroxbuster** | Find web paths in an authorized lab. | reference | [Reference](https://github.com/epi052/feroxbuster) | 2.13.1 |
| kali-40: **FFmpeg** | Extract frames or audio from media. | next: [media-6](LEARNING_RESOURCES.md#media-6) | [Reference](https://ffmpeg.org/ffmpeg.html) | (not captured) / apt (ffmpeg) |
| kali-41: **ffuf** | Compare web responses during controlled fuzzing. | next: [web-network-4](LEARNING_RESOURCES.md#web-network-4) | [Reference](https://github.com/ffuf/ffuf) | 2.1.0-dev |
| kali-42: **file (libmagic)** | Identify unknown file formats. | reference | [Reference](https://github.com/file/file) | 5.47 |
| kali-43: **FLOSS (FLARE Obfuscated String Solver)** | Recover obscured strings from binaries. | core: [reverse-6](LEARNING_RESOURCES.md#reverse-6) | [Reference](https://github.com/mandiant/flare-floss) | (not captured) / pipx (flare-floss) |
| kali-44: **foremost** | Carve files from raw evidence. | reference | [Reference](https://www.kali.org/tools/foremost/) | (not captured) / Installed; version not captured |
| kali-45: **FQLite** | Inspect deleted SQLite records. | reference | [Reference](https://github.com/pawlaszczyk/fqlite) | (not captured) / /opt/fqlite/bin/fqlite (symlinked to /usr/local/bin) |
| kali-46: **Frida** | Observe runtime function calls. | reference | [Reference](https://frida.re/docs/javascript-api/) | 17.23.3 |
| kali-47: **GCC, G++ and build tools (build-essential, make, CMake, pkg-config)** | Build small local programs with debug information. | reference | [Reference](https://gcc.gnu.org/onlinedocs/gcc/Debugging-Options.html) | 15.3.0 / Debian gcc 15.3.0-2 |
| kali-48: **GEF (GDB Enhanced Features)** | Inspect register and stack state in GDB. | reference | [Reference](https://hugsy.github.io/gef/) | (not captured) / /opt/tools/gef.py / Load with: gdb -x /opt/tools/gef.py. Not auto-sourced, to avoid a clash with peda |
| kali-49: **Git** | Trace file history in a local repository. | reference | [Reference](https://git-scm.com/docs/git-log) | 2.53.0 |
| kali-50: **Gitleaks** | Locate exposed secrets in local repository history. | reference | [Reference](https://github.com/gitleaks/gitleaks) | (not captured) / The tool does not report a version (set at build time) |
| kali-51: **G'MIC (gmic)** | Inspect image channels and contrast. | reference | [Reference](https://gmic.eu/reference/) | (not captured) / Version not captured (the command started the G'MIC interpreter) |
| kali-52: **GNU Wget** | Save public files for local analysis. | reference | [Reference](https://www.gnu.org/software/wget/manual/wget.html) | 1.25.0 |
| kali-53: **Go** | Build or run local Go utilities. | reference | [Reference](https://go.dev/doc/cmd) | 1.26.5 |
| kali-54: **Gobuster** | Discover web directories or virtual hosts. | reference | [Reference](https://github.com/OJ/gobuster) | 3.8.2 |
| kali-55: **GoReSym** | Recover symbols in a Go binary. | reference | [Reference](https://github.com/mandiant/GoReSym) | (not captured) / go install (github.com/mandiant/GoReSym@latest) |
| kali-56: **GTFOBins (offline copy)** | Interpret permitted binary functions in a CTF lab. | reference | [Reference](https://gtfobins.org/) | (not captured) / git (/opt/tools/GTFOBins.github.io) |
| kali-57: **gzip** | Unpack and check gzip files. | reference | [Reference](https://www.gnu.org/software/gzip/manual/gzip.html) | 1.13 |
| kali-58: **HackTricks (offline copy)** | Find a technique checklist for a lab task. | reference | [Reference](https://github.com/HackTricks-wiki/hacktricks) | (not captured) / git (/opt/tools/hacktricks) |
| kali-59: **hashcat** | Match hash formats and choose a recovery mode. | core: [crypto-foundations-6](LEARNING_RESOURCES.md#crypto-foundations-6) | [Reference](https://hashcat.net/wiki/doku.php?id=example_hashes) | 7.1.2 |
| kali-60: **hashid** | Suggest possible hash formats. | reference | [Reference](https://github.com/psypanda/hashID) | 3.1.4 |
| kali-61: **Hayabusa** | Build a Windows event timeline. | reference | [Reference](https://github.com/Yamato-Security/hayabusa) | (not captured) / Version not captured (the --version option is not supported) |
| kali-62: **hcxtools** | Convert captured wireless authentication data. | reference | [Reference](https://github.com/ZerBea/hcxtools) | 7.1.2 / Version of hcxpcapngtool |
| kali-63: **Hindsight (pyhindsight)** | Parse a saved browser profile. | reference | [Reference](https://github.com/RyanDFIR/hindsight) | (not captured) / pipx (pyhindsight) |
| kali-64: **hlextend** | Explore hash length extension with generic examples. | reference | [Reference](https://github.com/stephenbradshaw/hlextend) | (not captured) / Python module (/usr/local/lib/python3.14/dist-packages/hlextend.py) |
| kali-65: **Hydra** | Understand form authentication test syntax. | reference | [Reference](https://github.com/vanhauser-thc/thc-hydra) | (not captured) / Installed; version not captured |
| kali-66: **iLEAPP (iOS Logs, Events, And Plists Parser)** | Parse iOS forensic artifacts. | reference | [Reference](https://github.com/abrignoni/iLEAPP) | - / No installation information recorded |
| kali-67: **ImageMagick** | Inspect image channels and properties. | reference | [Reference](https://imagemagick.org/command-line-processing/) | 7.1.2-27 |
| kali-68: **Impacket** | Work with SMB and network protocol examples. | reference | [Reference](https://github.com/fortra/impacket) | 0.14.0 |
| kali-69: **innoextract** | Unpack an Inno Setup installer. | reference | [Reference](https://constexpr.org/innoextract/) | dev build |
| kali-70: **internet_detector** | Simulate internet services in a malware lab. | reference | [Reference](https://www.inetsim.org/) | (not captured) / apt (inetsim) / Provided by the apt package 'inetsim' |
| kali-71: **IPython** | Explore Python objects and run small scripts. | reference | [Reference](https://ipython.readthedocs.io/en/stable/interactive/tutorial.html) | 9.17.1 |
| kali-72: **jadx (jadx-gui)** | Inspect Android application logic. | reference: [reverse-9](LEARNING_RESOURCES.md#reverse-9) | [Reference](https://github.com/skylot/jadx) | 1.5.6 |
| kali-73: **John the Ripper (jumbo)** | Prepare and recover passwords from local test data. | core: [crypto-foundations-7](LEARNING_RESOURCES.md#crypto-foundations-7) | [Reference](https://www.openwall.com/john/doc/) | 1.9.0-Jumbo-1 |
| kali-74: **Jpeginfo** | Check JPEG structure and integrity. | reference | [Reference](https://github.com/tjko/jpeginfo) | 1.7.1 |
| kali-75: **js-beautify** | Format compressed JavaScript for inspection. | reference | [Reference](https://github.com/beautifier/js-beautify) | 2.0.3 |
| kali-76: **js-deobfuscator** | Simplify JavaScript string arrays and proxy functions. | reference | [Reference](https://github.com/ben-sb/javascript-deobfuscator) | (not captured) / npm (js-deobfuscator) |
| kali-77: **jwt_tool** | Inspect and test JSON Web Tokens. | reference | [Reference](https://github.com/ticarpi/jwt_tool) | (not captured) / /opt/tools/jwt_tool (/usr/local/bin/jwt_tool) |
| kali-78: **Katana** | Discover in-scope URLs and application routes. | reference | [Reference](https://docs.projectdiscovery.io/opensource/katana/usage) | (not captured) / go install (github.com/projectdiscovery/katana/cmd/katana@latest) |
| kali-79: **legion** | Organize network discovery in a lab. | reference | [Reference](https://github.com/Abacus-Group-RTO/legion) | 0.7.0 |
| kali-80: **libesedb tools** | Inspect Windows ESE database tables. | reference | [Reference](https://github.com/libyal/libesedb) | 20240420 / Version of esedbexport |
| kali-81: **LibreOffice** | Convert documents to inspectable formats. | reference | [Reference](https://help.libreoffice.org/latest/en-US/text/shared/guide/start_parameters.html) | 26.8.0.3 |
| kali-82: **lrzip** | Unpack long-range compressed files. | reference | [Reference](https://github.com/ckolivas/lrzip) | 0.660 |
| kali-83: **ltrace** | Observe dynamic library calls. | reference | [Reference](https://ltrace.org/) | 0.7.91 |
| kali-84: **lz4** | Unpack LZ4 data. | reference | [Reference](https://github.com/lz4/lz4) | 1.10.0 |
| kali-85: **lzip** | Unpack and check lzip files. | reference | [Reference](https://www.nongnu.org/lzip/manual/lzip_manual.html) | 1.26 |
| kali-86: **mac_apt** | Parse macOS artifacts from saved evidence. | reference | [Reference](https://github.com/ydkhatri/mac_apt) | (not captured) / git (/opt/tools/mac_apt) |
| kali-87: **MediaInfo** | Inspect media container and codec information. | reference | [Reference](https://mediaarea.net/en/MediaInfo) | (not captured) / Version not captured |
| kali-88: **Metasploit Framework** | Navigate module documentation in a local lab. | reference | [Reference](https://docs.metasploit.com/) | 6.5.2-dev |
| kali-89: **mimikatz** | Understand offline Windows authentication-dump analysis. | reference | [Reference](https://github.com/gentilkiwi/mimikatz/wiki) | 2.2.0 / Wine (Windows binary) |
| kali-90: **Miniforge3 (conda)** | Create a separate dependency environment. | reference | [Reference](https://github.com/conda-forge/miniforge) | (not captured) / /home/kali/miniforge3 |
| kali-91: **multimon-ng** | Decode supported audio modulation formats. | reference | [Reference](https://github.com/EliasOenal/multimon-ng) | (not captured) / apt (multimon-ng) |
| kali-92: **mupdf-tools (mutool)** | Inspect PDF objects and extract resources. | reference | [Reference](https://mupdf.readthedocs.io/en/latest/tools/mutool.html) | 1.27.0 |
| kali-93: **NASM (Netwide Assembler)** | Assemble or inspect x86 instructions. | reference | [Reference](https://www.nasm.us/docs.html) | 3.01 |
| kali-94: **Nmap (with Ncat / Nping)** | Identify services and inspect network connectivity. | next: [web-network-9](LEARNING_RESOURCES.md#web-network-9) | [Reference](https://www.kali.org/tools/nmap/) | 7.99 |
| kali-95: **Node.js (with npm)** | Convert binary representations in JavaScript. | reference | [Reference](https://nodejs.org/docs/latest-v24.x/api/buffer.html) | 24.21.0 |
| kali-96: **obfuscator-io-deobfuscator** | Recover readable JavaScript from Obfuscator.io output. | reference | [Reference](https://github.com/ben-sb/obfuscator-io-deobfuscator) | 1.0.6 |
| kali-97: **Obsidian** | Organize investigation notes with links. | reference | [Reference](https://help.obsidian.md/links) | (not captured) / Version not captured; startup reported that ~/.config/obsidian/obsidian.json does not exist |
| kali-98: **oletools (full suite: olevba, oleid, oleobj, rtfobj, mraptor, msodde, olemeta, oletimes, pyxswf)** | Inspect Office documents and extract macros or embedded objects. | reference | [Reference](https://github.com/decalage2/oletools) | (not captured) / pipx (oletools) |
| kali-99: **OllyDbg** | Debug 32-bit Windows executables. | reference | [Reference](https://www.ollydbg.de/quickst.htm) | 1.10-1kali5 / Wine (Windows binary) |
| kali-100: **OpenStego** | Extract data hidden using OpenStego. | reference | [Reference](https://www.openstego.com/) | (not captured) / GitHub .deb package |
| kali-101: **padding-oracle-attacker** | Understand the tool's padding oracle input and response options. | reference | [Reference](https://github.com/KishanBagaria/padding-oracle-attacker) | (not captured) / Version not captured (the command printed a banner only) |
| kali-102: **PARI/GP** | Explore modular arithmetic and discrete logarithms. | reference | [Reference](https://pari.math.u-bordeaux.fr/dochtml/html-stable/Arithmetic_functions.html) | 2.17.4 |
| kali-103: **PayloadsAllTheThings (offline copy)** | Find a structured web vulnerability reference. | reference | [Reference](https://github.com/swisskyrepo/PayloadsAllTheThings) | (not captured) / git (/opt/tools/PayloadsAllTheThings) |
| kali-104: **peda** | Inspect debugging state and cyclic-pattern offsets. | reference | [Reference](https://github.com/longld/peda) | (not captured) / /opt/tools/peda (sourced in ~/.gdbinit) |
| kali-105: **peepdf-3** | Inspect PDF objects and streams. | reference | [Reference](https://github.com/digitalsleuth/peepdf-3) | (not captured) / pipx (peepdf-3) |
| kali-106: **pff-tools (libpff)** | Inspect and extract Outlook personal-folder data. | reference | [Reference](https://github.com/libyal/libpff) | 20231205 / Version of pffexport |
| kali-107: **Plaso (log2timeline, psort, pinfo)** | Build a forensic timeline from artifacts. | reference | [Reference](https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html) | 20260119-1kali1 |
| kali-108: **pngcheck** | Inspect PNG structure and integrity. | reference | [Reference](https://github.com/pnggroup/pngcheck) | (not captured) / apt (pngcheck) |
| kali-109: **pwndbg** | Inspect binary debugging state and offsets. | reference | [Reference](https://pwndbg.re/stable/commands/) | (not captured) / /opt/tools/pwndbg / setup.sh completed |
| kali-110: **pycdc (Decompyle++)** | Decompile or disassemble Python bytecode. | reference | [Reference](https://github.com/zrax/pycdc) | (not captured) / Version not captured (no --version option) |
| kali-111: **pyinstxtractor-ng** | Extract files bundled by PyInstaller. | reference: [reverse-10](LEARNING_RESOURCES.md#reverse-10) | [Reference](https://github.com/pyinstxtractor/pyinstxtractor-ng) | (not captured) / pipx (pyinstxtractor-ng) |
| kali-112: **pypykatz** | Parse a supplied Windows memory dump. | reference | [Reference](https://github.com/skelsec/pypykatz) | 0.6.13 |
| kali-113: **Python 2.7** | Read binary records in legacy Python scripts. | reference | [Reference](https://docs.python.org/2.7/library/struct.html) | 2.7.18 |
| kali-114: **Python 3.11 (via uv)** | Select Python 3.11 through uv; workbook records no installation information. | core: [crypto-foundations-3](LEARNING_RESOURCES.md#crypto-foundations-3) | [Reference](https://docs.astral.sh/uv/guides/install-python/) | - / No installation information recorded |
| kali-115: **qemu-img (qemu-utils)** | Identify and convert virtual disk formats. | reference | [Reference](https://www.qemu.org/docs/master/tools/qemu-img.html) | 11.0.3 |
| kali-116: **radare2** | Locate and disassemble binary functions. | reference | [Reference](https://book.rada.re/analysis/intro.html) | 6.0.5 |
| kali-117: **rat-king-parser** | Extract configuration from supported RAT families. | reference | [Reference](https://github.com/jeFF0Falltrades/rat_king_parser) | 4.2.4 |
| kali-118: **RegRipper** | Extract artifacts from offline Windows registry hives. | reference | [Reference](https://github.com/keydet89/RegRipper3.0) | 3.0 |
| kali-119: **ripgrep (rg)** | Search text and selectively include hidden or binary files. | reference | [Reference](https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md) | 15.2.0 |
| kali-120: **rockyou.txt (Kali 'wordlists' package)** | Locate the approved password dictionary. | core: [crypto-foundations-6](LEARNING_RESOURCES.md#crypto-foundations-6), [crypto-foundations-7](LEARNING_RESOURCES.md#crypto-foundations-7) | [Reference](https://www.kali.org/tools/wordlists/) | (not captured) / /usr/share/wordlists/rockyou.txt |
| kali-121: **ROPgadget** | Find instruction gadgets in a binary. | reference | [Reference](https://github.com/JonathanSalwan/ROPgadget) | 7.7 |
| kali-122: **rtptools (rtpdump, rtpplay and others)** | Inspect or replay RTP recordings. | reference | [Reference](https://github.com/irtlab/rtptools) | (not captured) / /opt/tools/rtptools / Built from source |
| kali-123: **Rust (rustup, rustc, cargo)** | Build and run a Rust analysis utility. | reference | [Reference](https://doc.rust-lang.org/book/ch01-03-hello-cargo.html) | 1.95.0 (2026-04-14) / Built from a source tarball |
| kali-124: **rustscan** | Understand port discovery and scanner options. | reference | [Reference](https://github.com/RustScan/RustScan/wiki/Usage) | 2.4.1 |
| kali-125: **SageMath** | Explore discrete logarithms; workbook records no installation information. | core: [crypto-foundations-3](LEARNING_RESOURCES.md#crypto-foundations-3), [crypto-foundations-5](LEARNING_RESOURCES.md#crypto-foundations-5) | [Reference](https://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html) | - / No installation information recorded |
| kali-126: **SecLists** | Select a wordlist suited to a web discovery task. | next: [web-network-4](LEARNING_RESOURCES.md#web-network-4) | [Reference](https://github.com/danielmiessler/SecLists) | (not captured) / /usr/bin/seclists |
| kali-127: **socat** | Connect standard input to a TCP service. | reference | [Reference](https://www.kali.org/tools/socat/) | 1.8.1.3 |
| kali-128: **Sonic Visualiser** | Inspect audio with spectrogram layers. | next: [media-8](LEARNING_RESOURCES.md#media-8) | [Reference](https://www.sonicvisualiser.org/doc/reference/5.2.1/en/) | 5.2.1 |
| kali-129: **SoX (Sound eXchange)** | Generate audio spectrograms with the workbook-reported SoX_ng build; confirm local command options. | reference | [Reference](https://codeberg.org/sox_ng/sox_ng) | 14.7.1.2 / SoX_ng build |
| kali-130: **SQLCipher Community Edition — CLI** | Open a SQLCipher database with its known key and settings. | reference | [Reference](https://www.zetetic.net/sqlcipher/sqlcipher-api/) | SQLite 3.53.4 / SQLCipher 4.18.0 |
| kali-131: **sqlite3** | Inspect a SQLite database without changing it. | next: [forensics-8](LEARNING_RESOURCES.md#forensics-8) | [Reference](https://sqlite.org/cli.html) | 3.53.4 |
| kali-132: **sqlmap** | Understand sqlmap options for an authorized test request. | reference | [Reference](https://github.com/sqlmapproject/sqlmap/wiki/Usage) | 1.10.8 (stable) |
| kali-133: **sstv (command-line SSTV decoder)** | Decode SSTV audio; installed identity uncertain because workbook location lists the PySSTV encoder. | reference | [Reference](https://github.com/colaclanth/sstv) | (not captured) / pip (PySSTV); decoder name / PySSTV encoder installation mismatch |
| kali-134: **steghide** | Inspect and extract a steghide carrier. | core: [media-4](LEARNING_RESOURCES.md#media-4) | [Reference](https://www.kali.org/tools/steghide/) | 0.6.0 |
| kali-135: **stegseek** | Recover data from steghide carriers. | core: [media-4](LEARNING_RESOURCES.md#media-4) | [Reference](https://github.com/RickdeJager/stegseek) | 0.6 |
| kali-136: **stegsnow (SNOW)** | Decode whitespace-based hidden data. | reference | [Reference](https://www.darkside.com.au/snow/) | (not captured) / apt (stegsnow) |
| kali-137: **StegSolve** | Inspect image bit planes; installed StegSolve version and fork are unknown. | reference | [Reference](https://github.com/Giotino/stegsolve) | (not captured) / Version not captured (GUI tool; it was started without a display) |
| kali-138: **strace** | Observe a program's file and system-call behavior. | reference | [Reference](https://strace.io/) | 7.0 |
| kali-139: **Subfinder** | Collect publicly reported subdomains. | reference | [Reference](https://docs.projectdiscovery.io/tools/subfinder/usage) | 2.16.0 |
| kali-140: **Sublime Text** | Search source and notes in an editor. | reference | [Reference](https://www.sublimetext.com/docs/) | Build 4215 |
| kali-141: **tar** | List and extract archive members. | reference | [Reference](https://www.gnu.org/software/tar/manual/html_node/extract.html) | 1.35 |
| kali-142: **tcpdump** | Inspect captured packets with filters. | reference | [Reference](https://www.tcpdump.org/manpages/tcpdump.1.html) | 4.99.6 |
| kali-143: **TestDisk and PhotoRec** | Recover files from a disk image. | reference | [Reference](https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step) | 7.2 |
| kali-144: **unar** | List and extract supported archive formats. | reference | [Reference](https://theunarchiver.com/command-line) | 1.10.8 |
| kali-145: **uncompyle6** | Recover source from supported Python bytecode. | reference | [Reference](https://github.com/rocky/python-uncompyle6) | 3.9.3 |
| kali-146: **unpyc3 (unpyc37-3.10)** | Decompile supported Python bytecode; this fork has only minimal Python 3.10 support. | reference | [Reference](https://github.com/greyblue9/unpyc37-3.10) | (not captured) / git (/opt/tools/unpyc3) |
| kali-147: **unrar** | List, test and extract RAR archives. | reference | [Reference](https://www.rarlab.com/rar_add.htm) | (not captured) / /usr/bin/unrar |
| kali-148: **unzip** | List and extract ZIP members. | reference | [Reference](https://infozip.sourceforge.net/UnZip.html) | 6.0-30 |
| kali-149: **UPX** | Check and unpack a UPX-packed executable. | reference | [Reference](https://github.com/upx/upx/blob/devel/doc/upx-doc.txt) | 4.2.4 |
| kali-150: **Visual Studio Code** | Search and edit analysis code. | reference | [Reference](https://code.visualstudio.com/docs/editor/codebasics) | 1.141.2 |
| kali-151: **Volatility 2** | Identify a memory image profile and inspect processes. | reference | [Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) | (not captured) / git (/opt/tools/volatility) |
| kali-152: **Volatility 2 community plugins** | Load community plugins for Volatility 2. | reference | [Reference](https://github.com/volatilityfoundation/community) | (not captured) / git (/opt/tools/community) |
| kali-153: **Volatility 2 profiles (Linux and macOS)** | Match Linux or macOS profiles to memory images. | reference | [Reference](https://github.com/volatilityfoundation/profiles) | (not captured) / git (/opt/tools/profiles) |
| kali-154: **Volatility 3 community plugins (community3)** | Load Volatility 3 community plugins; check each plugin against the installed release. | reference | [Reference](https://github.com/volatilityfoundation/community3) | (not captured) / git (/opt/tools/community3) |
| kali-155: **VS Code extension: C/C++ (ms-vscode.cpptools)** | Configure C/C++ source debugging. | reference | [Reference](https://code.visualstudio.com/docs/cpp/cpp-debug) | (not captured) / VS Code extension (ms-vscode.cpptools) |
| kali-156: **VS Code extension: Python (ms-python.python)** | Select a Python interpreter for analysis scripts. | reference | [Reference](https://code.visualstudio.com/docs/python/environments) | (not captured) / VS Code extension (ms-python.python) |
| kali-157: **YARA** | Create signatures and scan sample files. | next: [reverse-7](LEARNING_RESOURCES.md#reverse-7) | [Reference](https://yara.readthedocs.io/en/stable/writingrules.html) | 4.5.8 |
| kali-158: **yara-python (and YARA on Linux)** | Compile YARA rules and scan files from Python. | reference | [Reference](https://yara.readthedocs.io/en/stable/yarapython.html) | (not captured) / pip (yara-python) |
| kali-159: **zip** | Package files into ZIP archives. | reference | [Reference](https://infozip.sourceforge.net/Zip.html) | (not captured) / Installed; version not captured |
| kali-160: **zstd** | Inspect and decompress Zstandard data. | reference | [Reference](https://github.com/facebook/zstd/blob/dev/programs/README.md) | 1.5.7 |
| kali-161: **Zui (formerly Brim)** | Explore imported network-capture data. | reference | [Reference](https://github.com/brimdata/zui) | (not captured) / Version not captured (the command only printed a startup message) |

## Why some families stay reference-only

The 24-hour path teaches representative workflows. These decisions preserve distinct tools and their limitations instead of treating a shared category as complete coverage.

### File triage and media

- ZBar, xxd, file and foremost are short task-driven identification/conversion/carving lookups. They support triage but do not each justify another long lesson; keep each existing reference and consult it when QR, hex, unknown-format or carving evidence appears.
- Image channels and integrity remain an important reference family. zsteg does not replace visual bit-plane inspection or PNG/JPEG validation. Keep ImageMagick/G’MIC channel manipulation, StegSolve bit planes and pngcheck/jpeginfo integrity references; prioritise these on a challenge with damaged headers, CRC errors or visible channel clues. Installed fork/version remains relevant.
- MediaInfo and SoX_ng overlap common inspection covered by FFmpeg/Audacity; keep reference-only to avoid repeat lessons. SSTV is a distinct narrow encoding and must remain discoverable, but the decoder-versus-PySSTV package mismatch prevents treating execution as a dependable flight prerequisite.
- OpenStego-specific and SNOW whitespace extraction are recognisable narrow branches. Retain existing direct references and lookup triggers; generic PNG LSB or audio study does not imply mastery of these formats.
- AperiSolve is reference-only because local deployment preparation is substantial and its analyzer set overlaps individually taught tools; public upload is forbidden for event artifacts.
- Sonic Visualiser is covered by the free reading alternative and optional audio investigation, rather than a duplicate full audio-editor lesson. Its v5.2.1 reference matches the workbook version.

### Web and network evidence

- Burp/curl/ffuf form one inspect-replay-enumerate workflow; Feroxbuster/Gobuster/Katana stay reference-only to avoid repeating discovery introductions.
- SQLmap and jwt_tool are vulnerability-specific lookups after identifying relevant SQL/JWT evidence; PayloadsAllTheThings remains indexed reference, not cover-to-cover reading.
- Nmap gets a short state/service refresher; RustScan/Legion repeat reconnaissance setup, and Impacket/Metasploit/Hydra require a specific service/target, so retain their exact approved references.
- CAN utilities/cannelloni and RTP tools need matching bus/media artifacts; wireless Aircrack/hcxtools need captures and protocol prerequisites. Keep references rather than requiring hardware/live work on a plane.
- Subfinder is the sole OSINT entry in this lane and needs network-backed passive sources; explicitly reference-only.
- tcpdump and Zui overlap the selected packet workflow; retain their tool-specific references. OpenVPN setup and Chrome DevTools remain utility lookups.
- Community manual tools are usable; Professional scanner, Collaborator, full Intruder and saved project files must not be implied by the training plan. Supplemental ffufme/Docker home practice does not expand event approval.

### Filesystem, memory and artifact analysis

- Keep ALEAPP/iLEAPP/mac_apt reference-only: input acquisition formats and OS versions determine useful parsers, and no corresponding evidence set is assumed. Trigger: a supplied Android/iOS/macOS extraction. First consult the row repository for accepted input layout and output reports; generic disk lessons do not teach these tools.
- SQLite schema/query training is transferable but not a substitute for Hindsight browser artifacts, FQLite deleted-record recovery or SQLCipher keys/settings. Keep these interfaces reference-only; use the input-specific parser when ordinary SQLite inspection cannot answer the question. Preserve supplied database companions; no guarantee deleted records survive.
- Autopsy and the MFTECmd/Chainsaw lessons cover artifact selection and output reasoning, not standalone RegRipper, Plaso or Hayabusa operation. Keep row docs: choose RegRipper for a specific hive, Plaso for cross-artifact timelines, Hayabusa as the alternate EVTX workflow rather than learning two event hunters during the first pass.
- Volatility 2, its profiles/plugins and Volatility 3 symbols/plugins are separate compatibility paths. The core teaches only approved windows-31 Volatility 3. Linux symbol generation, SSH-session recovery and credential artifacts stay reference-only until the evidence requires them; no promise that installed plugins support a particular image.
- Keep EWF/qemu-img/ESE/PFF and bulk/carving/FAT-check docs as format-triggered references. They solve different obstacles, not mandatory extra stages for every challenge. Filesystem-aware TSK triage comes first; carving may lose names/paths and cannot guarantee recovery.
- Preserve each row reference without a separate course. qpdf covers structural PDF inspection; it does not teach every viewer or mutool. strings retains its GNU documentation after the old TSK lesson is replaced. Git/Gitleaks are evidence-specific history/search workflows, not part of the disk-memory sequence.

### Reversing and static triage

- dnSpyEx is the sole selected managed-code routing reference. Native Ghidra/GDB proficiency does not establish .NET expertise; keep a short reference until a real managed assembly warrants a separate lab.
- JADX orientation covers APK/DEX and manifest/resource navigation. Apktool, dex2jar, Android Studio, Bytecode Viewer and Fernflower retain exact approved-row references; separate overlapping introductions would crowd out practice. APK modification/emulation and native JNI need a separate prepared lab.
- pyinstxtractor-ng is a short extraction reference; pycdc/uncompyle6/unpyc3 remain bytecode-version-specific references, not interchangeable guarantees. Read supported input versions rather than inferring support from the host Python runtime.
- Ghidra and stock GDB provide the core workflow. x64dbg/OllyDbg/Cutter/radare2 and GEF/peda/pwndbg remain approved reference choices; no need to relearn the same branch task in every interface.
- capa/FLOSS/YARA establish static triage roles. Existing approved references for Didier tools, oletools, FakeNet-NG, AutoIt and format-specific unpackers remain available; no live-malware plane lab is required or proposed.
- angr/ROPgadget remain references for a challenge that actually needs path constraints or gadgets. General native input-check recovery is a prerequisite; adding advanced courses without a diagnostic gap would dilute this refresher.

### Encodings, crypto and passwords

- crypto-attacks remains a searchable implementation/test-vector library. Specialized lattice tuning is outside the scheduled refresher; removal from study does not remove approval or its inventory reference.
- factordb-python is network-dependent and unnecessary for the tiny local RSA fixture. Keep reference only; approval is not authorization to transmit event challenge material.
- hlextend and padding-oracle-attacker are pattern-specific helpers needing a vulnerable construction/oracle. General RSA/hash exercises do not cover them; retain exact upstream references and state this gap instead of claiming broad cryptographic mastery.
- PARI/GP is an alternative number-theory runtime; Sage/Python cover this block’s arithmetic. Use the existing reference if a supplied solver specifically needs GP.
- hashid is triage, not proof of algorithm identity; check context and known format examples before selecting a cracking mode.
- rockyou is a wordlist, not a separate tool course. The three-word fixture teaches candidate handling without downloading a large corpus.
- OpenSSL remains reference-only for explicit cipher, key, IV and salt parameters; the curated block does not claim AES/OpenSSL coverage.
- multimon-ng signal decoding needs an appropriate recorded signal and modulation knowledge; reference-only pending a matching challenge, not covered by the crypto refresh.
- GTFOBins and HackTricks offline copies are broad lookups, not sequential course material. Preserve references and use matching sections when a concrete binary or technique appears.
- Runtimes, editors, archive utilities and environment/data helpers are supporting tools. Preserve every existing row-specific reference; use the participant’s familiar editor/runtime and a small archive exercise rather than parallel language or editor courses. Python 2 differs from the Python 3.8+ inverse example.

