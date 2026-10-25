# Distribution packages and runtimes

Project launchers live in `../bin-distro`. Existing system/CTF/Conda commands are reused when their startup checks pass. Missing distro packages are installed in `cyber-sea-game-2026-tools:local`; its Dockerfile and package list are in this directory. Rebuild with `docker build -t cyber-sea-game-2026-tools:local tools/distro` from the project root.

Container launchers bind only this project, preserve your user ID, and start no background services. Run them from within the project and keep input/output files there. WSLg display sockets are forwarded when available. Containers have no added capabilities: raw packet capture, Wi-Fi hardware, kernel debugging, and privileged operations need a suitable separately configured environment. GUI startup and real devices are not covered by CLI smoke checks.

The Docker image is stored by Docker, not physically inside this directory. Existing host tools remain in their original locations. Newly installed npm tools, Python 3.11 and .NET are scoped to this directory. Sage uses the preexisting Conda Sage environment because of its native mathematics dependencies.

Full install and startup logs are in `../logs/distro`; exact per-entry evidence is in `../status/distro.json`. Tool versions may differ from the organizer's captured environment.

Additional image packages: Ruby with the `zsteg` gem, Metasploit Framework, and Xvfb/xauth for headless GUI verification. No services are enabled or started during installation.

.NET SDK 6.0.400 (organizer version) and 8.0.426 are both installed. `dotnet --list-sdks` shows both; projects requiring 6.0.400 should select it with their `global.json`. SDK selection was checked separately in `tools/logs/distro/dotnet6-check/global.json`.

The container runner creates a private temporary runtime directory and dconf profile. LibreOffice uses an explicit temporary user profile; preferences do not persist across runs. Nmap's image-only file capabilities and automatic `--privileged` wrapper were removed so it runs normally as the project user; raw scanning remains unavailable without separately configured privileges. Plaso uses current `plaso-log2timeline`, `plaso-psort`, and `plaso-pinfo` entrypoints, with project aliases for `log2timeline`, `psort`, `pinfo`, and their `.py` spellings. The organizer's `internet_detector` row names the `inetsim` package, whose actual executable is `inetsim`.

Project container launchers require a working directory inside this project. Outside directories are not mounted, so the runner now exits with an explicit message rather than silently substituting the project directory. Use native installed tools when working from an offline export elsewhere.
