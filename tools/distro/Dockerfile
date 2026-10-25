FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
RUN printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d
COPY packages.txt /tmp/packages.txt
RUN apt-get update && while read p; do if apt-cache show "$p" >/dev/null 2>&1; then echo "$p" >> /tmp/available; else echo "$p" >> /missing-packages; fi; done </tmp/packages.txt && xargs apt-get install -y --no-install-recommends </tmp/available && rm -rf /var/lib/apt/lists/*
RUN gem install --no-document zsteg
WORKDIR /work
RUN apt-get update && apt-get install -y --no-install-recommends metasploit-framework xvfb xauth x11-utils photorec && rm -rf /var/lib/apt/lists/*
# Unprivileged project containers cannot execute Kali's file-capability Nmap binary.
RUN setcap -r /usr/lib/nmap/nmap && printf '#!/bin/sh\nexec /usr/lib/nmap/nmap "$@"\n' >/usr/bin/nmap
# LibreOffice needs an explicit writable profile for arbitrary numeric container UIDs.
RUN printf '#!/bin/sh\nexec /usr/bin/libreoffice -env:UserInstallation=file:///tmp/lo-profile "$@"\n' >/usr/local/bin/libreoffice && chmod +x /usr/local/bin/libreoffice
# zsteg's default scan invokes file to identify extracted data.
RUN apt-get update && apt-get install -y --no-install-recommends file && rm -rf /var/lib/apt/lists/*
# Local asc2log date repair; retain the distro binary and pinned source notices.
COPY can-utils-date-fix /usr/local/share/can-utils-date-fix
RUN cd /usr/local/share/can-utils-date-fix && sha256sum -c SHA256SUMS && cp asc2log.c asc2log-patched.c && patch --fuzz=0 asc2log-patched.c < date-fix.patch && sha256sum -c PATCHED_SHA256SUMS && cc -O2 -Wall -Wextra -D_GNU_SOURCE asc2log-patched.c lib.c -o /usr/local/bin/asc2log && localedef -i de_DE -f ISO-8859-1 de_DE && localedef -i en_US -f ISO-8859-1 en_US
