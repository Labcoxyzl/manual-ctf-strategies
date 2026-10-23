# Current Cyber SEA Game 2026 source material

These files were supplied on 19 October 2026 and take priority over the older tool-request workbook and assumptions in the lost site. They remain in Windows Downloads and have **not** been copied into this recovery directory.

| File | Location | SHA-256 |
| --- | --- | --- |
| Tool review list | `/mnt/c/Users/Nicho/Downloads/AJCCBC_CTF2026_Tool_Review_List_261015r11.xlsx` | `a7de8719aae3c344c1158e3489eb59543378bb34b1ba16661caef36b332eedaf` |
| Practice Environment Setup Guide | `/mnt/c/Users/Nicho/Downloads/Practice Environment Setup Guide.pdf` | `41e085a678156514f20919134e68cc975e3e4c3cf92086caeda06872cb60165a` |

The PDF metadata marks it **Internal Use Only**. Keep the original files and any account details out of a public repository.

## Tool decisions from the review workbook

The workbook has three sheets with sequentially numbered rows: **39 approved Windows entries**, **161 approved Kali entries**, and **82 unapproved entries**. These counts refer to workbook rows, not unique tool packages across platforms. The Windows sheet says listed tools are pre-approved and available on competition PCs. The Kali sheet says its tools were installed on a best-effort basis and explicitly does not guarantee that every tool operates. The unapproved sheet lists tools that could not be installed for this event. Read each row's version, location, and remarks before writing a recipe; some Windows-list tools are installed in WSL.

The lost site's October 14 guide matched 32 entries in an earlier request workbook. That result does not establish coverage of the current review list. In particular, the new sheets separate Windows and Kali and include a distinct unapproved list. The rebuild should derive the visible tool catalog and first-use checks from these current rows.

## Competition and practice rules from the PDF

- **Categories:** Digital Forensics, Malware Analysis, Web Security, Reverse Engineering, OSINT, Cryptography, and Miscellaneous. The format is Jeopardy-style, flags are submitted through CTFd, and the challenge sets differ between 26 and 27 October. (pp. 2, 11)
- **Dates:** Practice runs 19–23 October; competition runs 26–27 October 2026. Practice uses each participant's own computer. The competition uses organiser-provided Windows 11 Pro laptops; a Kali Linux environment is also available through Platform Experience. (pp. 1, 3–4, 13)
- **Tool installation:** Organisers provide approved tools and approved requests. Participants may add libraries, dependencies, plugins, and packages if unrelated to generative AI. A standalone application outside the approved list needs organiser approval. Personal licences for commercial software such as IDA are not allowed. (pp. 5, 21)
- **AI:** Generative AI assistants may not be used to generate solutions, code, or scripts or analyze challenges. The guide permits viewing an automatically displayed AI summary in search results. (p. 8)
- **References and internet:** Physical and electronic notes, personal GitHub repositories, and scripts created before the competition are allowed. Google Search and technical references are allowed. Internet is via hotel Wi-Fi, while CTFd and related services are restricted to approved networks. Uploading challenge files to online services is prohibited. External assistance and sharing challenge content outside the team are prohibited. (pp. 3, 6–7, 9, 21)
- **Practice access:** Each team receives four accounts, one per participant. The practice portal and Kali access are described on pp. 14–19. Lab startup can take about 20 minutes and each account has at most three launches. Do not put account credentials in the rebuilt site or its logs. (pp. 14–19)

The old site's offline design is still useful because it avoids depending on network availability, but the PDF permits specific online references and personal GitHub repositories. The rebuild should state the actual rule rather than claim all internet use is forbidden.
