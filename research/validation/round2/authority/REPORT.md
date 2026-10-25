# Organiser tool authority — round 2

Use **windows-1 through windows-32 first** to implement the user's request to prioritise organiser-highlighted tools. These are the 32 TrendMicro-proposed entries. Keep the other 168 approved entries available as later options. This preparation order follows the user's preference; the workbook itself defines the colours as **origin**, not a priority or sufficiency ranking.

| Source location | What it establishes |
| --- | --- |
| `Approved Tool List for Windows!B4` | The `List` column means `1 = proposed by TrendMicro`, `2 = added at the request of participants`. |
| Windows `D8:D39` | 32 List-1 entries, light blue `FFDDEBF7`, style 9. Original IDs: `windows-1`–`windows-32`. |
| Windows `D40:D46`; Kali `D8:D168` | 7 + 161 List-2 entries, light green `FFE2EFDA`, style 12. Original IDs: `windows-33`–`windows-39`, `kali-1`–`kali-161`. |
| Windows `B3` | All Windows-sheet tools are pre-approved and will be available on competition PCs. This includes Windows and WSL installations and a browser bookmark. |
| Kali `B3`, `B6` | The participant-requested tools are described as installed; installation is best-effort and operation is explicitly **not guaranteed**. |
| Windows `B48` | Several exercises require only a web browser. It does not say every exercise does. |

All 200 approved tool names have the same bold style 8. Neither approved sheet has conditional formatting. Merged headings contain the title, availability/origin explanation, AI restrictions, or Kali operational caveat. No separate priority legend was found. Kali column H is hidden raw-source text; it does not establish a priority. The unapproved sheet has 38 individual reasons saying a challenge can be solved without a named unapproved tool. Those statements do not identify the blue group as an exhaustive sufficient set.

The setup PDF's page 5 says the organiser installs both approved-list software and approved requests. It allows libraries, dependencies, plugins and packages unrelated to generative AI; standalone applications outside the approved list require organiser approval. Workbook Windows `B5`, `H14:H15` and Kali `B4` state the broader AI/ML library restriction. Page 22 fixes versions at the mid-October installation start and explains that Defender-sensitive examples run on Kali (`kali-61`, `kali-88`, `kali-89`). Pages 6 and 21 prohibit uploading challenge files to online services. The local `kali-7` AperiSolve entry does not waive that rule.

The user's report that organisers said every challenge can be solved with the main tools remains a **user-reported organiser assurance**. No explicit all-challenges guarantee was found in the workbook cells or the PDF text layer. This limits documentary corroboration; it does not negate the user's report or prevent prioritising the 32 organiser-proposed tools.

`priority-authority.json` contains hashes, exact source locations, rule excerpts, formatting evidence and all 200 original tool IDs. `priority-authority.csv` is the flat tool table. `preparation_order` is the user-directed working order; `documented_official_priority` is empty because no explicit rank was found.

Validation: regenerated the inventory from the original workbook and matched it exactly; checked every ID, name, origin cell, list style and name style; inspected all workbook sheets and merged ranges; searched all 23 nonempty PDF text pages; cross-checked the page-5 layout with `pdftotext` and a rendered page. Source hashes are in the JSON. No full PDF extraction or account details were saved in these outputs.

Not checked: live competition/PX tool operation or challenge coverage. No network requests, installations or submissions were made; approval and installation statements do not prove successful execution.
