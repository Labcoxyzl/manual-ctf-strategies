# Independent resource review — 22 October 2026

Reviewed the five lane reports, organiser-source notes, inventory, integrated study guide, all-tool index and combined research data for a rusty CTF participant preparing for 24 hours of flight study. This is a read-only content review; the task owner owns changes to the guide.

## Verdict

No blocking findings. The shortlist separates prioritised learning from complete tool-reference coverage and accurately distinguishes research from tested offline operation. The portal and downloaded offline bundle remain explicitly outside the completed work.

## Checks and evidence

- The combined data contains 44 distinct resource URLs: 31 readings, 9 videos and 4 practice resources. Estimates total 1,095 minutes; the schedule totals 24 hours and explicitly includes practice and notes rather than presenting those estimates as video runtimes.
- All 200 approved inventory IDs occur exactly once in coverage. Every selected resource's tool ID is approved, every linked resource ID exists, and the Markdown index has 200 rows. Checked index-to-lesson anchors resolve.
- Reviewed video identity and verification statements across all nine recommendations. They distinguish transcript/description checks from playback. The redundant metadata-only NetworkChuck recommendation was removed by the task owner before this integrated review.
- Independently retrieved [Sage number theory](https://doc.sagemath.org/html/en/tutorial/tour_numtheory.html): its modular arithmetic, gcd, factoring, inverse and CRT examples match the described lesson. Python tabs import Sage; the guide correctly warns that ordinary Python alone is insufficient.
- Independently retrieved [The Sleuth Kit filesystem scenarios](https://wiki.sleuthkit.org/FS-Analysis/): the historical example does mix the extracted-image offset with the original-image `dd` input. The final guide explicitly flags this and directs readers to the `blkcalc`/`blkcat` explanation.
- Independently retrieved the [Stegseek README](https://github.com/RickdeJager/stegseek) and compared its documented scope with the lesson. The curation avoids adopting headline performance claims and distinguishes detection/unencrypted extraction from bypassing encryption.
- Checked that online SageCell, public AperiSolve uploads, KAPE acquisition, cloud labs, symbol downloads and local deployment prerequisites are qualified rather than implied to be approved or available offline. Current documentation is not presented as proof of the organiser's installed version.
- A targeted independent fetch of the LiveOverflow companion GitHub directory failed through the web fetcher. That result does not establish a broken link; its creator-source inspection remains supported by the reverse lane's recorded checks.

## Optional navigation improvement

The schedule initially had no direct lesson links, while the 438-line resource list used a different topic order. In particular, CyberChef belongs to block 1 but appears near the bottom. Add compact lesson-anchor links to the schedule's Focus cells. This makes the existing selection easier to follow without adding resources or expanding the search. This was a usability improvement, not a correctness blocker.

Focused recheck: the task owner added direct lesson links to blocks 1–8 and a compact five-row public-practice table. All newly added local anchor links resolve. The practice table preserves the distinction between public sample material and organiser challenges, labels the YARA drill as suggested, and does not claim files were downloaded or exercises run. The 44-resource selection is unchanged. No further findings.

## Limits

Did not repeat every lane search, re-fetch all inherited October 19 references, watch videos, install tools, download samples, execute exercises, or test offline playback. The guide discloses these limits; actual flight readiness still depends on staging and testing the chosen assets before departure.
