# AV03 doctor waveform provenance

These two synthetic WAV files were authored for the autosolve engine evaluation on 2026-10-27. They contain no third-party challenge media or secrets. They are redistributed with this toolkit as test data.

| File | SHA-256 | Generation and expected decoder result |
| --- | --- | --- |
| `morse-sos.wav` | `04f836645344e118a7f16fbda5baebdc350de889e286dd47fc229ed85112a64a` | Project-authored Python synthesized 800 Hz sine bursts for `... --- ...` at 22,050 Hz, mono 16-bit PCM. Independent multimon-ng 1.3.1 decoded `SOS`. |
| `afsk-hello.wav` | `e27fa45d5b51830bcc13cd0207ee8d0a6992e3652f689fe1e36c8ea1f23b3e21` | Upstream multimon-ng `gen-ng` at commit `b5f7d71c5e9b5a76093ba55c515968dc40f92804` generated raw AX.25 AFSK1200 with `gen-ng -t raw -p 'AFSK_PROBE_20261027'`; the PCM bytes were wrapped as 22,050 Hz mono 16-bit WAV. Independent multimon-ng 1.3.1 decoded `AFSK1200: fm AE4WA-0 to HB9JNX-0 UI  pid=F0` followed by `AFSK_PROBE_20261027`. Original raw PCM SHA-256: `394b60a8e9d81644dcd7e25ac79cdbd669b02b3e19a1f7aaba53a45e510ff140`. |

The generator source is GPL-2.0 licensed; no generator source code or recorded upstream audio is included in these fixtures. The WAVs are task-authored output. No separate license is asserted for the WAVs beyond the repository's terms. These known signals check whether doctor can exercise both decoders; they do not establish performance on different AFSK encodings or noisy recordings.
