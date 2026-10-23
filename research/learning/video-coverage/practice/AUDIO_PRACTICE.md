# Audio inspection: resolve nearby tones

Use the bundled [audio-tones.wav](audio-tones.wav), an authored eight-second mono PCM file. It is a known-answer exercise, not an organiser challenge or hidden-message sample. No external download is required.

Read Audacity's [Spectrogram View](https://manual.audacityteam.org/man/spectrogram_view.html) sections on time/frequency smearing and [Spectrogram Settings](https://manual.audacityteam.org/man/spectrogram_settings.html). These are free public pages; save them before flying. Audacity must already work locally for the GUI exercise. The paper route below needs only these notes.

1. Open the WAV in Audacity. Keep the original file unchanged. Note the eight-second duration and 8,000 Hz sampling rate.
2. In the track dropdown, select Spectrogram. Open that track's Spectrogram Settings; use the Frequencies algorithm, a linear scale, a range around 350–550 Hz, and a Hann window. Menu appearance varies with the installed release.
3. Compare window sizes 256 and 2048. Inspect the middle of each two-second region, away from transitions. Record how many tones you can distinguish and estimate their frequencies. If the display is blank or washed out, inspect the frequency range and gain/range before assuming the input lacks a signal.
4. Compare transition boundaries near two, four and six seconds. Explain why the larger window separates frequencies better but makes abrupt changes less sharply localized in time. Do not confuse spectrogram color with a different encoding.
5. Close the answer below and repeat. Your deliverable is a four-row time/frequency table and a statement of the resolution tradeoff.

<details>
<summary>Check your answer</summary>

0–2 s: 440 Hz; 2–4 s: 460 Hz; 4–6 s: both; 6–8 s: silence. At 8 kHz, the nominal FFT-bin spacing is 31.25 Hz for a 256-sample window and about 3.91 Hz for 2048 samples. Their window spans are 32 ms and 256 ms. Bin spacing alone does not guarantee two-tone separation: window shape, signal duration and strength also matter. Display estimates need not equal the generated frequencies exactly.

</details>

**Paper route:** Given the frequencies and sampling rate, calculate both bin spacings and time spans. Choose the larger window to investigate tones 20 Hz apart; choose the smaller window when timing a short click matters more. Explain one reason a blank display would be an inconclusive result.

The WAV structure and frequencies were checked from its samples; Audacity GUI operation remains untested. This exercises spectral inspection, not every audio encoding or SSTV decoding method.
