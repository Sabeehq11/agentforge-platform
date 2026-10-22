# 0008 Graded transcripts

- Date: 2026-10-22
- Schema: platform store. New table `graded_transcripts`.
- Version change: store 0007 to 0008. Contracts stay v1.
- Breaking: no. `signals` still accepts only `fail` and `partial`. A pass is not a finding and does not increment `signal_count`.
- What existing rows become: nothing. The table starts empty. A pass from an earlier campaign is not backfilled.
- How to reverse: drop `graded_transcripts`. Do not alter `signals`.

`graded_transcripts` stores the executor transcript and the deterministic Judge label so a synthetic fixture grade can be replayed. The write is refused when the transcript matches a PHI pattern. It is not a published report and does not draft Documentation.
