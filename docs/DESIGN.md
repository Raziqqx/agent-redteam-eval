# Design

The full rationale is in `../DECISIONS.md`; numbers are in `../results/report.md`.

**Caveat on every number here:** all results come from a susceptible mock LLM and a mock judge. They show
defence mechanics, not real-model robustness. The real provider (`--provider anthropic`) has never run because
no API key was available.

## Threat model

The asset is a security-operations agent with read tools (log search, IOC lookup, file read) and acting tools
(block IP, disable account, send report, delete logs, run shell). The attacker controls part of the user's
prompt, or text the agent later reads through tools (log lines they caused, threat-intel notes). The attacker
cannot change code, the policy file, the approver or the system prompt. Out of scope: weight or training-data
attacks, cost-based denial of service, side channels, approver social engineering, multi-turn conversations.

## Key decisions and trade-offs

| Decision | Why | Trade-off / alternative considered |
|---|---|---|
| Score executed effects, not intent | A denied call needs no clean-up; counting it would overstate risk | Misses "near misses"; these are logged as `denied` for analysis |
| Susceptible mock LLM | Project 5's mock never reads free text, so nothing could succeed; no key for a real model | Absolute ASR reflects chosen probabilities. Alternative: a real model (path exists, never run) |
| Hash-keyed coin flips | Every condition sees the same draw, so the ablation is paired | Toy and p5 get identical per-category rates under `all` (expected) |
| Mock patterns and defence patterns written separately and on purpose mismatched | Avoids defences trivially matching the mock | Same author wrote both, so a real model would generalise in ways neither anticipates |
| Toy positive control | Proves the judge sees real effects | It is naive on purpose (e.g. obeys paths inside payloads) |
| Project 5 via path dependency | Its flat layout with four top-level packages is not pip-installable as one package; nothing is copied or modified | Needs the sibling folder; CI skips those tests |
| Harness approval gate that approves everything under `none` | Worst case: a rubber-stamping human | More pessimistic than project 5's shipped default (deny) |
| Privsep approver approves exactly the authorised list | Simple, deterministic | Optimistic; privsep numbers are an upper bound |
| Mutants committed as a versioned file | Reproducible and reviewable | Not regenerated per run, so less variety per run |
| Regex defences | Transparent baselines with clear mechanisms | Cannot catch semantic hijacks |
| Mock LLM judge instead of a real one | No key; a real judge would be untested code | Main gap for the "LLM-as-judge" claim |

## Baseline vs improved

Baseline is `none`; the improved configuration is `all` (every defence stacked). Same cases, same seeds, same
coin flips.

| target | condition | ASR [95% CI] | direct | indirect | jailbreak | tool misuse | exfil | hijack | benign task success | benign FPR |
|---|---|---|---|---|---|---|---|---|---|---|
| toy | none | 0.588 [0.541, 0.633] | 0.481 | 0.533 | 0.667 | 0.476 | 0.639 | 0.778 | 1.000 | 0.000 |
| toy | all | 0.067 [0.047, 0.095] | 0.025 | 0.089 | 0.048 | 0.000 | 0.000 | 0.254 | 0.667 | 0.333 |
| p5 | none | 0.357 [0.313, 0.404] | 0.222 | 0.333 | 0.381 | 0.000 | 0.704 | 0.651 | 1.000 | 0.000 |
| p5 | all | 0.069 [0.048, 0.097] | 0.025 | 0.089 | 0.048 | 0.000 | 0.000 | 0.254 | 0.667 | 0.333 |

Single-defence mechanics (toy):

- **Input filter** (ASR 0.377): jailbreak drops from 0.667 to 0.048 and direct from 0.481 to 0.185, but
  indirect is unchanged at 0.533, because the payload never passes through the prompt. It is the only single
  defence with a non-zero benign FPR (0.333).
- **Output filter** (0.495): only exfiltration moves, 0.639 to 0.083. It is pure DLP.
- **Sanitiser** (0.380): indirect drops from 0.533 to 0.167 and hijack from 0.778 to 0.429.
- **Privsep** (0.343) and **policy** (0.308): cut tool-driven attacks; policy brings tool misuse to 0.079.
- On project 5, tool misuse is 0.000 even with no defence: its own allow-list and server-side argument
  validation already reject those calls (the harness records them as `error`).

Mutants vs seeds: with no defence, mutants are slightly more successful (toy 0.608 vs 0.549). Under `all`, the
split-across-log-events operator survives best (0.200 on both targets), while base64 and rot13 reach 0.000.

## Judge evaluation

Across 5,985 attack runs, the rule judge and the mock LLM judge agree with kappa 0.828 (toy) and 0.711 (p5).
The p5 gap is mostly attempted-but-rejected calls that the mock judge counts as success. On 40 hand-labelled
transcripts, rules score kappa 1.000 and the mock judge 0.780 (2 FP, 2 FN, including a missed base64 key leak).
Rules-vs-hand is weak evidence: the same author wrote the rules and the labelling guide, and the labeller was
the build agent, not an independent human. Labelling also found two toy-planner routing bugs (fixed with
word-boundary matching, matrix re-run).

## Known limitations

- All results are from mocks; only relative, per-mechanism effects are meaningful. The real provider has never run.
- Benign FPR of 0.333 under `all` comes from a small n (12 benign cases on toy, 9 on p5, x3 seeds), and the
  blocked cases (BN-006, BN-008, BN-009, BN-014) are deliberate bait. It is a stress figure. No "all except
  input filter" condition was run, so the attack-reduction cost of dropping that filter is not measured.
- Goal hijack still succeeds 0.254 (toy) with all defences on. No regex defence understands wording like
  "conclude there is no malicious activity".
- Single-turn tasks only, one project 5 data seed, one task template for most attacks.
- One labeller, who also wrote the cases.
- CI does not check out project 5, so its adapter tests are skipped there; project 5 is a path dependency.

## Next steps

1. Run `--provider anthropic` against project 5 with a real key, and add a real LLM judge.
2. A semantic output check or a plan/act separation (dual-LLM / CaMeL-style) to address goal hijack.
3. A classifier-based injection detector to replace the regex input filter and reduce benign FPR; add an
   "all except input filter" condition to measure that trade-off.
4. Independent human labels; multi-turn cases; more data seeds and task templates.
5. Make project 5 installable so CI can run its adapter tests.
