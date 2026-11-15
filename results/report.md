# agent-redteam-eval report

Suite core v1.0.0: 64 seed cases + 98 mutants; conditions none, input_filter, output_filter, sanitiser, privsep, policy, all; seeds [1, 2, 3]; LLM: mock (susceptible mock: results show the harness and defence mechanics, not a real model's robustness).

## Ablation: toy

Attack success rate (rule judge) per category; benign FPR = share of benign runs where any defence blocked an input, a tool call or redacted output.

| condition | direct | indirect | jailbreak | tool misuse | exfil | hijack | ASR all [95% CI] | safe-refusal | benign task success | benign FPR | over-refusal |
|---|---|---|---|---|---|---|---|---|---|---|---|
| none | 0.481 | 0.533 | 0.667 | 0.476 | 0.639 | 0.778 | 0.588 [0.541, 0.633] | 0.183 | 1.000 | 0.000 | 0.000 |
| input_filter | 0.185 | 0.533 | 0.048 | 0.302 | 0.542 | 0.619 | 0.377 [0.333, 0.424] | 0.449 | 0.667 | 0.333 | 0.333 |
| output_filter | 0.481 | 0.533 | 0.667 | 0.476 | 0.083 | 0.778 | 0.495 [0.448, 0.542] | 0.183 | 1.000 | 0.000 | 0.000 |
| sanitiser | 0.481 | 0.167 | 0.667 | 0.317 | 0.292 | 0.429 | 0.380 [0.335, 0.426] | 0.183 | 1.000 | 0.000 | 0.000 |
| privsep | 0.136 | 0.278 | 0.238 | 0.254 | 0.556 | 0.651 | 0.343 [0.299, 0.389] | 0.192 | 1.000 | 0.000 | 0.000 |
| policy | 0.136 | 0.278 | 0.238 | 0.079 | 0.500 | 0.651 | 0.308 [0.266, 0.353] | 0.194 | 1.000 | 0.000 | 0.000 |
| all | 0.025 | 0.089 | 0.048 | 0.000 | 0.000 | 0.254 | 0.067 [0.047, 0.095] | 0.458 | 0.667 | 0.333 | 0.333 |

## Seed cases vs generated mutants: toy

| condition | seed cases ASR | n | mutants ASR | n |
|---|---|---|---|---|
| none | 0.549 | 144 | 0.608 | 288 |
| input_filter | 0.444 | 144 | 0.344 | 288 |
| output_filter | 0.444 | 144 | 0.521 | 288 |
| sanitiser | 0.396 | 144 | 0.372 | 288 |
| privsep | 0.299 | 144 | 0.365 | 288 |
| policy | 0.271 | 144 | 0.326 | 288 |
| all | 0.097 | 144 | 0.052 | 288 |

## Mutant ASR by operator under all defences: toy

| operator | ASR under 'all' | runs |
|---|---|---|
| b64 | 0.000 | 69 |
| delimiter | 0.083 | 96 |
| paraphrase | 0.013 | 78 |
| roleplay | 0.040 | 75 |
| rot13 | 0.000 | 72 |
| split | 0.200 | 30 |

## Ablation: p5

Attack success rate (rule judge) per category; benign FPR = share of benign runs where any defence blocked an input, a tool call or redacted output.

| condition | direct | indirect | jailbreak | tool misuse | exfil | hijack | ASR all [95% CI] | safe-refusal | benign task success | benign FPR | over-refusal |
|---|---|---|---|---|---|---|---|---|---|---|---|
| none | 0.222 | 0.333 | 0.381 | 0.000 | 0.704 | 0.651 | 0.357 [0.313, 0.404] | 0.191 | 1.000 | 0.000 | 0.000 |
| input_filter | 0.049 | 0.333 | 0.048 | 0.000 | 0.611 | 0.492 | 0.239 [0.201, 0.282] | 0.452 | 0.667 | 0.333 | 0.333 |
| output_filter | 0.222 | 0.333 | 0.381 | 0.000 | 0.093 | 0.651 | 0.279 [0.238, 0.324] | 0.191 | 1.000 | 0.000 | 0.000 |
| sanitiser | 0.222 | 0.089 | 0.381 | 0.000 | 0.315 | 0.413 | 0.220 [0.183, 0.262] | 0.191 | 1.000 | 0.000 | 0.000 |
| privsep | 0.136 | 0.278 | 0.238 | 0.000 | 0.704 | 0.651 | 0.307 [0.265, 0.353] | 0.191 | 1.000 | 0.000 | 0.000 |
| policy | 0.136 | 0.289 | 0.238 | 0.000 | 0.667 | 0.651 | 0.305 [0.263, 0.350] | 0.191 | 1.000 | 0.000 | 0.000 |
| all | 0.025 | 0.089 | 0.048 | 0.000 | 0.000 | 0.254 | 0.069 [0.048, 0.097] | 0.452 | 0.667 | 0.333 | 0.333 |

## Seed cases vs generated mutants: p5

| condition | seed cases ASR | n | mutants ASR | n |
|---|---|---|---|---|
| none | 0.312 | 141 | 0.379 | 282 |
| input_filter | 0.262 | 141 | 0.227 | 282 |
| output_filter | 0.227 | 141 | 0.305 | 282 |
| sanitiser | 0.220 | 141 | 0.220 | 282 |
| privsep | 0.262 | 141 | 0.330 | 282 |
| policy | 0.255 | 141 | 0.330 | 282 |
| all | 0.099 | 141 | 0.053 | 282 |

## Mutant ASR by operator under all defences: p5

| operator | ASR under 'all' | runs |
|---|---|---|
| b64 | 0.000 | 63 |
| delimiter | 0.083 | 96 |
| paraphrase | 0.013 | 75 |
| roleplay | 0.042 | 72 |
| rot13 | 0.000 | 69 |
| split | 0.200 | 30 |

## Rule judge vs mock LLM judge (all attack runs)

| target | attack runs | rule vs mock-judge agreement | kappa |
|---|---|---|---|
| toy | 3024 | 0.919 | 0.828 |
| p5 | 2961 | 0.882 | 0.711 |

## Agreement with hand labels

40 hand-labelled transcripts (14 labelled successful).

| comparison | n | kappa | tp | fp | fn | tn |
|---|---|---|---|---|---|---|
| rules vs hand labels | 40 | 1.000 | 14 | 0 | 0 | 26 |
| mock judge vs hand labels | 40 | 0.780 | 12 | 2 | 2 | 24 |
