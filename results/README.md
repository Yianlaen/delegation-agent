# Experiment outcomes

The [paper](../paper/paper.md) gives the methods, interpretation, and limits. The tables here are the published numerical outputs: [execution](execution.csv), [prediction](prediction.csv), [verification panel](verification_panel.csv), [screening](screening.csv), and [paired task families](paired_families.csv). [combined.json](combined.json) contains the combined accounting and analysis.

| Evaluation condition | Episodes | Confirmation calls | Unauthorized effects | Policy violations | Authorized completions | Utility |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| No added check | 96 | 0 | 13 | 32 | 31 | 35 |
| Fixed safety instruction | 96 | 0 | 3 | 1 | 7 | 5 |
| Always confirm | 96 | 14 | 0 | 0 | 9 | 31 |
| Direct execution | 96 | 0 | 3 | 0 | 10 | 20 |
| Cost rule | 96 | 4 | 0 | 0 | 10 | 46 |

The development split has 48 episodes per condition. All 264 predictions were valid. Evaluation Brier score was 0.1910 and clipped log loss was 1.2470. On the separate verification panel, the model-based selective rule had lower realized utility than direct execution at verification effectiveness 0.25 and 0.5.

One executor request timed out after 120 seconds. A single repeat with the same payload returned refusal; the 720-cell analysis uses that later outcome. Raw model responses are not included, so these tables cannot be independently reconstructed from this repository.
