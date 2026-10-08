# A Delegation Harness for Runtime Authorization in Shared LLM Agents

**Authors:** Yihao Jiang and Zhiyuan Deng

Technical report, experiment code, synthetic dataset, and result tables for a study of runtime authorization in shared LLM agents.

- [Read the report](paper/paper.md) or [download the PDF](paper/paper.pdf).
- [Review the experiment outcomes](results/README.md) and [CSV tables](results/).
- [Inspect the synthetic inputs and evaluator truth](experiments/data/current_theory/).
- [Inspect the experiment framework](experiments/framework/current_theory/).

The study contains 144 synthetic execution inputs, 192 separate verification worlds, 264 probability predictions, and 720 execution episodes across five conditions. The predictor and executor use DeepSeek-V4.1-Flash through the `deepseek-flash` API alias.

## Framework checks

Python 3.10 or later is required. The framework has no third-party runtime dependencies. From the repository root:

```sh
python3 -B experiments/framework/current_theory/run.py check
python3 -B experiments/framework/current_theory/run.py freeze
```

`check` runs 45 local tests. `freeze` checks the code and data against the hashes in `config/freeze.json`. Both commands make no model calls.

The model-facing inputs and evaluator truth are stored separately. `development/inputs.jsonl` and `evaluation_inputs/inputs.jsonl` hold constructed tasks and observations. `development/truth.jsonl` and `evaluation_truth/truth.jsonl` hold labels and scoring values. The key in `data.py` is a public synthetic test fixture.

## Results and limitations

One executor request timed out. A single repeat with the same payload returned a refusal, which is included in the reported results. See Appendix C.4 for request accounting.

Raw model responses are not included, so the result tables cannot be independently reconstructed from this repository.

These results describe a finite synthetic comparison. They do not establish real-world authorization accuracy, human verification performance, population effects, or production security.
