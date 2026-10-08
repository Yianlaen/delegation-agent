# Synthetic authorization experiment framework

Python 3.10+ standard-library framework for generating synthetic authorization cases, running local conformance checks, collecting model responses, and scoring sandbox effects. The source is under [`src/authorization_experiment`](src/authorization_experiment/); tests are under [`tests`](tests/). The frozen study settings are in [`config/study.json`](config/study.json).

From the repository root:

```sh
python3 -B experiments/framework/current_theory/run.py check
python3 -B experiments/framework/current_theory/run.py freeze
```

`check` runs 45 local tests. `freeze` checks the source, tests, study configuration, and dataset against `config/freeze.json`. Neither command makes model calls.

To exercise the pipeline without model calls:

```sh
python3 -B experiments/framework/current_theory/run.py run --run-id local-example
python3 -B experiments/framework/current_theory/run.py analyze --run-id local-example
python3 -B experiments/framework/current_theory/run.py verify --run-id local-example
```

This offline run checks the pipeline with model outputs marked unavailable. It does not reproduce the paper's model results. Generated files appear under `experiments/results/` and `experiments/reports/`. Use a new run ID for each run.
