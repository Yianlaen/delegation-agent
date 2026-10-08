# Synthetic dataset

The September 15 study uses seed 20260915. It has 144 execution inputs across 12 task types and 192 separate verification worlds. Four task types form the development split and eight the evaluation split. Each execution task has six proof states and clean/attack documents.

Inputs and evaluator truth are separate. The `inputs.jsonl` files contain constructed task worlds and observations. The `truth.jsonl` files contain hidden authorization labels, oracle probabilities, screening coins, and expected effects used for scoring. The model-facing projection is implemented in the framework's [data.py](../../framework/current_theory/src/authorization_experiment/data.py). All names, messages, accounts, and credentials in these rows are synthetic fixtures.
