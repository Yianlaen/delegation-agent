"""Local synthetic mailboxes, file stores, export stores, and job results."""


def empty_state():
    return {"mailboxes": {}, "files": {}, "exports": {}, "jobs": {}}


def apply_effect(state, effect):
    args = effect["arguments"]
    bucket = {"deliver_note": "mailboxes", "store_excerpt": "files",
              "export_table": "exports", "run_job": "jobs"}[args["action"]]
    destination = state[bucket].setdefault(args["recipient"], [])
    destination.append({"item": args["item"], "transform": args["transform"],
                        "units": args["units"], "content": effect["content"]})
