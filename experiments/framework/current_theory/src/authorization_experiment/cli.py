import argparse
import json
import os
from pathlib import Path

from .analysis import analyze, verify_results
from .data import generate
from .runner import check, freeze, run


def main(default_root=None):
    parser = argparse.ArgumentParser(description="Current-theory synthetic authorization experiment")
    parser.add_argument("--root", type=Path, default=default_root or Path.cwd())
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "generate"):
        sub.add_parser(name)
    sub.add_parser("freeze")
    running = sub.add_parser("run", help="Paid only with --paid; default is zero-provider offline mode")
    running.add_argument("--run-id", required=True)
    running.add_argument("--paid", action="store_true")
    running.add_argument("--key-file", type=Path)
    for name in ("analyze", "verify"):
        sub.add_parser(name).add_argument("--run-id", required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.command in {"run", "analyze", "verify"}:
        if not args.run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in args.run_id):
            parser.error("run-id must contain only letters, numbers, hyphens and underscores")
    if args.command == "check":
        check(root)
        result = {"status": "PASS", "provider_calls": 0}
    elif args.command == "generate":
        if (root / "config/freeze.json").exists():
            parser.error("generation is disabled after freeze; verify the retained data instead")
        result = generate(root)
    elif args.command == "freeze":
        result = freeze(root)["budget"]
    elif args.command == "run":
        key = args.key_file.read_text().strip() if args.paid and args.key_file else os.environ.get("DEEPSEEK_API_KEY", "")
        if args.paid and not key:
            parser.error("paid run needs DEEPSEEK_API_KEY or --key-file; no key value is logged")
        result = run(root, args.run_id, key, paid=args.paid)
    elif args.command == "analyze":
        result = {k: v for k, v in analyze(root, args.run_id).items() if k in {"execution_statuses", "provider_accounting"}}
    else:
        result = verify_results(root, args.run_id)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
