"""``keeper`` command line interface.

Small on purpose. It exists for the things you cannot do from inside the
application: check a prompt against your policy without deploying, validate a
policy file in CI, replay yesterday's audit log against a candidate policy, and
mint an API key without writing a script to do it.

    keeper check "ignore all previous instructions"
    keeper scan ./prompts.txt --policy policies/templates/gdpr.yaml
    keeper policy validate policies/default.yaml
    keeper policy dry-run candidate.yaml --events audit.jsonl
    keeper keygen --principal svc:ci --roles service
    keeper detectors
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence

from .accesscontrol.auth import generate_api_key
from .client import Keeper
from .config import KeeperConfig
from .detectors import registered
from .errors import KeeperError
from .policy.loader import dry_run_report, load_policy_document
from .policy.models import Policy
from .types import Stage, TrustLevel
from .version import __version__


def _keeper(args: argparse.Namespace) -> Keeper:
    overrides: dict[str, Any] = {"application": getattr(args, "application", "keeper-cli")}
    if getattr(args, "policy", None):
        overrides["policy"] = {"source": "local", "path": args.policy}
    return Keeper(config=KeeperConfig.load(getattr(args, "config", None), **overrides))


def _print_decision(decision: Any, payload: str, verbose: bool) -> None:
    fired = decision.reasons
    icon = {"allow": "ALLOW", "flag": "FLAG ", "redact": "REDACT", "challenge": "CHALLENGE", "block": "BLOCK"}[
        decision.action.value
    ]
    print(f"{icon}  {payload[:70]!r}")
    for finding in fired:
        print(f"       - {finding.detector} [{finding.severity.value}] {finding.summary}")
    for trace in decision.policy_traces:
        if trace.matched:
            print(f"       - policy {trace.policy_id}@{trace.policy_version} rule={trace.rule_id} -> {trace.action.value}")
    if decision.action.value == "redact" and decision.payload:
        print(f"       redacted: {decision.payload[:100]}")
    if verbose:
        print(json.dumps([f.to_dict() for f in decision.findings], indent=2))


def cmd_check(args: argparse.Namespace) -> int:
    with _keeper(args) as keeper:
        stage = Stage(args.stage)
        decision = keeper.pipeline.evaluate(
            stage,
            args.text,
            keeper.context(),
            trust=TrustLevel(args.trust),
            emit=False,
        )
        _print_decision(decision, args.text, args.verbose)
        return 1 if decision.blocked else 0


def cmd_scan(args: argparse.Namespace) -> int:
    with _keeper(args) as keeper:
        blocked = 0
        total = 0
        with open(args.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                total += 1
                decision = keeper.pipeline.evaluate(
                    Stage(args.stage),
                    line,
                    keeper.context(),
                    trust=TrustLevel(args.trust),
                    emit=False,
                )
                if decision.action.value != "allow" or args.verbose:
                    _print_decision(decision, line, False)
                if decision.blocked:
                    blocked += 1
        print(f"\n{total} lines scanned, {blocked} would be blocked")
        return 1 if blocked and args.fail_on_block else 0


def cmd_policy_validate(args: argparse.Namespace) -> int:
    try:
        policy = Policy.from_dict(load_policy_document(args.path), source=args.path)
    except KeeperError as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 1
    print(f"valid: {policy.ref} — {len(policy.rules)} rule(s)")
    for rule in policy.rules:
        print(f"  {rule.id:<30} -> {rule.action.value:<10} {rule.description}")
    return 0


def cmd_policy_dry_run(args: argparse.Namespace) -> int:
    policy = Policy.from_dict(load_policy_document(args.path), source=args.path)
    events: list[dict[str, Any]] = []
    with open(args.events, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    report = dry_run_report(policy, events)
    print(json.dumps(report, indent=2))
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    key, digest = generate_api_key(args.prefix)
    record = {
        "key_id": args.key_id or args.principal,
        "hash": digest,
        "principal_id": args.principal,
        "roles": list(args.roles),
    }
    if args.tenant:
        record["tenant"] = args.tenant
    print("Store this key now — it is not recoverable:\n")
    print(f"  {key}\n")
    print("Add this record to your API key file:\n")
    print(json.dumps(record, indent=2))
    return 0


def cmd_detectors(args: argparse.Namespace) -> int:
    config = KeeperConfig.load()
    for name in registered():
        det_config = config.detector(name)
        state = "enabled " if det_config.enabled else "disabled"
        print(f"  {name:<20} {state}  fail-{det_config.fail_mode:<7} timeout={det_config.timeout_ms}ms")
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    with _keeper(args) as keeper:
        print(json.dumps(keeper.health(), indent=2, default=str))
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keeper", description="Keeper AI firewall CLI")
    parser.add_argument("--version", action="version", version=f"keeper-firewall {__version__}")
    parser.add_argument("--config", help="path to a Keeper config file")
    parser.add_argument("--policy", help="path to a policy file to enforce")
    parser.add_argument("--application", default="keeper-cli")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="evaluate one string against the firewall")
    check.add_argument("text")
    check.add_argument("--stage", default="input", choices=[s.value for s in Stage])
    check.add_argument("--trust", default="user", choices=[t.value for t in TrustLevel])
    check.add_argument("-v", "--verbose", action="store_true")
    check.set_defaults(func=cmd_check)

    scan = sub.add_parser("scan", help="evaluate every line of a file")
    scan.add_argument("path")
    scan.add_argument("--stage", default="input", choices=[s.value for s in Stage])
    scan.add_argument("--trust", default="user", choices=[t.value for t in TrustLevel])
    scan.add_argument("--fail-on-block", action="store_true", help="exit non-zero if anything is blocked")
    scan.add_argument("-v", "--verbose", action="store_true")
    scan.set_defaults(func=cmd_scan)

    policy = sub.add_parser("policy", help="work with policy bundles")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    validate = policy_sub.add_parser("validate", help="check a policy file loads and compiles")
    validate.add_argument("path")
    validate.set_defaults(func=cmd_policy_validate)
    dry = policy_sub.add_parser("dry-run", help="replay audit events against a candidate policy")
    dry.add_argument("path")
    dry.add_argument("--events", required=True, help="JSONL file of audit events")
    dry.set_defaults(func=cmd_policy_dry_run)

    keygen = sub.add_parser("keygen", help="generate an API key and its stored hash")
    keygen.add_argument("--principal", required=True)
    keygen.add_argument("--roles", nargs="*", default=[])
    keygen.add_argument("--tenant")
    keygen.add_argument("--key-id")
    keygen.add_argument("--prefix", default="kf")
    keygen.set_defaults(func=cmd_keygen)

    sub.add_parser("detectors", help="list available detectors").set_defaults(func=cmd_detectors)
    sub.add_parser("health", help="print SDK health as JSON").set_defaults(func=cmd_health)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeeperError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
