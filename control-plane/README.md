# keeper-control-plane

The control plane for [Keeper](https://github.com/prnvv2/Keeper): the
aggregation, investigation, policy-distribution, alerting and SIEM-export half
of the AI firewall. Every SDK instance reports here; security teams work here.

```bash
pip install -e .            # or: docker compose up
python -m keeper_control
```

Two API surfaces with separate credentials, because they have different
audiences and different blast radii:

- `/v1/*` — called by SDK instances. Ship telemetry, pull policy, register with
  the fleet inventory. Authenticated with an **ingest** key that hundreds of
  application processes hold.
- `/api/*` — called by humans and the dashboard. Search the audit trail,
  publish policy, manage alerts. Authenticated with an **admin** key.

Interactive API docs at `/docs`. Health at `/healthz`, `/readyz`, `/health`,
and Prometheus metrics at `/metrics`.

See [`docs/deployment.md`](../docs/deployment.md) for configuration and
production hardening, and [`docs/observability.md`](../docs/observability.md)
for wiring SIEM export and alerting.
