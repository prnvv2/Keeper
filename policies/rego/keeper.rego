# The default Keeper policy, expressed in Rego.
#
# This exists so that `policy.engine: opa` is a concrete option rather than an
# interface and a promise. An organisation already running OPA keeps its
# authoring, review and distribution toolchain, and gets the same decisions.
#
#   opa run --server --addr :8181 policies/rego/keeper.rego
#
#   keeper = Keeper(application="app", policy={"engine": "opa",
#                                              "opa_url": "http://localhost:8181"})
#
# Contract with the SDK, deliberately narrow so the pipeline treats the
# embedded and OPA engines identically:
#
#   input   the flattened facts the condition language reads — stage,
#           environment, application, model, tenant, principal_id, roles,
#           authenticated, trust, tool, detectors_fired, categories, labels,
#           severity, max_score, tags, turn_count
#
#   output  data.keeper.decision — a set of {action, rule, message} objects.
#           The SDK combines them with detector findings by escalation, so a
#           rule here can raise the action but never lower it.
#
# Note the difference in evaluation model, which is the point of using Rego at
# all: every rule that matches contributes. There is no `stop`, and no ordering.

package keeper

import rego.v1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

severity_rank := {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

fired(name) if name in input.detectors_fired

severity_at_least(level) if severity_rank[input.severity] >= severity_rank[level]

ingress_stage if input.stage in {"retrieval", "tool_result", "memory_write"}

# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------

# Credentials, in either direction. There is no legitimate case for either.
decision contains {
	"action": "block",
	"rule": "block-credential-egress",
	"message": "This request contains credential material and was blocked.",
} if {
	some detector in {"secrets", "secret_leakage"}
	fired(detector)
}

# Instructions embedded in content that has no business issuing them. Higher
# confidence than the direct case, hence a separate rule.
decision contains {
	"action": "block",
	"rule": "block-indirect-injection",
	"message": "Untrusted content in this request contained embedded instructions and was rejected.",
} if {
	fired("prompt_injection")
	ingress_stage
}

decision contains {
	"action": "block",
	"rule": "block-direct-injection",
	"message": "This request was identified as a prompt injection attempt.",
} if {
	fired("prompt_injection")
	severity_at_least("high")
}

# Low-authority content driving a privileged sink, or memory whose provenance
# does not support the action it is authorising.
decision contains {
	"action": "block",
	"rule": "block-unsafe-tool-flow",
	"message": "This action was not authorised by a sufficiently trusted source.",
} if {
	fired("token_flow")
	severity_at_least("high")
}

decision contains {
	"action": "block",
	"rule": "block-unsafe-tool-flow",
	"message": "This action was not authorised by a sufficiently trusted source.",
} if {
	some category in {"memory_provenance_laundering", "excessive_agency"}
	category in input.categories
}

decision contains {
	"action": "block",
	"rule": "block-multi-turn-escalation",
	"message": "This conversation was flagged for review and cannot continue on this topic.",
} if {
	fired("trajectory")
	severity_at_least("high")
}

# CHALLENGE requires out-of-band human confirmation. Without a confirmation
# callback the SDK degrades it to a block, which is the intended default.
decision contains {
	"action": "challenge",
	"rule": "challenge-unverified-authority",
	"message": "This request asserts an authority we could not verify.",
} if {
	fired("authority_claim")
	severity_at_least("high")
}

decision contains {
	"action": "block",
	"rule": "block-banned-content",
	"message": "This content is not permitted by organisational policy.",
} if {
	fired("banned_topics")
	severity_at_least("high")
}

# Strip personal data rather than failing the request. Contributes REDACT; a
# concurrent BLOCK from any rule above still wins under escalation.
decision contains {
	"action": "redact",
	"rule": "redact-personal-data",
	"message": "",
} if fired("pii")

# Observability-only. These change nothing; they exist so the event lands in
# the dashboard with a named rule attached, making it searchable and alertable.
decision contains {
	"action": "flag",
	"rule": "flag-weak-injection-signals",
	"message": "",
} if {
	fired("prompt_injection")
	severity_at_least("low")
}

decision contains {
	"action": "flag",
	"rule": "flag-ungrounded-answers",
	"message": "",
} if fired("groundedness")

decision contains {
	"action": "flag",
	"rule": "flag-external-content-in-memory",
	"message": "",
} if {
	input.stage == "memory_write"
	input.trust in {"external", "retrieved"}
}

# ---------------------------------------------------------------------------
# Example of what Rego buys you that the embedded language does not:
# arbitrary computation over the facts. Here, a per-tenant model allowlist
# loaded as external data rather than enumerated in the policy document.
# ---------------------------------------------------------------------------

# decision contains {
# 	"action": "block",
# 	"rule": "tenant-model-allowlist",
# 	"message": "This model is not enabled for your organisation.",
# } if {
# 	input.model != null
# 	allowed := data.tenants[input.tenant].allowed_models
# 	not input.model in allowed
# }
