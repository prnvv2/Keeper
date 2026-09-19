"""Role-based authorization over models, tools, and agents.

Scope note, because the word "RBAC" appears twice in this project and they are
different systems: this module governs **which end users and services may reach
which models and tools**. The dashboard has its own, separate RBAC governing
who may read audit logs and publish policy; that lives in the control plane.

Roles map to permissions; permissions are ``resource_type:pattern`` pairs with
glob matching, so ``model:gpt-4*`` or ``tool:db.*`` work as you would expect.
Deny rules exist and always win — an org needs to say "analysts may use every
model except the one with customer data" without enumerating the allow list.

**Why not ABAC in v1.** Attribute-based rules (department, data classification,
time of day) are genuinely useful and genuinely easy to make unreviewable. The
compromise here: roles are the decision unit, but :class:`Permission` carries an
optional ``condition`` evaluated against principal attributes using the same
condition language as policy rules. That covers the common attribute cases
without inventing a second policy engine, and a full ABAC implementation can
replace this module behind the same :meth:`Authorizer.authorize` signature.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..errors import AuthorizationError
from ..types import Principal


@dataclass(frozen=True, slots=True)
class Permission:
    """Permission to act on a resource, optionally conditioned on attributes."""

    resource_type: str          # "model" | "tool" | "agent" | custom
    pattern: str = "*"
    effect: str = "allow"       # "allow" | "deny"
    condition: Any = None       # policy condition over principal attributes

    def matches(self, resource_type: str, resource: str) -> bool:
        return self.resource_type in (resource_type, "*") and fnmatch.fnmatchcase(resource, self.pattern)

    @classmethod
    def parse(cls, spec: str | Mapping[str, Any]) -> Permission:
        """Parse ``"model:gpt-4*"``, ``"!tool:shell.*"`` or a mapping."""
        if isinstance(spec, Mapping):
            return cls(
                resource_type=str(spec.get("resource_type", "*")),
                pattern=str(spec.get("pattern", "*")),
                effect=str(spec.get("effect", "allow")),
                condition=spec.get("condition"),
            )
        text = spec.strip()
        effect = "allow"
        if text.startswith("!"):
            effect, text = "deny", text[1:]
        if ":" in text:
            resource_type, pattern = text.split(":", 1)
        else:
            resource_type, pattern = "*", text
        return cls(resource_type=resource_type.strip(), pattern=pattern.strip(), effect=effect)


@dataclass(slots=True)
class Role:
    """A named bundle of permissions, optionally inheriting from other roles."""

    name: str
    permissions: tuple[Permission, ...] = ()
    inherits: tuple[str, ...] = ()
    description: str = ""

    @classmethod
    def from_dict(cls, name: str, data: Mapping[str, Any]) -> Role:
        return cls(
            name=name,
            permissions=tuple(Permission.parse(p) for p in data.get("permissions", ())),
            inherits=tuple(data.get("inherits", ())),
            description=str(data.get("description", "")),
        )


@dataclass(slots=True)
class Authorizer:
    """Evaluates role-based access decisions."""

    roles: dict[str, Role] = field(default_factory=dict)
    #: When no permission matches at all. Default deny is the only defensible
    #: choice for a security control, but it is configurable because teams roll
    #: access control out gradually and "log what would be denied" is a real
    #: migration step.
    default_effect: str = "deny"
    #: Roles that bypass every check. Kept explicit so it shows up in review.
    superuser_roles: frozenset[str] = frozenset({"admin"})

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Authorizer:
        roles = {name: Role.from_dict(name, spec) for name, spec in (data.get("roles") or {}).items()}
        return cls(
            roles=roles,
            default_effect=str(data.get("default_effect", "deny")),
            superuser_roles=frozenset(data.get("superuser_roles", ("admin",))),
        )

    def effective_permissions(self, role_names: Iterable[str]) -> list[Permission]:
        """Flatten a principal's roles, following inheritance, cycles included."""
        seen: set[str] = set()
        out: list[Permission] = []
        stack = list(role_names)
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            role = self.roles.get(name)
            if role is None:
                continue
            out.extend(role.permissions)
            stack.extend(role.inherits)
        return out

    def check(self, principal: Principal, resource_type: str, resource: str) -> tuple[bool, str]:
        """Return ``(allowed, reason)`` without raising."""
        if set(principal.roles) & self.superuser_roles:
            return True, "superuser role"

        permissions = self.effective_permissions(principal.roles)
        matched = [p for p in permissions if p.matches(resource_type, resource)]
        applicable = [p for p in matched if self._condition_holds(p, principal)]

        denies = [p for p in applicable if p.effect == "deny"]
        if denies:
            return False, f"denied by {denies[0].resource_type}:{denies[0].pattern}"
        allows = [p for p in applicable if p.effect == "allow"]
        if allows:
            return True, f"allowed by {allows[0].resource_type}:{allows[0].pattern}"
        if self.default_effect == "allow":
            return True, "default allow"
        roles = ", ".join(principal.roles) or "none"
        return False, f"no permission for {resource_type}:{resource} (roles: {roles})"

    def authorize(self, principal: Principal, resource_type: str, resource: str) -> None:
        """Raise :class:`AuthorizationError` unless the principal may act."""
        allowed, reason = self.check(principal, resource_type, resource)
        if not allowed:
            raise AuthorizationError(
                f"principal {principal.id!r} may not use {resource_type} {resource!r}: {reason}",
                principal=principal.id,
                resource=f"{resource_type}:{resource}",
            )

    @staticmethod
    def _condition_holds(permission: Permission, principal: Principal) -> bool:
        if permission.condition is None:
            return True
        from ..policy.models import compile_condition

        facts = {
            "principal_id": principal.id,
            "roles": list(principal.roles),
            "tenant": principal.tenant,
            "authenticated": principal.authenticated,
            "tags": dict(principal.attributes),
        }
        return compile_condition(permission.condition)(facts)


def from_policy(model_access: Mapping[str, Sequence[str]], tool_access: Mapping[str, Sequence[str]]) -> Authorizer:
    """Build an authorizer from a policy bundle's access lists.

    Lets the control plane distribute model and tool access alongside filtering
    rules, so "analysts lose access to the finance model" is a policy publish
    rather than an application deploy.
    """
    def spec(kind: str, pattern: str) -> str:
        # A leading "!" marks a deny entry; it has to stay in front of the
        # resource type for Permission.parse to see it.
        return f"!{kind}:{pattern[1:]}" if pattern.startswith("!") else f"{kind}:{pattern}"

    # A policy that defines no access lists has not delegated this decision to
    # Keeper, so the authorizer abstains rather than denying everything. Without
    # this, an org that only wants content filtering would find every model and
    # tool call refused by an RBAC layer they never configured.
    if not model_access and not tool_access:
        return Authorizer(roles={}, default_effect="allow")

    roles: dict[str, Role] = {}
    for role, patterns in model_access.items():
        roles.setdefault(role, Role(name=role))
        roles[role] = Role(
            name=role,
            permissions=roles[role].permissions + tuple(Permission.parse(spec("model", p)) for p in patterns),
            inherits=roles[role].inherits,
        )
    for role, patterns in tool_access.items():
        roles.setdefault(role, Role(name=role))
        roles[role] = Role(
            name=role,
            permissions=roles[role].permissions + tuple(Permission.parse(spec("tool", p)) for p in patterns),
            inherits=roles[role].inherits,
        )
    return Authorizer(roles=roles)
