"""Compile grouped inspection bindings against the configured inventory."""

from dataclasses import dataclass

from .contracts import digest

DIRECTIONS = ("request", "response")
GROUPS = ("caller", "model", "delegates", "connectors")

# Several enforcement points share one operator-facing direction.
CHANNELS = {
    "caller.request": ("caller", "request"),
    "caller.response": ("caller", "response"),
    "candidate.release": ("caller", "response"),
    "reasoning.request": ("model", "request"),
    "reasoning.response": ("model", "response"),
    "delegation.request": ("delegates", "request"),
    "delegation.response": ("delegates", "response"),
    "tool.invoke": ("connectors", "request"),
    "tool.result": ("connectors", "response"),
}


@dataclass(frozen=True)
class InspectionRule:
    fields: dict
    origins: dict
    revision: str

    def profile_for(self, *, artifact):
        if artifact and "artifact_profile" in self.fields:
            return self.fields["artifact_profile"]
        return self.fields.get("profile")

    def report(self, *, artifacts=False):
        fields, origins = self.fields.copy(), self.origins.copy()
        if artifacts and "profile" in fields:
            fields.setdefault("artifact_profile", fields["profile"])
            origins.setdefault("artifact_profile", origins["profile"])
        return {**fields, "origins": origins}


OFF = {"mode": "off"}


class InspectionBindings:
    @classmethod
    def from_manifest(cls, document):
        return cls(
            document.get("content_security", {}),
            {peer["expected_service_id"] for peer in document.get("peers", [])},
            {
                connector["id"]: {
                    operation["operation_id"] for operation in connector["operations"]
                }
                for executor in document["executors"]
                for connector in executor.get("connectors", [])
            },
        )

    def __init__(self, settings, peers, connectors):
        profiles = settings.get("inspection_profiles", [])
        self.profiles = {profile["id"]: profile for profile in profiles}
        if len(self.profiles) != len(profiles):
            raise ValueError("Duplicate inspection profile ID")
        groups = settings.get("bindings", {})
        self.defaults = {
            group: self.apply(group, {}, groups.get(group, {}), group + ".default")
            for group in GROUPS
        }

        peer_overrides = self.index(
            groups.get("delegates", {}).get("overrides", []),
            lambda entry: entry["service_id"],
        )
        if peer_overrides.keys() - peers:
            raise ValueError("Inspection override names an unknown peer")
        self.delegates = {
            peer: self.apply(
                "delegates",
                self.defaults["delegates"],
                peer_overrides.get(peer, {}),
                "peer:" + peer,
            )
            for peer in sorted(peers)
        }

        connector_overrides = self.index(
            groups.get("connectors", {}).get("overrides", []),
            lambda entry: (entry["connector_id"], entry.get("operation_id")),
        )
        for connector_id, operation in connector_overrides:
            if connector_id not in connectors:
                raise ValueError("Inspection override names an unknown connector")
            if operation is not None and operation not in connectors[connector_id]:
                raise ValueError("Inspection override names an operation outside its connector")
        self.connectors = {
            name: self.apply(
                "connectors",
                self.defaults["connectors"],
                connector_overrides.get((name, None), {}),
                "connector:" + name,
            )
            for name in sorted(connectors)
        }
        self.operations = {
            (name, operation): self.apply(
                "connectors",
                self.connectors[name],
                connector_overrides.get((name, operation), {}),
                "operation:" + operation,
            )
            for name, operations in sorted(connectors.items())
            for operation in sorted(operations)
        }

    @staticmethod
    def index(entries, key_for):
        indexed = {key_for(entry): entry for entry in entries}
        if len(indexed) != len(entries):
            raise ValueError("Duplicate inspection override selector")
        return indexed

    def apply(self, group, inherited, patch, origin):
        return {
            direction: self.compose(
                inherited.get(direction),
                patch.get(direction),
                origin,
                artifacts=group in {"caller", "delegates"} and direction == "response",
            )
            for direction in DIRECTIONS
        }

    def compose(self, previous, patch, origin, *, artifacts):
        if patch is None and previous is not None:
            return previous
        if patch is None:
            return InspectionRule(OFF, {"mode": "unconfigured"}, digest(OFF))
        if patch["mode"] == "off":
            return InspectionRule(OFF, {"mode": origin}, digest(OFF))
        if "artifact_profile" in patch and not artifacts:
            raise ValueError("Artifact profiles require a caller or delegate response")
        fields = (previous.fields if previous else {}) | patch
        if "profile" not in fields:
            raise ValueError("Active inspection rule requires a resolved profile")
        if any(fields[key] not in self.profiles for key in fields.keys() - {"mode"}):
            raise ValueError("Inspection rule names an unknown profile")
        origins = (previous.origins if previous else {}) | dict.fromkeys(patch, origin)
        return InspectionRule(fields, origins, digest(fields))

    def resolve(self, channel, destination, *, connector=None, operation=None):
        group, direction = CHANNELS[channel]
        rules = self.defaults[group]
        if group == "delegates":
            rules = self.delegates.get(destination.removeprefix("peer:"), rules)
        elif group == "connectors":
            rules = self.operations.get((connector, operation), rules)
        return rules[direction]

    def active_profiles(self):
        directions = (
            self.defaults["caller"],
            self.defaults["model"],
            *self.delegates.values(),
            *self.operations.values(),
        )
        used = {
            profile
            for rules in directions
            for rule in rules.values()
            for profile in (rule.profile_for(artifact=False), rule.profile_for(artifact=True))
        }
        return [profile for key, profile in self.profiles.items() if key in used]

    def report(self):
        def directions(group, rules):
            return {
                name: rule.report(artifacts=group in {"caller", "delegates"} and name == "response")
                for name, rule in rules.items()
            }

        return {
            "defaults": {group: directions(group, rules) for group, rules in self.defaults.items()},
            "delegates": {
                peer: directions("delegates", rules) for peer, rules in self.delegates.items()
            },
            "connectors": {
                name: directions("connectors", rules) for name, rules in self.connectors.items()
            },
            "operations": {
                f"{connector}/{operation}": directions("connectors", rules)
                for (connector, operation), rules in self.operations.items()
            },
        }
