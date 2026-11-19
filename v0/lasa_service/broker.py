"""Receiver-authorized tool calls with durable effect operation identities."""

import asyncio
import copy
from pathlib import PurePosixPath

from .capabilities import reference, require
from .connector_schema import validate as validate_connector
from .connectors import Connector
from .contracts import canonical, digest, parse_json, validate_data
from .errors import LasaError
from .planning import object_schema
from .store import encode, zero

TEXT = {"type": "string", "minLength": 1, "maxLength": 65536}
PATH = {"type": "string", "minLength": 1, "maxLength": 512}
SCHEMAS = {
    "workspace.read": object_schema({"relative_path": PATH}),
    "workspace.write": object_schema({"relative_path": PATH, "text": TEXT}),
    "workspace.list": object_schema({"relative_path": PATH}, []),
    "lasa.request_input": object_schema(
        {"message": {"type": "string", "minLength": 1, "maxLength": 8192}}
    ),
    "lasa.export_text": object_schema(
        {
            "relative_path": PATH,
            "media_type": {"enum": ["text/plain", "text/markdown", "application/json"]},
        }
    ),
}


class Broker:
    def __init__(self, coordinator):
        self.coordinator = coordinator
        self.connectors = {}
        self.operations = {}
        self.tool_names = {name.replace(".", "_"): name for name in SCHEMAS}
        self.locks = {}

    async def start(self):
        c = self.coordinator
        for resource in c.config.connectors.values():
            connector = Connector(c.config, resource, c.root)
            self.connectors[resource["id"]] = connector
            for operation in resource["operations"]:
                name = operation["operation_id"]
                tool = name.replace(".", "_")
                require(tool not in self.tool_names, "invalid_input")
                self.tool_names[tool] = name
                self.operations[name] = (connector, operation)
        await asyncio.gather(*(connector.start() for connector in self.connectors.values()))

    async def close(self):
        for connector in self.connectors.values():
            await connector.close()

    def binding_state(self, binding, rule, authority=None):
        states = []
        for name in binding["required_operations"]:
            if name not in self.operations:
                return "unavailable"
            connector, operation = self.operations[name]
            ceilings = [(rule["effects"], rule["resources"])]
            if authority is not None:
                ceilings.append((authority["allowed_effects"], authority["resources"]))
            if any(
                operation["effect"] not in effects
                or not any(
                    r["resource"] == operation["resource"] and "read" in r["actions"]
                    for r in resources
                )
                for effects, resources in ceilings
            ):
                return "unauthorized"
            states.append(connector.state(name))
        return next(
            (
                state
                for state in ["unauthorized", "unavailable", "unknown", "busy"]
                if state in states
            ),
            "available",
        )

    def _authorized(self, task_id):
        c = self.coordinator
        context = c.contexts.get(task_id)
        if not context or context.binding is None:
            return set()
        allowed = set()
        for name in SCHEMAS:
            if name == "workspace.write":
                effect, action = "workspace.write", "update"
            else:
                effect, action = "workspace.read", "read"
            if c.permits(task_id, effect, "workspace:self", action):
                allowed.add(name)
        if "delegation" in c.request(task_id):
            allowed.discard("lasa.request_input")
        for name in context.binding["required_operations"]:
            _, operation = self.operations[name]
            if c.permits(task_id, operation["effect"], operation["resource"], "read"):
                allowed.add(name)
        return allowed

    def tools(self, task_id):
        return [
            {
                "type": "function",
                "deferLoading": False,
                "name": name.replace(".", "_"),
                "description": self.operations[name][1]["description"]
                if name in self.operations
                else "Receiver-authorized " + name,
                "inputSchema": self.operation_input_schema(task_id, name)
                if name in self.operations
                else SCHEMAS[name],
            }
            for name in sorted(self._authorized(task_id))
        ]

    def operation_input_schema(self, task_id, name):
        operation = self.operations[name][1]
        constraints = copy.deepcopy(operation["argument_constraints"])
        inputs = self.coordinator.contexts[task_id].prompt["input"]
        for match in operation["task_input_bindings"]:
            require(match["input_field"] in inputs, "authority_denied", 403)
            target = inputs[match["input_field"]]
            properties = constraints.setdefault("properties", {})
            if match["comparison"] == "exact":
                properties[match["argument_field"]] = {
                    "allOf": [properties.get(match["argument_field"], {}), {"const": target}]
                }
            else:
                values = properties.get(match["argument_field"], {}).get("enum")
                if values is not None:
                    selected = [
                        value
                        for value in values
                        if isinstance(value, str) and PurePosixPath(value).name == target
                    ]
                    require(bool(selected), "authority_denied", 403)
                    properties[match["argument_field"]] = {"enum": selected}
        return {"type": "object", "allOf": [operation["input_schema"], constraints]}

    async def call(self, task_id, operation_id, name, arguments):
        try:
            async with asyncio.timeout(self.coordinator.remaining_seconds(task_id)):
                return await self._invoke(task_id, operation_id, name, arguments)
        except TimeoutError:
            raise LasaError(
                "deadline_exceeded",
                422,
                effect="unknown" if self.coordinator.store.uncertain(task_id) else "known",
            ) from None

    async def _invoke(self, task_id, operation_id, name, arguments):
        lock = self.locks.setdefault(task_id, asyncio.Lock())
        async with lock:
            c = self.coordinator
            c.check_active(task_id)
            require(name in self._authorized(task_id), "authority_denied", 403)
            schema = (
                self.operations[name][1]["input_schema"]
                if name in self.operations
                else SCHEMAS[name]
            )
            if name in self.operations:
                validate_connector(schema, arguments, "invalid_input", 400)
                validate_connector(
                    self.operations[name][1]["argument_constraints"],
                    arguments,
                    "authority_denied",
                    403,
                )
                for match in self.operations[name][1]["task_input_bindings"]:
                    selected = self.coordinator.contexts[task_id].prompt["input"]
                    value = arguments.get(match["argument_field"])
                    if match["comparison"] == "basename":
                        require(isinstance(value, str), "authority_denied", 403)
                        value = PurePosixPath(value).name
                    require(
                        match["input_field"] in selected
                        and value == selected[match["input_field"]],
                        "authority_denied",
                        403,
                    )
            else:
                validate_data(schema, arguments)
            body = {"name": name, "arguments": arguments}
            hashed = digest(body)
            existing = c.store.db.execute(
                "SELECT * FROM actions WHERE task_id=? AND operation_id=?", (task_id, operation_id)
            ).fetchone()
            if existing:
                require(existing["digest"] == hashed, "idempotency_conflict", 409)
                require(existing["state"] == "finished", "child_outcome_unknown", 503)
                result = parse_json(existing["result"])
                if "error" in result:
                    raise LasaError(result["error"]["code"])
                return result["value"]
            amount = zero()
            amount["tool_calls"] = 1
            effect = "workspace.write" if name == "workspace.write" else "none"
            context = c.contexts[task_id]
            if name in self.operations:
                permission = self.operations[name][1]
                resource, permission_effect, action = (
                    permission["resource"],
                    permission["effect"],
                    "read",
                )
            else:
                resource = "workspace:self"
                permission_effect = (
                    "workspace.write" if name == "workspace.write" else "workspace.read"
                )
                action = "update" if name == "workspace.write" else "read"
            with c.store.transaction():
                c.reserve(
                    task_id,
                    operation_id,
                    "tool",
                    amount,
                    {
                        "step_id": context.step_id,
                        "resource": resource,
                        "action": action,
                        "effect": permission_effect,
                    },
                )
                c.store.db.execute(
                    "INSERT INTO actions VALUES(?,?,?,?,NULL,?,?)",
                    (task_id, operation_id, hashed, "started", effect, encode(body)),
                )
            c.diagnostics.call(
                task_id, operation_id, "tool", "started", body, reserved=amount, content=body
            )
            c.hit("before_effect", task_id)
            workspace = c.workspace(c.store.task(task_id)[1]["session_id"])
            try:
                if name == "workspace.read":
                    value = {"text": workspace.read(arguments["relative_path"])}
                elif name == "workspace.write":
                    value = workspace.write(arguments["relative_path"], arguments["text"])
                elif name == "workspace.list":
                    value = workspace.list(arguments.get("relative_path", "."))
                elif name == "lasa.request_input":
                    value = await c.request_input(task_id, arguments["message"])
                elif name == "lasa.export_text":
                    value = c.snapshot_artifact(
                        task_id,
                        arguments["media_type"],
                        workspace.read(arguments["relative_path"]),
                    )
                else:
                    connector, operation = self.operations[name]
                    value = await connector.call(
                        name,
                        arguments,
                        max(0.001, c.remaining_seconds(task_id)),
                    )
                    validate_connector(operation["output_schema"], value)
                    require(
                        canonical(c.diagnostics.redact(value, task_id)) == canonical(value),
                        "disclosure_denied",
                        403,
                    )
                    sequence = c.store.db.execute(
                        "SELECT rowid FROM actions WHERE task_id=? AND operation_id=?",
                        (task_id, operation_id),
                    ).fetchone()[0]
                    manifest = c.snapshot_artifact(
                        task_id,
                        "application/json",
                        canonical(value).decode(),
                        provenance={
                            "kind": "operation-result",
                            "service_id": c.config.service_id,
                            "task_id": task_id,
                            "operation_id": operation_id,
                            "sequence": sequence,
                            "resource": operation["resource"],
                            "contract": reference(context.definition),
                            "input_digest": digest(context.prompt["input"]),
                            "result_digest": digest(value),
                            "schema_digest": digest(
                                {
                                    key: operation[key]
                                    for key in [
                                        "input_schema",
                                        "argument_constraints",
                                        "output_schema",
                                        "task_input_bindings",
                                    ]
                                }
                            ),
                        },
                    )
                    value = {"output": value, "evidence_artifact": manifest}
                c.hit("after_effect", task_id)
                c.check_active(task_id)
                require(
                    len(canonical(value))
                    <= c.config.document["limits"]["max_task_budget"]["output_bytes"],
                    "capacity_exhausted",
                    429,
                )
                stored = {"value": value}
            except (LasaError, OSError, UnicodeError, ValueError) as exc:
                if effect != "none":
                    raise LasaError("child_outcome_unknown", 503, effect="unknown") from exc
                error = exc if isinstance(exc, LasaError) else LasaError("verification_failed", 422)
                stored = {"error": error.public()}
            with c.store.transaction():
                c.store.db.execute(
                    "UPDATE actions SET state='finished',result=? WHERE task_id=? AND operation_id=?",
                    (encode(stored), task_id, operation_id),
                )
                c.store.settle(task_id, operation_id, amount)
            c.diagnostics.call(
                task_id,
                operation_id,
                "tool",
                "finished",
                body,
                usage=amount,
                output=stored,
                content=stored,
            )
            if "error" in stored:
                raise LasaError(stored["error"]["code"])
            return value
