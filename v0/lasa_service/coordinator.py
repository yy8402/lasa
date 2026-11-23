"""Receiver-owned admission and durable bounded execution orchestration."""

import asyncio
import copy
import hashlib
import time
from dataclasses import dataclass
from weakref import WeakValueDictionary

from .auth import Authentication, Authorization
from .capabilities import CapabilityRegistry, Publication, epoch, instant, require
from .contracts import canonical, digest, parse_json, request_digest, validate_data
from .diagnostics import Diagnostics
from .discovery import Discovery
from .errors import LasaError
from .evidence import release_readbacks
from .maintenance import Maintenance
from .peer import PeerClient
from .planning import ModelService, Planner
from .preconditions import check_inputs, input_size, request_input_size, restrict
from .store import TERMINAL, Store, encode, identity, zero
from .workspace import Workspace


@dataclass
class ExecutionContext:
    coordinator: object
    task_id: str
    document: dict
    definition: dict
    prompt: dict
    limits: dict
    binding: dict | None
    effects: list
    workspace: Workspace
    baseline: dict
    step_id: str | None = None


class Coordinator:
    def __init__(
        self,
        config,
        runtime,
        *,
        peer_transport=None,
        model_transport=None,
        planner=None,
        verifier=None,
    ):
        self.config = config
        self.contracts = config.contracts
        self.runtime = runtime
        self.model_transport = model_transport
        self.root = config.private_root
        self.store = Store(self.root)
        try:
            self.registry = CapabilityRegistry.configured(config, self.root)
        except BaseException:
            self.store.close()
            raise
        self.authentication = Authentication(config)
        self.authorization = Authorization(config)
        self.publication = Publication(
            config, self.registry, self.authorization.rules, self.offer_availability
        )
        self.discovery = Discovery(
            config,
            self.registry,
            self.publication,
            self.authentication,
            self.authorization,
            self.historical_contract,
        )
        self.peers = {
            settings["expected_service_id"]: PeerClient(config, settings, transport=peer_transport)
            for settings in config.peers
        }
        self.models = ModelService(self)
        self.planner = Planner(self, planner, verifier)
        from .delegation import DelegationController
        from .routing import RoutingController

        self.routing = RoutingController(self)
        self.delegation = DelegationController(self)
        self.diagnostics = Diagnostics(self)
        self.jobs = {}
        self.contexts = {}
        self.expiries = {}
        self.assessment_expiries = {}
        self.step_expiries = {}
        self.step_timeouts = {}
        self.operation_expiries = {}
        self.runtime_active = set()
        self.cleanup_expiries = {}
        self.questions = {}
        self.reconcile_locks = WeakValueDictionary()
        self.maintenance = Maintenance(self)
        self.maintenance_job = None
        self.ready = False
        self.fault = None
        from .broker import Broker

        self.broker = Broker(self)

    async def start(self):
        await self.authentication.start()
        for peer in self.peers.values():
            await peer.start()
        await self.runtime.recover(self)
        for task_id in self.store.active():
            uncertain = self.store.uncertain(task_id)
            self.fail(
                task_id,
                LasaError(
                    "child_outcome_unknown" if uncertain else "internal_error",
                    503,
                    effect="unknown" if uncertain else "known",
                ),
                recovery=True,
            )
        await self.broker.start()
        await self.runtime.probe(self)
        self.ready = True
        self.maintenance_job = asyncio.create_task(self.maintenance.run(), name="lasa-maintenance")

    async def close(self):
        self.ready = False
        if self.maintenance_job is not None:
            self.maintenance_job.cancel()
            await asyncio.gather(self.maintenance_job, return_exceptions=True)
        jobs = list(self.jobs.values())
        for job in jobs:
            if not job.cancelling():
                job.cancel()
        await asyncio.gather(*jobs, return_exceptions=True)
        await self.broker.close()
        await self.models.close()
        await asyncio.gather(*(peer.close() for peer in self.peers.values()))
        self.registry.close()
        self.store.close()

    def availability(self):
        if not self.ready:
            return "unavailable"
        return (
            "busy"
            if len(self.store.active()) >= self.config.document["limits"]["max_active_tasks"]
            else "available"
        )

    def offer_availability(self, principal, offer):
        binding = next(
            (
                item
                for item in self.config.document["bindings"]
                if item["contract"] == offer["contract"]
            ),
            None,
        )
        if binding is None:
            return "unknown" if self.availability() == "available" else self.availability()
        rule = self.authorization.rule(principal, offer["authorization_ref"])
        dependency = self.broker.binding_state(binding, rule)
        return self.availability() if dependency == "available" else dependency

    def historical_contract(self, principal, contract_digest):
        return (
            self.store.db.execute(
                "SELECT 1 FROM tasks JOIN sessions ON tasks.session_id=sessions.id WHERE sessions.owner=? AND json_extract(tasks.request,'$.selection.contract.digest')=?",
                (principal["subject"], contract_digest),
            ).fetchone()
            is not None
        )

    def remaining_seconds(self, task_id, *, task_only=False, operation_id=None):
        """One monotonic work expiry, intersected with absolute and allocated ceilings."""
        loop = asyncio.get_running_loop()
        row, task = self.store.task(task_id)
        if task["status"] in TERMINAL:
            return 0.0
        authority = parse_json(row["authority"])
        now = loop.time()
        ends = [
            self.expiries.get(task_id, now),
            now + epoch(authority["limits"]["deadline"]) - time.time(),
        ]
        if not task_only:
            if task["status"] == "evaluating":
                ends.append(self.assessment_expiries.get(task_id, now))
            if task_id in self.step_expiries:
                ends.append(self.step_expiries[task_id])
        if operation_id is not None:
            ends.append(self.operation_expiries.get(task_id, {}).get(operation_id, now))
        return max(0.0, min(ends) - now)

    async def bounded_step(self, task_id, limits, operation):
        loop = asyncio.get_running_loop()
        end = min(
            loop.time() + limits["budget"]["wall_time_ms"] / 1000,
            loop.time() + self.remaining_seconds(task_id),
            loop.time() + epoch(limits["deadline"]) - time.time(),
        )
        self.step_expiries[task_id] = end
        try:
            async with asyncio.timeout_at(end) as timeout:
                self.step_timeouts[task_id] = timeout
                return await operation()
        finally:
            self.step_timeouts.pop(task_id, None)
            self.step_expiries.pop(task_id, None)

    def finish_delegated_execution(self, task_id):
        # Child execution has settled; parent verification uses its own reserved allocation.
        self.step_expiries.pop(task_id, None)
        timer = self.step_timeouts.get(task_id)
        if timer is not None:
            timer.reschedule(
                asyncio.get_running_loop().time() + self.remaining_seconds(task_id, task_only=True)
            )

    async def cleanup_runtime(self, task_id):
        if task_id not in self.runtime_active:
            return
        end = self.cleanup_expiries.setdefault(
            task_id,
            asyncio.get_running_loop().time()
            + self.config.document["limits"]["reconciliation_timeout_seconds"],
        )

        async def stop():
            require(
                end > asyncio.get_running_loop().time(),
                "child_outcome_unknown",
                503,
            )
            async with asyncio.timeout_at(end):
                await self.runtime.kill(task_id)
            self.runtime_active.discard(task_id)
            self.cleanup_expiries.pop(task_id, None)

        cleanup = asyncio.create_task(stop(), name="lasa-cleanup:" + task_id)
        try:
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                # A work timeout cannot discard the separately bounded stop confirmation.
                await cleanup
                raise
        except (TimeoutError, LasaError):
            self.ready = False
            raise LasaError("child_outcome_unknown", 503, effect="unknown") from None

    async def run_runtime(self, context):
        self.contexts[context.task_id] = context
        self.runtime_active.add(context.task_id)
        try:
            return await self.bounded_step(
                context.task_id, context.limits, lambda: self.runtime.run(context)
            )
        finally:
            try:
                await self.cleanup_runtime(context.task_id)
            finally:
                self.contexts.pop(context.task_id, None)

    def principal(self, task_id):
        return parse_json(self.store.task(task_id)[0]["principal"])

    def request(self, task_id):
        return parse_json(self.store.task(task_id)[0]["request"])

    def authority(self, task_id):
        return parse_json(self.store.task(task_id)[0]["authority"])

    def workspace(self, session_id):
        return Workspace(
            self.config.workspace_root / session_id,
            self.config.document["limits"]["max_task_budget"]["artifact_bytes"],
        )

    def hit(self, point, task_id):
        if self.fault:
            self.fault(point, task_id)

    def check_active(self, task_id, *, evaluating=False):
        row, task = self.store.task(task_id)
        request = parse_json(row["request"])
        require(
            task["status"] not in TERMINAL and task["status"] != "cancelling",
            "task_state_conflict",
            409,
        )
        require(
            evaluating or task["status"] not in {"evaluating", "awaiting_input"},
            "task_state_conflict",
            409,
        )
        require(
            epoch(request["requested_limits"]["deadline"]) > time.time(), "deadline_exceeded", 422
        )
        require(parse_json(row["principal"])["token_expiry"] > time.time(), "authority_denied", 403)
        require(self.remaining_seconds(task_id) > 0, "deadline_exceeded", 422)
        rule = self.authorization.rule(parse_json(row["principal"]), request["authorization_ref"])
        require(request["selection"]["contract"] in rule["contracts"], "authority_denied", 403)
        return row, task

    def current_ceiling(self, task_id):
        row, _ = self.check_active(task_id, evaluating=True)
        rule = self.authorization.rule(
            parse_json(row["principal"]), parse_json(row["request"])["authorization_ref"]
        )
        granted = parse_json(row["authority"])["limits"]["budget"]
        return {
            key: min(
                value, rule["budget"][key], self.config.document["limits"]["max_task_budget"][key]
            )
            for key, value in granted.items()
        }

    def permits(self, task_id, effect, resource, action):
        row, _ = self.check_active(task_id)
        rule = self.authorization.rule(
            parse_json(row["principal"]), parse_json(row["request"])["authorization_ref"]
        )
        context = self.contexts.get(task_id)
        allowed = set(parse_json(row["authority"])["allowed_effects"]) & set(rule["effects"])
        if context:
            allowed &= set(context.effects)
        return (
            effect in allowed
            and any(r["resource"] == resource and action in r["actions"] for r in rule["resources"])
            and any(
                r["resource"] == resource and action in r["actions"]
                for r in parse_json(row["authority"])["resources"]
            )
            and context is not None
            and context.binding is not None
            and any(
                r["resource"] == resource and action in r["actions"]
                for r in context.binding["approved_resources"]
            )
        )

    def reserve(self, task_id, operation_id, kind, amount, details=None):
        context = self.contexts.get(task_id)
        if context:
            held = self.store.usage(task_id, reserved=True)
            require(
                all(
                    held[key] - context.baseline[key] + amount[key] <= context.limits["budget"][key]
                    for key in amount
                ),
                "capacity_exhausted",
                429,
            )
        return self.store.reserve(
            task_id, operation_id, kind, amount, self.current_ceiling(task_id), details
        )

    def create_session(self, principal, body, key, route):
        owner = principal["subject"]
        request_hash = digest(body)
        with self.store.transaction():
            replay = self.store.replay(owner, route, key, request_hash, body["operation_id"])
            if replay:
                return self.store.session(replay["resource_id"], owner)[1], replay["status"]
            session_id = identity("session")
            created = instant()
            retention = instant(
                time.time() + self.config.document["service"]["session_retention_seconds"]
            )
            document = {
                "session_id": session_id,
                "service_id": self.config.service_id,
                "created_at": created,
                "retention_until": retention,
                "active_task_id": None,
            }
            path = self.config.workspace_root / session_id
            path.mkdir(parents=True, mode=0o700)
            self.store.db.execute(
                "INSERT INTO sessions VALUES(?,?,?)", (session_id, owner, encode(document))
            )
            self.store.operation(
                owner, route, key, request_hash, body["operation_id"], session_id, "session", 201
            )
        return document, 201

    def submit(self, principal, session_id, body, key, route):
        received_monotonic = asyncio.get_running_loop().time()
        received_at = instant()
        owner = principal["subject"]
        request_hash = digest(body)
        with self.store.transaction():
            replay = self.store.replay(owner, route, key, request_hash, body["operation_id"])
            if replay:
                return self.store.task(replay["resource_id"], owner)[1], replay["status"]
            _, session = self.store.session(session_id, owner)
            require(epoch(session["retention_until"]) > time.time(), "not_found", 404)
            require(not self.store.active(session_id), "session_busy", 409)
            require(self.availability() == "available", "capacity_exhausted", 429)
            offer = self.publication.select(principal, body["selection"])
            require(
                body["authorization_ref"] == offer["authorization_ref"],
                "authority_denied",
                403,
            )
            authority = self.authorization.resolve(
                principal,
                body,
                offer,
                self.registry,
                deadline_ceiling=instant(
                    epoch(received_at) + body["requested_limits"]["budget"]["wall_time_ms"] / 1000
                ),
            )
            task_id = identity("task")
            created = received_at
            document = {
                "task_id": task_id,
                "session_id": session_id,
                "service_id": self.config.service_id,
                "operation_id": body["operation_id"],
                "revision": 1,
                "status": "evaluating",
                "received_at": created,
                "updated_at": created,
                "selection": body["selection"],
                "request_digest": request_digest(body),
            }
            self.store.db.execute(
                "INSERT INTO tasks VALUES(?,?,?,?,?,?,?,NULL)",
                (
                    task_id,
                    session_id,
                    "evaluating",
                    encode(document),
                    encode(body),
                    encode(principal),
                    encode(authority),
                ),
            )
            self.store.operation(
                owner, route, key, request_hash, body["operation_id"], task_id, "task", 202
            )
            session["active_task_id"] = task_id
            self.store.db.execute(
                "UPDATE sessions SET document=? WHERE id=?", (encode(session), session_id)
            )
            amount = zero()
            amount["input_bytes"] = request_input_size(body)
            self.store.reserve(
                task_id, "initial-input", "input", amount, authority["limits"]["budget"]
            )
            self.store.settle(task_id, "initial-input", amount)
        now_mono = asyncio.get_running_loop().time()
        self.expiries[task_id] = min(
            received_monotonic + body["requested_limits"]["budget"]["wall_time_ms"] / 1000,
            now_mono + epoch(authority["limits"]["deadline"]) - time.time(),
        )
        self.assessment_expiries[task_id] = min(
            self.expiries[task_id],
            received_monotonic
            + self.config.document["limits"]["assessment_budget"]["wall_time_ms"] / 1000,
        )
        job = asyncio.create_task(self.run(task_id), name="lasa:" + task_id)
        self.jobs[task_id] = job
        job.add_done_callback(lambda done: self.finish_job(task_id, done))
        return copy.deepcopy(document), 202

    def finish_job(self, task_id, job):
        self.jobs.pop(task_id)
        self.expiries.pop(task_id)
        self.assessment_expiries.pop(task_id)
        self.operation_expiries.pop(task_id, None)
        if job.cancelled():
            # A cancellation before the coroutine starts cannot reach run's handler.
            self.fail(task_id, LasaError("task_state_conflict", 409), cancel=True)

    def begin_model(self, task_id, body, purpose):
        row, task = self.check_active(task_id, evaluating=True)
        amount = zero()
        amount.update(
            model_calls=1,
            model_tokens=len(canonical(body)) + body.get("max_output_tokens", 3000) + 1024,
            wall_time_ms=max(1, min(60000, int(self.remaining_seconds(task_id) * 1000))),
        )
        if task["status"] == "evaluating":
            used = zero()
            for row in self.store.db.execute(
                "SELECT reserved FROM allocations WHERE task_id=? AND kind='assessment'", (task_id,)
            ):
                for key, value in parse_json(row[0]).items():
                    used[key] += value
            ceiling = self.config.document["limits"]["assessment_budget"]
            require(
                used["model_calls"] + 1 <= ceiling["model_calls"]
                and used["model_tokens"] + amount["model_tokens"] <= ceiling["model_tokens"],
                "capacity_exhausted",
                429,
            )
            kind = "assessment"
        else:
            kind = "model"
        context = self.contexts.get(task_id)
        if context:
            used = self.store.usage(task_id, reserved=True)
            require(
                all(
                    used[key] - context.baseline[key] + amount[key] <= context.limits["budget"][key]
                    for key in ["model_calls", "model_tokens"]
                ),
                "capacity_exhausted",
                429,
            )
        operation = identity("model")
        from_integration = False
        with self.store.transaction():
            pool = self.store.db.execute(
                "SELECT * FROM allocations WHERE task_id=? AND operation_id='integration-reserve' AND state='reserved'",
                (task_id,),
            ).fetchone()
            if pool and (
                purpose in {"verification", "planning"} or (context and context.binding is None)
            ):
                from_integration = True
                held = parse_json(pool["reserved"])
                amount["wall_time_ms"] = min(amount["wall_time_ms"], held["wall_time_ms"])
                require(all(amount[key] <= held[key] for key in amount), "capacity_exhausted", 429)
                self.store.db.execute(
                    "UPDATE allocations SET reserved=? WHERE task_id=? AND operation_id='integration-reserve'",
                    (encode({key: held[key] - amount[key] for key in held}), task_id),
                )
            self.reserve(
                task_id,
                operation,
                kind,
                amount,
                {"purpose": purpose, "from_integration": from_integration},
            )
        self.operation_expiries.setdefault(task_id, {})[operation] = (
            asyncio.get_running_loop().time() + amount["wall_time_ms"] / 1000
        )
        queries = [
            x for x in body.get("input", []) if isinstance(x, dict) and x.get("role") == "user"
        ]
        self.diagnostics.call(
            task_id,
            operation,
            "model",
            "started",
            {"purpose": purpose, "input": queries},
            reserved=amount,
            content={"purpose": purpose, "input": queries},
        )
        return operation

    def finish_model(self, task_id, operation, provider_usage, wall_ms, output):
        usage = zero()
        usage.update(
            model_calls=1, model_tokens=provider_usage.get("total_tokens", 0), wall_time_ms=wall_ms
        )
        require(
            type(usage["model_tokens"]) is int and usage["model_tokens"] > 0,
            "verification_failed",
            502,
        )
        with self.store.transaction():
            allocation = self.store.db.execute(
                "SELECT * FROM allocations WHERE task_id=? AND operation_id=?", (task_id, operation)
            ).fetchone()
            self.store.settle(task_id, operation, usage)
            if allocation["state"] != "finished" and parse_json(allocation["details"]).get(
                "from_integration"
            ):
                pool = self.store.db.execute(
                    "SELECT * FROM allocations WHERE task_id=? AND operation_id='integration-reserve' AND state='reserved'",
                    (task_id,),
                ).fetchone()
                if pool:
                    held = parse_json(pool["reserved"])
                    reserved = parse_json(allocation["reserved"])
                    self.store.db.execute(
                        "UPDATE allocations SET reserved=? WHERE task_id=? AND operation_id='integration-reserve'",
                        (
                            encode({key: held[key] + reserved[key] - usage[key] for key in held}),
                            task_id,
                        ),
                    )
        self.diagnostics.call(
            task_id,
            operation,
            "model",
            "finished",
            {"operation_id": operation},
            usage=usage,
            output=output,
            content={"output": output},
        )

    async def execute_step(self, task_id, step, inputs, predecessors):
        prior_artifacts = {
            item for result in predecessors.values() for item in result["artifact_ids"]
        }
        request = self.request(task_id)
        dependency_resources = set(request.get("delegation", {}).get("dependency_resources", []))
        dependency_resources.update(
            resource
            for result in predecessors.values()
            for resource in result["disclosure_resources"]
        )
        if step["executor"] == "peer":
            return await self.bounded_step(
                task_id,
                step["allocation"],
                lambda: self.delegation.execute(
                    task_id, step, inputs, predecessors, prior_artifacts, dependency_resources
                ),
            )
        definition = self.registry.get(step["contract"])
        binding = next(
            x for x in self.config.document["bindings"] if x["contract"] == step["contract"]
        )
        authority = self.authority(task_id)
        _, task = self.store.task(task_id)
        effects = sorted(
            set(authority["allowed_effects"])
            & set(binding["allowed_effects"])
            & set(definition["max_effects"])
        )
        scoped = restrict(authority, effects, binding["approved_resources"])
        scoped["limits"] = step["allocation"]
        offer = authority["selected_offer"]
        additional = [
            predicate
            for predicate in offer["restrictions"]["additional_preconditions"]
            if offer["contract"] == step["contract"] and predicate["kind"] == "artifact_present"
        ]
        artifacts = check_inputs(
            self, task_id, definition, inputs, scoped, additional, prior_artifacts=prior_artifacts
        )
        delegated_dependencies = request.get("dependency_results", {})
        dependencies = {key: result["output"] for key, result in predecessors.items()}
        require(
            input_size(inputs, dependencies, delegated_dependencies, artifacts)
            <= scoped["limits"]["budget"]["input_bytes"],
            "capacity_exhausted",
            429,
        )
        context = ExecutionContext(
            self,
            task_id,
            task,
            definition,
            {
                "contract": step["contract"],
                "input": inputs,
                "requirements": step["requirement_ids"],
                "dependency_results": dependencies,
                "delegated_dependencies": delegated_dependencies,
                "input_artifacts": artifacts,
            },
            step["allocation"],
            binding,
            effects,
            self.workspace(task["session_id"]),
            self.store.usage(task_id, reserved=True),
            step["step_id"],
        )
        result = await self.run_runtime(context)
        rows = self.store.db.execute(
            "SELECT a.intent,a.result FROM actions a JOIN allocations l ON a.task_id=l.task_id AND a.operation_id=l.operation_id "
            "WHERE a.task_id=? AND a.state='finished' AND json_extract(l.details,'$.step_id')=? ORDER BY a.rowid",
            (task_id, step["step_id"]),
        ).fetchall()
        successful, artifacts = set(), []
        for row in rows:
            intent, stored = parse_json(row["intent"]), parse_json(row["result"])
            if "value" not in stored:
                continue
            successful.add(intent["name"])
            if intent["name"] in self.broker.operations:
                artifacts.append(stored["value"]["evidence_artifact"]["artifact_id"])
        require(set(binding["required_operations"]) <= successful, "verification_failed", 422)
        result["artifact_ids"] = list(dict.fromkeys([*result["artifact_ids"], *artifacts]))
        profile = self.registry.source_profile(step["contract"])
        if profile:
            from .evidence import verification_material
            from .outcomes import assemble_source_outcome

            require(
                result["output"] == {"ready_for_verification": True}, "verification_failed", 422
            )
            material = verification_material(
                self, task_id, step_id=step["step_id"], artifact_ids=result["artifact_ids"]
            )
            result["output"] = assemble_source_outcome(
                profile, step["contract"], inputs, material
            ).output
        result["disclosure_resources"] = sorted(
            dependency_resources
            | {rule["resource"] for rule in scoped["resources"] if rule["actions"]}
        )
        return result

    async def run(self, task_id):
        try:
            request = self.request(task_id)
            async with asyncio.timeout(max(0.001, self.remaining_seconds(task_id, task_only=True))):
                self.hit("after_receipt", task_id)
                async with asyncio.timeout(max(0.001, self.remaining_seconds(task_id))):
                    private_plan = await self.routing.prepare(task_id, request)
                    plan = private_plan["document"]
                    require(
                        await self.planner.verify_plan(task_id, request, private_plan),
                        "precondition_failed",
                        422,
                    )
                    self.routing.allocate(task_id, private_plan)
                _, task = self.check_active(task_id, evaluating=True)
                offer = self.publication.revalidate(
                    self.principal(task_id), self.authority(task_id)["selected_offer"]
                )
                authority = self.authorization.resolve(
                    self.principal(task_id),
                    request,
                    offer,
                    self.registry,
                    deadline_ceiling=self.authority(task_id)["limits"]["deadline"],
                )
                check_inputs(
                    self,
                    task_id,
                    self.registry.get(request["selection"]["contract"]),
                    request["input"],
                    authority,
                    offer["restrictions"]["additional_preconditions"],
                )
                with self.store.transaction():
                    self.store.db.execute(
                        "UPDATE tasks SET plan=?,authority=? WHERE id=?",
                        (encode(private_plan), encode(authority), task_id),
                    )
                    self.store.reserve(
                        task_id,
                        "integration-reserve",
                        "integration",
                        plan["integration_reserve"],
                        authority["limits"]["budget"],
                    )
                    for step in plan["steps"]:
                        if step["executor"] == "peer":
                            amount = copy.deepcopy(step["allocation"]["budget"])
                            amount["delegations"] += 1
                            self.store.reserve(
                                task_id,
                                "step-reservation-" + step["step_id"],
                                "future-child",
                                amount,
                                authority["limits"]["budget"],
                            )
                    task["status"] = "accepted"
                    task["admission"] = {
                        "accepted_at": instant(),
                        "contract": request["selection"]["contract"],
                        "request_digest": request_digest(request),
                        "effective_limits": authority["limits"],
                        "authorization_decision_id": authority["decision_id"],
                        "plan_digest": digest(private_plan),
                    }
                    self.store.save_task(task)
                self.hit("after_admission", task_id)
                completed = {}
                prerequisite_steps = {
                    dependency for step in plan["steps"] for dependency in step["depends_on"]
                }
                pending = list(plan["steps"])
                while pending:
                    step = next(
                        (x for x in pending if set(x["depends_on"]) <= set(completed)), None
                    )
                    require(step is not None, "precondition_failed", 422)
                    _, task = self.check_active(task_id)
                    task["status"] = "executing"
                    self.store.save_task(task)
                    predecessors = {key: completed[key] for key in step["depends_on"]}
                    result = await self.execute_step(
                        task_id, step, private_plan["inputs"][step["step_id"]], predecessors
                    )
                    self.store.event(
                        task_id,
                        "private_step_candidate",
                        {"step_id": step["step_id"], "candidate": result},
                    )
                    self.registry.check_output(
                        step["contract"],
                        private_plan["inputs"][step["step_id"]],
                        result["output"],
                        result["evidence"],
                    )
                    if step["executor"] == "local" and step["step_id"] in prerequisite_steps:
                        require(
                            await self.planner.verify(
                                task_id,
                                self.registry.get(step["contract"]),
                                private_plan["inputs"][step["step_id"]],
                                result["output"],
                                result["evidence"],
                                artifact_ids=result["artifact_ids"],
                                step_id=step["step_id"],
                                verified_steps=predecessors,
                            ),
                            "verification_failed",
                            422,
                        )
                    completed[step["step_id"]] = result
                    pending.remove(step)
                with self.store.transaction():
                    self.store.settle(task_id, "integration-reserve", zero())
                reuse_step = (
                    len(plan["steps"]) == 1
                    and plan["steps"][0]["contract"] == request["selection"]["contract"]
                )
                if reuse_step:
                    final = completed[plan["steps"][0]["step_id"]]
                elif self.registry.source_profile(request["selection"]["contract"]):
                    from .evidence import verification_material
                    from .outcomes import assemble_source_outcome

                    artifacts = list(
                        dict.fromkeys(
                            artifact
                            for result in completed.values()
                            for artifact in result["artifact_ids"]
                        )
                    )
                    material = verification_material(self, task_id, artifact_ids=artifacts)
                    final = {
                        "output": assemble_source_outcome(
                            self.registry.source_profile(request["selection"]["contract"]),
                            request["selection"]["contract"],
                            request["input"],
                            material,
                        ).output,
                        "artifact_ids": artifacts,
                        "evidence": [
                            {
                                "criterion_id": item["id"],
                                "disposition": "passed",
                                "summary": "Exact source fields assembled from recorded, digest-verified operation artifacts.",
                                "artifact_ids": artifacts,
                            }
                            for item in self.registry.get(request["selection"]["contract"])[
                                "postconditions"
                            ]
                        ],
                    }
                else:
                    _, task = self.store.task(task_id)
                    definition = self.registry.get(request["selection"]["contract"])
                    baseline = self.store.usage(task_id, reserved=True)
                    left = {
                        key: authority["limits"]["budget"][key] - spent
                        for key, spent in baseline.items()
                    }
                    context = ExecutionContext(
                        self,
                        task_id,
                        task,
                        definition,
                        {
                            "contract": request["selection"]["contract"],
                            "input": request["input"],
                            "verified_step_results": completed,
                            "instruction": self.config.prompts["integration"],
                        },
                        {
                            "budget": left,
                            "deadline": request["requested_limits"]["deadline"],
                            "max_hops": 0,
                        },
                        None,
                        [],
                        self.workspace(task["session_id"]),
                        baseline,
                    )
                    final = await self.run_runtime(context)
                    final["artifact_ids"] = list(
                        dict.fromkeys(
                            [
                                *final["artifact_ids"],
                                *(
                                    artifact
                                    for result in completed.values()
                                    for artifact in result["artifact_ids"]
                                ),
                            ]
                        )
                    )
                definition = self.registry.get(request["selection"]["contract"])
                self.registry.check_output(
                    request["selection"]["contract"],
                    request["input"],
                    final["output"],
                    final["evidence"],
                )
                require(
                    await self.planner.verify(
                        task_id,
                        definition,
                        request["input"],
                        final["output"],
                        final["evidence"],
                        requirements=plan["requirements"],
                        artifact_ids=final["artifact_ids"],
                        include_step_inputs=True,
                        verified_steps={
                            step["step_id"]: completed[step["step_id"]]
                            for step in plan["steps"]
                            if step["executor"] == "peer" or step["step_id"] in prerequisite_steps
                        }
                        if not reuse_step
                        else {},
                    ),
                    "verification_failed",
                    422,
                )
                self.release(task_id, final)
        except asyncio.CancelledError:
            if self.store.task(task_id)[1]["status"] not in TERMINAL:
                self.fail(
                    task_id,
                    LasaError(
                        "task_state_conflict",
                        409,
                        effect="unknown" if self.store.uncertain(task_id) else "known",
                    ),
                    cancel=True,
                )
            raise
        except TimeoutError:
            self.fail(
                task_id,
                LasaError(
                    "deadline_exceeded",
                    422,
                    effect="unknown" if self.store.uncertain(task_id) else "known",
                ),
            )
        except Exception as exc:
            self.fail(
                task_id,
                exc
                if isinstance(exc, LasaError)
                else LasaError(
                    "internal_error",
                    500,
                    effect="unknown" if self.store.uncertain(task_id) else "known",
                ),
            )
        finally:
            if task_id in self.runtime_active:
                try:
                    await self.cleanup_runtime(task_id)
                except LasaError:
                    self.store.event(task_id, "cleanup_unconfirmed", {})
            self.contexts.pop(task_id, None)
            self.questions.pop(task_id, None)
            self.broker.locks.pop(task_id, None)
            self.diagnostics.forget_secrets(task_id)
            self.planner.verified = {
                key: value for key, value in self.planner.verified.items() if key[0] != task_id
            }

    def release(self, task_id, final):
        self.check_active(task_id)
        self.hit("before_release", task_id)
        row, task = self.store.task(task_id)
        request = parse_json(row["request"])
        artifacts = []
        for artifact_id in final["artifact_ids"]:
            artifact = self.store.db.execute(
                "SELECT * FROM artifacts WHERE id=? AND task_id=?", (artifact_id, task_id)
            ).fetchone()
            require(artifact is not None, "verification_failed", 422)
            artifacts.append(parse_json(artifact["manifest"]))
        amount = zero()
        amount["output_bytes"] = len(canonical(final["output"]))
        with self.store.transaction():
            effect = self.store.effect_disposition(task_id)
            require(effect != "unknown", "child_outcome_unknown", 503)
            self.store.reserve(
                task_id,
                "released-output",
                "output",
                amount,
                self.authority(task_id)["limits"]["budget"],
            )
            self.store.settle(task_id, "released-output", amount)
            task["status"] = "completed"
            task["result"] = {
                "contract": request["selection"]["contract"],
                "request_digest": request_digest(request),
                "output": final["output"],
                "usage": self.store.usage(task_id),
                "effect_disposition": effect,
                "artifacts": artifacts,
                "evidence": final["evidence"],
            }
            if readbacks := release_readbacks(self, task_id, final["output"]):
                task["result"]["workspace_readbacks"] = readbacks
            self.config.contracts.validate("Task", task)
            self.store.save_task(task)
            for artifact in artifacts:
                self.store.db.execute(
                    "UPDATE artifacts SET released=1 WHERE id=?", (artifact["artifact_id"],)
                )
        self.diagnostics.emit(
            task_id,
            "verification",
            {
                "step_id": "final-release",
                "contract": request["selection"]["contract"],
                "request_digest": request_digest(request),
                "checks": final["evidence"],
                "release": "accepted",
            },
        )
        self.hit("after_release", task_id)

    def fail(self, task_id, error, *, cancel=False, recovery=False):
        _, task = self.store.task(task_id)
        if task["status"] in TERMINAL:
            return
        effect = self.store.effect_disposition(task_id)
        unknown = error.effect == "unknown" or effect == "unknown"
        codes = self.config.contracts.schemas["Problem"]["properties"]["code"]["enum"]
        if error.code not in codes:
            error = LasaError("internal_error", 500, effect="unknown" if unknown else "known")
        task.pop("question", None)
        task["status"] = (
            "indeterminate"
            if unknown
            else ("cancelled" if cancel else ("rejected" if "admission" not in task else "failed"))
        )
        task["problem"] = error.public()
        task["problem"]["effect_disposition"] = (
            "unknown" if unknown else "known" if effect == "known" else error.effect
        )
        if unknown:
            task["problem"]["retry"] = "reconcile"
        with self.store.transaction():
            self.store.save_task(task)
            self.store.db.execute(
                "UPDATE artifacts SET released=-1 WHERE task_id=? AND released<=0", (task_id,)
            )
            self.store.db.execute(
                "UPDATE allocations SET state='finished',usage=? WHERE task_id=? AND kind IN ('integration','future-child') AND state='reserved'",
                (encode(zero()), task_id),
            )
            self.store.event(
                task_id,
                "recovery" if recovery else "failure",
                {"code": error.code, "status": task["status"]},
            )

    async def request_input(self, task_id, message):
        row, task = self.check_active(task_id)
        request = parse_json(row["request"])
        require("delegation" not in request, "precondition_failed", 422)
        question = {
            "question_id": identity("question"),
            "revision": 1,
            "prompt": message,
            "answer_schema": {"type": "string", "minLength": 1, "maxLength": 8192},
            "expires_at": instant(time.time() + self.remaining_seconds(task_id)),
        }
        self.contracts.validate("Question", question, "verification_failed", 422)
        prior = task["status"]
        task["status"] = "awaiting_input"
        task["question"] = question
        self.store.save_task(task)
        future = asyncio.get_running_loop().create_future()
        self.questions[task_id] = (question, future)
        answer = await future
        _, task = self.store.task(task_id)
        task.pop("question", None)
        task["status"] = prior
        self.store.save_task(task)
        return {"answer": answer}

    def mutation(self, principal, task_id, body, key, route, if_match, kind):
        owner = principal["subject"]
        request_hash = digest(body)
        answer = None
        cancel = None
        with self.store.transaction():
            replay = self.store.replay(owner, route, key, request_hash, body["operation_id"])
            if replay:
                return self.store.task(task_id, owner)[1], 202
            _, task = self.store.task(task_id, owner)
            require(if_match is not None, "precondition_required", 428)
            require(if_match == '"' + str(task["revision"]) + '"', "stale_revision", 412)
            if kind == "input":
                require(
                    task["status"] == "awaiting_input" and task_id in self.questions,
                    "task_state_conflict",
                    409,
                )
                question, future = self.questions[task_id]
                require(not future.done(), "task_state_conflict", 409)
                require(
                    body["question_id"] == question["question_id"]
                    and body["question_revision"] == question["revision"],
                    "stale_revision",
                    412,
                )
                validate_data(question["answer_schema"], body["answer"])
                amount = zero()
                amount["input_bytes"] = len(canonical(body["answer"]))
                self.reserve(task_id, question["question_id"], "input", amount)
                self.store.settle(task_id, question["question_id"], amount)
                answer = future
            elif task["status"] not in TERMINAL and task["status"] != "cancelling":
                task.pop("question", None)
                task["status"] = "cancelling"
                self.store.save_task(task)
                cancel = self.jobs[task_id]
            self.store.operation(
                owner, route, key, request_hash, body["operation_id"], task_id, "task", 202
            )
        if answer is not None:
            answer.set_result(body["answer"])
        if cancel is not None:
            cancel.cancel()
        return self.store.task(task_id, owner)[1], 202

    def snapshot_artifact(self, task_id, media_type, text, *, provenance=None):
        self.check_active(task_id)
        data = text.encode()
        artifact_id = identity("artifact")
        manifest = {
            "artifact_id": artifact_id,
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "media_type": media_type,
            "source_task_id": task_id,
        }
        if provenance is not None:
            self.contracts.validate("OperationProvenance", provenance)
            manifest["provenance"] = provenance
        amount = zero()
        amount["artifact_bytes"] = len(data)
        with self.store.transaction():
            self.reserve(task_id, artifact_id, "artifact", amount)
            self.store.settle(task_id, artifact_id, amount)
            self.store.db.execute(
                "INSERT INTO artifacts VALUES(?,?,?,?,0)",
                (artifact_id, task_id, encode(manifest), data),
            )
        return manifest

    async def reconcile_internal(self, task_id):
        _, task = self.store.task(task_id)
        if task["status"] not in {"indeterminate", "failed", "cancelled"}:
            return
        await self.delegation.reconcile_parent(task_id)
        for action in self.store.db.execute(
            "SELECT * FROM actions WHERE task_id=? AND state='started' AND effect='workspace.write'",
            (task_id,),
        ).fetchall():
            intent = parse_json(action["intent"])
            try:
                content = self.workspace(task["session_id"]).read(
                    intent["arguments"]["relative_path"]
                )
                if content != intent["arguments"]["text"]:
                    continue
            except (LasaError, OSError, UnicodeError):
                continue
            result = {"value": {"bytes_written": len(content.encode())}}
            amount = zero()
            amount["tool_calls"] = 1
            with self.store.transaction():
                self.store.db.execute(
                    "UPDATE actions SET state='finished',result=? WHERE task_id=? AND operation_id=?",
                    (encode(result), task_id, action["operation_id"]),
                )
                self.store.settle(task_id, action["operation_id"], amount)
        if task_id not in self.runtime_active and not self.store.uncertain(task_id):
            receipt = digest(
                {
                    "children": self.store.children(task_id),
                    "actions": [
                        dict(x)
                        for x in self.store.db.execute(
                            "SELECT operation_id,state,digest FROM actions WHERE task_id=?",
                            (task_id,),
                        )
                    ],
                }
            )
            prior = self.store.db.execute(
                "SELECT 1 FROM events WHERE task_id=? AND json_extract(document,'$.kind')='resolution' AND json_extract(document,'$.payload.receipt_digest')=?",
                (task_id, receipt),
            ).fetchone()
            if not prior:
                self.diagnostics.emit(
                    task_id,
                    "resolution",
                    {
                        "operation_id": "reconcile-" + task_id,
                        "original_terminal_state": task["status"],
                        "resolved_effect_disposition": "known",
                        "summary": "Bounded reconciliation established the recorded operation disposition. Original terminal state and result remain immutable; no work was replayed.",
                        "receipt_digest": receipt,
                    },
                )

    async def reconcile(self, principal, task_id, body, key, route):
        owner = principal["subject"]
        self.store.task(task_id, owner)
        hashed = digest(body)
        operation_id = body["operation_id"]
        async with self.reconcile_locks.setdefault(task_id, asyncio.Lock()):
            if not self.store.replay(owner, route, key, hashed, operation_id):
                await self.reconcile_internal(task_id)
                with self.store.transaction():
                    if not self.store.replay(owner, route, key, hashed, operation_id):
                        self.store.operation(
                            owner, route, key, hashed, operation_id, task_id, "task", 202
                        )
        return self.store.task(task_id, owner)[1], 202

    async def reconcile_background(self, task_id):
        async with self.reconcile_locks.setdefault(task_id, asyncio.Lock()):
            await self.reconcile_internal(task_id)
