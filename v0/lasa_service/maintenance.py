"""Background reconciliation and retention for receiver-owned records and paths."""

import asyncio
import logging
import re
import shutil
import time
from pathlib import Path

from .capabilities import instant

LOG = logging.getLogger(__name__)
INTERVAL_SECONDS = 30
RECONCILIATION_BATCH = 4
RETENTION_BATCH = 8
PATH_BATCH = 32


class Maintenance:
    def __init__(self, coordinator):
        self.coordinator = coordinator
        self.store = coordinator.store
        self.roots = {
            "session": Path(coordinator.config.document["service"]["workspace_root"]),
            "task": coordinator.root / "runtime",
        }

    async def collect(self):
        self.store.retire_sessions(instant(), RETENTION_BATCH)
        for kind, resource_id in self.store.due_paths(instant(), PATH_BATCH):
            try:
                if kind not in self.roots or not re.fullmatch(kind + "-[0-9a-f]{32}", resource_id):
                    raise ValueError("Invalid retired path identity")
                await asyncio.to_thread(shutil.rmtree, self.roots[kind] / resource_id)
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                LOG.warning("Could not remove a retired LASA %s path; will retry", kind)
                self.store.finish_path(
                    kind, resource_id, retry_at=instant(time.time() + 5 * INTERVAL_SECONDS)
                )
                continue
            self.store.finish_path(kind, resource_id)

    async def run(self):
        after = ""
        while True:
            await self.collect()
            tasks = self.store.unresolved(after, RECONCILIATION_BATCH)
            for task_id in tasks:
                try:
                    await self.coordinator.reconcile_background(task_id)
                except Exception as exc:
                    LOG.warning("Background reconciliation failed (%s)", type(exc).__name__)
            after = tasks[-1] if len(tasks) == RECONCILIATION_BATCH else ""
            await asyncio.sleep(INTERVAL_SECONDS)
