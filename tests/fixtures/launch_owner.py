"""Abrupt owner exit fixture. Primary: ADRL-OPS-001, ADRL-SAF-007."""

import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from uuid import UUID

from adrl.api.auth import Principal
from adrl.api.store import ProductStore
from adrl.core.container_control import ContainerControl, ResourcePolicy
from adrl.core.isolated_execution import IsolatedExecution
from adrl.core.resource_owner import StoppedResourceOwner
from adrl.gates.workload import RepoInventory, WorkloadAssertion
from adrl.ledger.attempts import AttemptJournal
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.store import LedgerStore

v = json.load(sys.stdin)
a = v["principal"]["assertion"]
a["inventory"] = RepoInventory(**a["inventory"])
v["principal"]["assertion"] = WorkloadAssertion(**a)
principal = Principal(**v["principal"])
store = LedgerStore(Path(v["db"]))
store.open()
keys = FileKeyStore(Path(v["keys"]), store=store)
profile = Path(v["profile"]).read_bytes()
control = ContainerControl(
    Path(v["socket"]),
    profile,
    hashlib.sha256(profile).hexdigest(),
    ResourcePolicy(request_seconds=1),
)
run = IsolatedExecution(StoppedResourceOwner(AttemptJournal(ProductStore(store, keys)), control))
start = run.control.start


def die(identity):
    start(identity)
    os._exit(17)


run.control.start = die
asyncio.run(run.run(principal, UUID(v["operation"])))
