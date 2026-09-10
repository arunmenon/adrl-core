"""Safety, privacy and hard constraints. Primary: ADRL-SAF-001.

Gates run on every request class before optimisation and only ever tighten the permitted rung
set within a lineage. The pipeline in :mod:`adrl.gates.pipeline` is the single entry point the
proxy calls; the other modules are the individual gates and their supporting adapters.
"""

from adrl.gates.pipeline import GateOutcome, GatePipeline

__all__ = ["GateOutcome", "GatePipeline"]
