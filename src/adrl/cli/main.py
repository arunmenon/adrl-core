"""adrl command line. Primary: ADRL-OPS-001 (referenced by gloss). Secondary: ADRL-SAF-009."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import typer

from adrl.config.checks import all_checks
from adrl.config.loaders import canonical_json, load_bundle
from adrl.config.settings import Settings
from adrl.core.errors import ConfigError

app = typer.Typer(no_args_is_help=True, add_completion=False, help="ADRL operator commands")
config_app = typer.Typer(no_args_is_help=True, help="Configuration commands")
ledger_app = typer.Typer(no_args_is_help=True, help="Ledger commands")
app.add_typer(config_app, name="config")
app.add_typer(ledger_app, name="ledger")

from adrl.cli.ledger_commands import register as _register_ledger_commands  # noqa: E402

_register_ledger_commands(ledger_app)

from adrl.gates.cli import gates_app  # noqa: E402

app.add_typer(gates_app, name="gates")

from adrl.cli.product import connect_app, product_app  # noqa: E402

app.add_typer(connect_app, name="connect")
app.add_typer(product_app, name="product")

from adrl.cli.improvement import improve_app  # noqa: E402

app.add_typer(improve_app, name="improve")


@config_app.command("check")
def config_check(config_dir: Path | None = typer.Option(None, help="Config directory")) -> None:
    """Load every config file and run the load-time checks (ADRL-FND-002)."""
    settings = Settings() if config_dir is None else Settings(config_dir=config_dir)
    try:
        bundle = load_bundle(settings)
    except ConfigError as exc:
        typer.echo(f"FAIL {exc}")
        raise typer.Exit(code=1) from exc
    for result in all_checks(bundle, settings):
        typer.echo(f"{'ok  ' if result.ok else 'FAIL'} {result.name} {result.detail}".rstrip())
    typer.echo("versions " + json.dumps(bundle.versions, sort_keys=True))
    typer.echo(f"manifest_signature_verified {bundle.manifest_signature_verified}")


@config_app.command("sign-manifest")
def config_sign_manifest(
    key: Path = typer.Option(..., help="Ed25519 private key PEM"),
    config_dir: Path = typer.Option(Path("config")),
) -> None:
    """Sign repo-classification-v1.json (ADRL-SAF-008)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = serialization.load_pem_private_key(key.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        typer.echo("FAIL key must be Ed25519")
        raise typer.Exit(code=1)
    manifest_path = config_dir / "repo-classification-v1.json"
    payload = canonical_json(json.loads(manifest_path.read_bytes()))
    signature = base64.b64encode(private.sign(payload)).decode()
    (config_dir / "repo-classification-v1.sig").write_text(signature + "\n", encoding="utf-8")
    typer.echo("signed")


@config_app.command("sign-inventory")
def config_sign_inventory(
    key: Path = typer.Option(..., help="Ed25519 private key PEM"),
    config_dir: Path = typer.Option(Path("config")),
) -> None:
    """Sign endpoint-inventory-v1.json (ADRL-SAF-008 residency, ADRL-FND-002)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = serialization.load_pem_private_key(key.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        typer.echo("FAIL key must be Ed25519")
        raise typer.Exit(code=1)
    inventory_path = config_dir / "endpoint-inventory-v1.json"
    payload = canonical_json(json.loads(inventory_path.read_bytes()))
    signature = base64.b64encode(private.sign(payload)).decode()
    (config_dir / "endpoint-inventory-v1.sig").write_text(signature + "\n", encoding="utf-8")
    typer.echo("signed")


@ledger_app.command("verify-egress")
def ledger_verify_egress(
    path: Path | None = typer.Option(None, help="Path to egress.db"),
    public_key: list[Path] = typer.Option(
        [], "--public-key", help="Checkpoint public key PEM; repeat for a key set (rotation)"
    ),
    anchors: Path | None = typer.Option(
        None, help="Anchor file shipped off-device; detects deletion or truncation"
    ),
    chain_only: bool = typer.Option(
        False, "--chain-only", help="Check only the hash chain; not an audit"
    ),
) -> None:
    """Verify the egress hash chain, every checkpoint signature and the anchors (ADRL-SAF-009).

    Exit code is non-zero on any failure. Without --public-key the checkpoint signatures are
    not verified, so the command fails unless --chain-only says that was the intent; an audit
    needs the key set and the anchor file.
    """
    from adrl.ledger.anchoring import load_public_keys, read_anchor_file
    from adrl.ledger.egress import EgressLedger

    settings = Settings()
    ledger = EgressLedger(path or settings.egress_ledger_path)
    ledger.open()
    failed = False
    try:
        chain = ledger.verify_chain()
        typer.echo(f"chain entries {chain.entries} ok {chain.ok} {chain.detail or ''}".rstrip())
        failed = failed or not chain.ok
        if public_key:
            keys = load_public_keys(public_key)
            checkpoints = ledger.verify_checkpoints(keys)
            typer.echo(
                f"checkpoints {checkpoints.checkpoints} ok {checkpoints.ok} "
                f"newest_seq {checkpoints.newest_seq} {checkpoints.detail or ''}".rstrip()
            )
            failed = failed or not checkpoints.ok
            if anchors is not None:
                records = read_anchor_file(anchors)
                result = ledger.verify_against_anchors(records, keys)
                typer.echo(
                    f"anchors {result.anchors} ok {result.ok} "
                    f"newest_anchored_seq {result.newest_anchored_seq} "
                    f"{result.detail or ''}".rstrip()
                )
                failed = failed or not result.ok
        elif chain_only:
            typer.echo("chain only: checkpoint signatures not verified (not an audit)")
        else:
            typer.echo(
                "signatures not verified: pass --public-key (and --anchors) for an audit, "
                "or --chain-only to check the chain alone"
            )
            failed = True
        status = ledger.anchor_status()
        typer.echo(
            f"ledger_id {status['ledger_id']} unshipped {status['unshipped_checkpoints']} "
            f"newest_anchored_seq {status['newest_anchored_seq']}"
        )
    finally:
        ledger.close()
    if failed:
        raise typer.Exit(code=1)


@app.command("serve")
def serve(
    host: str | None = typer.Option(None, help="Listen host"),
    port: int | None = typer.Option(None, help="Listen port"),
) -> None:
    """Run the proxy (ADRL-FND-001)."""
    from adrl.app import serve as run_server

    settings = Settings()
    overrides: dict[str, object] = {}
    if host is not None:
        overrides["listen_host"] = host
    if port is not None:
        overrides["listen_port"] = port
    if overrides:
        settings = settings.model_copy(update=overrides)
    run_server(settings)


@app.command("audit")
def audit(lineage: str = typer.Option(..., help="Lineage HMAC")) -> None:
    """Did this lineage's content ever leave the machine (ADRL-SAF-009)."""
    from adrl.ledger.egress import EgressLedger

    settings = Settings()
    ledger = EgressLedger(settings.egress_ledger_path)
    ledger.open()
    try:
        rows = ledger.lineage_left_machine(lineage)
    finally:
        ledger.close()
    typer.echo(
        json.dumps({"lineage": lineage, "left_machine": bool(rows), "events": rows}, indent=2)
    )


@app.command("release")
def release(
    lineage: str = typer.Option(..., help="Lineage HMAC"),
    finding: str = typer.Option(..., help="Finding id shown in the block message"),
    reason: str = typer.Option(..., help="false_positive or test_fixture"),
    actor: str = typer.Option(..., help="Who is releasing"),
) -> None:
    """Audited human pin release (ADRL-SAF-002). Delegates to `adrl gates release`."""
    from adrl.core.enums import ReleaseReason
    from adrl.gates.cli import release as gates_release

    gates_release(lineage=lineage, finding=finding, reason=ReleaseReason(reason), actor=actor)


@app.command("verify")
def verify(
    snapshot: Path = typer.Option(..., help="Repository snapshot (worktree) to run in"),
    command: str = typer.Option(..., help="Allow-listed command, space separated"),
    allow: list[str] = typer.Option(..., help="Allow-list entries; repeat the flag"),
    timeout_s: float = typer.Option(300.0),
) -> None:
    """Sandboxed verification command (ADRL-SAF-007). Delegates to `adrl gates verify`."""
    from adrl.gates.cli import verify as gates_verify

    gates_verify(snapshot=snapshot, command=command, allow=allow, timeout_s=timeout_s)


@app.command("gateway-config")
def gateway_config(
    config_dir: Path = typer.Option(Path("config"), help="Config directory"),
    endpoints: Path | None = typer.Option(
        None,
        help="endpoint inventory JSON; default is the signed one in config",
    ),
    out: Path | None = typer.Option(None, help="Write the generated config here"),
) -> None:
    """Generate the LiteLLM config from rungs.yaml (ADRL-FND-002)."""
    import importlib.util
    import sys

    tools_dir = Path(__file__).resolve().parents[3] / "tools"
    spec = importlib.util.spec_from_file_location(
        "gen_litellm_config", tools_dir / "gen_litellm_config.py"
    )
    if spec is None or spec.loader is None:
        typer.echo("FAIL tools/gen_litellm_config.py not found")
        raise typer.Exit(code=1)
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_litellm_config"] = module
    spec.loader.exec_module(module)
    argv = ["--config-dir", str(config_dir)]
    if endpoints:
        argv += ["--endpoints", str(endpoints)]
    if out:
        argv += ["--out", str(out)]
    raise typer.Exit(code=int(module.main(argv)))


# learning (bucket LRN) -------------------------------------------------------------------

learning_app = typer.Typer(no_args_is_help=True, help="Learning commands (shadow-side, ADRL-LRN)")
app.add_typer(learning_app, name="learning")
cascade_app = typer.Typer(help="Cascade reports (ADRL-CAS-001)")
app.add_typer(cascade_app, name="cascade")


@cascade_app.command("coverage")
def cascade_coverage(
    ledger: Path | None = typer.Option(None, help="Path to adrl.db"),
) -> None:
    """Trip-wire miss and false-fire rates per rung over closed_final outcomes."""
    import json as _json

    from adrl.cascade.tripwires import coverage_report
    from adrl.ledger.store import LedgerStore

    settings = Settings()
    store = LedgerStore(ledger or settings.ledger_path)
    store.open()
    try:
        report = coverage_report(store)
    finally:
        store.close()
    typer.echo(_json.dumps(report, indent=2, sort_keys=True, default=str))


@app.command("readiness")
def readiness(
    ledger: Path | None = typer.Option(None, help="Path to adrl.db"),
    t1_required: int = typer.Option(300, help="EVL-004 T1 label requirement"),
) -> None:
    """Learning readiness report with blockers listed, never averaged (EVL-009)."""
    from adrl.learning.readiness import build_report
    from adrl.learning.tiers import LedgerExampleReader, TieredDataset
    from adrl.ledger.store import LedgerStore

    settings = Settings()
    bundle = load_bundle(settings)
    store = LedgerStore(ledger or settings.ledger_path)
    store.open()
    try:
        examples = [e for e in LedgerExampleReader(store).read() if e.family == "organic"]
    finally:
        store.close()
    dataset = TieredDataset.build(examples, bundle.learning_contract, family="organic")
    report = build_report(
        dataset,
        verifier_precision_threshold=bundle.learning_contract.verifier_precision_threshold,
        t1_required=t1_required,
    )
    typer.echo(report.render_json())


@learning_app.command("build-dataset")
def learning_build_dataset(
    ledger: Path | None = typer.Option(None, help="Path to adrl.db"),
    out: Path = typer.Option(Path("artifacts/dataset.json"), help="Output path"),
    holdout_fraction: float = typer.Option(0.3),
) -> None:
    """Build the T1 frame from decision-time snapshots with a temporal session split."""
    from adrl.learning.dataset import build_frame, temporal_session_split
    from adrl.learning.tiers import LedgerExampleReader, TieredDataset
    from adrl.ledger.store import LedgerStore

    settings = Settings()
    bundle = load_bundle(settings)
    store = LedgerStore(ledger or settings.ledger_path)
    store.open()
    try:
        examples = [e for e in LedgerExampleReader(store).read() if e.family == "organic"]
    finally:
        store.close()
    dataset = TieredDataset.build(examples, bundle.learning_contract, family="organic")
    frame = build_frame(dataset.objective_examples(), bundle.learning_contract).labelled()
    split = temporal_session_split(frame, holdout_fraction=holdout_fraction)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "features_version": frame.features_version,
                "tier_mix": dataset.tier_mix(),
                "train": [r.route_id for r in split.train.rows],
                "holdout": [r.route_id for r in split.holdout.rows],
                "dropped_straddling_sessions": split.dropped_straddling_sessions,
                "cutoff_ts": split.cutoff_ts,
            },
            indent=2,
        )
    )
    typer.echo(f"train {len(split.train)} holdout {len(split.holdout)} written {out}")


@learning_app.command("train")
def learning_train(
    dataset_path: Path = typer.Option(Path("artifacts/dataset.json")),
    out_dir: Path = typer.Option(Path("artifacts/estimator")),
    seed: int = typer.Option(0),
) -> None:
    """Train the CATE estimator as a proposal; it is never loaded without graduation."""
    from adrl.learning.artifacts import (
        ArtifactManifest,
        compatibility_from_bundle,
        save_model,
        write_manifest,
    )
    from adrl.learning.dataset import FeatureEncoder, build_frame
    from adrl.learning.estimator import CateEstimator, check_target_columns
    from adrl.learning.tiers import LedgerExampleReader, TieredDataset
    from adrl.ledger.store import LedgerStore

    settings = Settings()
    bundle = load_bundle(settings)
    check_target_columns(["verified_outcome"], bundle.learning_contract)
    spec = json.loads(dataset_path.read_text())
    train_ids = set(spec["train"])
    store = LedgerStore(settings.ledger_path)
    store.open()
    try:
        examples = [
            e
            for e in LedgerExampleReader(store).read()
            if e.family == "organic" and e.route_id in train_ids
        ]
        high_water = store.read("SELECT COALESCE(MAX(seq), 0) AS hw FROM events")[0]["hw"]
    finally:
        store.close()
    dataset = TieredDataset.build(examples, bundle.learning_contract, family="organic")
    frame = build_frame(dataset.objective_examples(), bundle.learning_contract).labelled()
    if len(frame) < 8:
        typer.echo(f"FAIL only {len(frame)} T1 rows; nothing to train")
        raise typer.Exit(code=1)
    encoder = FeatureEncoder(bundle.learning_contract)
    matrix = encoder.fit_transform(frame)
    estimator = CateEstimator(bundle.learning_contract).fit(frame, matrix)
    model_sha = save_model({"encoder": encoder, "estimator": estimator}, out_dir / "model.pkl")
    manifest = ArtifactManifest(
        artifact_id="cate-estimator",
        artifact_kind="estimator",
        artifact_version=f"cate-{seed}-{int(high_water)}",
        feature_schema_version=bundle.learning_contract.feature_schema_version,
        data_snapshot=dataset_path.name,
        objective="cate:verified_outcome",
        calibration={},
        thresholds={},
        policy_compatibility=compatibility_from_bundle(bundle),
        training_code_commit=_git_commit(),
        seed=seed,
        embedding_model_version=None,
        ledger_high_water_mark=int(high_water),
        tier_mix=dataset.tier_mix(),
        deny_list_version=bundle.learning_contract.version,
        target_columns=("verified_outcome",),
        model_file="model.pkl",
        model_sha256=model_sha,
    )
    write_manifest(manifest, out_dir / "manifest.json")
    typer.echo(f"proposal written to {out_dir}; graduation required before load (ADRL-LRN-007)")


@learning_app.command("evaluate")
def learning_evaluate(
    manifest_path: Path = typer.Option(Path("artifacts/estimator/manifest.json")),
) -> None:
    """Report whether an artifact would load: graduation and policy compatibility."""
    from adrl.learning.artifacts import ArtifactRefusedError, load_graduated

    settings = Settings()
    bundle = load_bundle(settings)
    key_path = settings.config_dir / "keys/dev/manifest-signing.pub"
    try:
        loaded = load_graduated(manifest_path, bundle, key_path.read_bytes())
    except ArtifactRefusedError as exc:
        typer.echo(f"REFUSED {exc.reason}: {exc.detail}")
        raise typer.Exit(code=1) from exc
    typer.echo(f"loadable {loaded.manifest.artifact_id} {loaded.manifest.artifact_version}")


@learning_app.command("explore-check")
def learning_explore_check() -> None:
    """Show the exploration configuration and its bounds (ADRL-LRN-008)."""
    from adrl.learning.explore import EPSILON_UPPER_BOUND, ExplorationArtifact

    settings = Settings()
    bundle = load_bundle(settings)
    policy = bundle.policy
    if not policy.exploration_epsilon_by_rung or policy.exploration_version is None:
        typer.echo("exploration disabled: no epsilon configured (propensity 1.0 on every turn)")
        return
    artifact = ExplorationArtifact(policy.exploration_version, policy.exploration_epsilon_by_rung)
    typer.echo(
        json.dumps(
            {
                "version": artifact.version,
                "epsilon_by_rung": {r.value: e for r, e in artifact.epsilon_by_rung.items()},
                "upper_bound": EPSILON_UPPER_BOUND,
                "graduated": artifact.graduated,
            },
            indent=2,
        )
    )


def _git_commit() -> str:
    import subprocess

    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return "unknown"
    return out.stdout.strip() or "unknown"


from adrl.gates.cli import launch as _gates_launch  # noqa: E402

app.command("launch")(_gates_launch)


if __name__ == "__main__":
    app()
