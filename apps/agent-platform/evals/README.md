# Agent evaluation assets

The manifest covers Golden, Edge, Adversarial, Incident-derived,
Production-sample, and Synthetic layers. Synthetic cases expand coverage but
never satisfy a release gate by themselves.

The live release population is source-backed: the four live datasets contain
at least 50 independently authored high/critical scenarios. The runner rejects
duplicate semantic or input SHA-256 fingerprints and executes each source
scenario exactly once; repeated IDs or repeated runs cannot satisfy the human
review minimum.

All versioned grader labels resolve through a closed executable registry. Live
hard graders consume independently fetched snapshot, audit, metrics, Artifact,
and fault-receipt observations; unknown labels or missing immutable sources block
the case. Offline mode reuses the same closed schema but remains only a
credential-free deterministic preflight.

Recovery cases use an authenticated staging-only controller for planner, worker,
verifier, approval, commit, model, tool, database, Artifact, and OPA faults. The
candidate manifest and results retain controller-signed Ed25519 receipts whose
schema binds release, git SHA, image digest, case/source, run, snapshot, audit, key,
and fixed signer identity. Every live case declares an exact ordered capability
trajectory with canonical argument hashes and invocation receipts. Human review is
bound to the canonical SHA-256 of the exact final result, claims, evidence,
audit/Artifact references, grader results, fault receipt, expected/observed tool
trajectories, and the complete release/git/image/case/source trajectory binding.

`release-policy.json` encodes the hard gates from the architecture:

- all hard gates pass;
- must-claim evidence coverage is at least 99%;
- every must success criterion has a matching, passed deterministic verification;
- critical-tool selection is at least 98% with zero high-risk misselection;
- mean cost per success regresses no more than 15%;
- P95 completion latency regresses no more than 20%;
- high-risk releases review at least 50 representative samples with zero major
  finding.

Run the deterministic release decision with:

```text
python evals/graders/release_gate.py --policy evals/release-policy.json --results results.json
```

Exit code `0` means pass and `2` means blocked. Model graders may contribute
quality scores but can never override schema, tenant, policy, side-effect, or
trajectory hard gates.
