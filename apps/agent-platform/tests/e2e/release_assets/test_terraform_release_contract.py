from __future__ import annotations

from pathlib import Path

PLATFORM_ROOT = Path(__file__).resolve().parents[3]
TERRAFORM_ROOT = PLATFORM_ROOT / "deploy" / "terraform"


def _read(relative_path: str) -> str:
    return (TERRAFORM_ROOT / relative_path).read_text(encoding="utf-8")


def test_terraform_and_provider_versions_are_exactly_locked() -> None:
    versions = _read("versions.tf")
    lock = _read(".terraform.lock.hcl")

    assert 'required_version = "= 1.9.8"' in versions
    assert 'version = "= 2.36.0"' in versions
    assert 'version     = "2.36.0"' in lock
    assert '"h1:' in lock
    assert '"zh:' in lock


def test_release_contract_covers_external_foundation_without_cloud_apply() -> None:
    variables = _read("variables.tf")
    main = _read("main.tf")

    for contract in (
        'variable "release_id"',
        'variable "git_sha"',
        'variable "foundation_attestation"',
        'variable "foundation_plan"',
        'variable "postgres"',
        'variable "artifact_storage"',
        'variable "temporal"',
        'variable "opa_bundle"',
        'variable "egress"',
        'variable "secret_manager"',
    ):
        assert contract in variables

    for invariant in (
        "plan_sha256",
        "signature_bundle_uri",
        "source_sha256",
        "terraform_version",
        "validated",
        "high_availability",
        "pitr_enabled",
        "object_lock_enabled",
        "per_object_retention_enabled",
        "worker_versioning_enabled",
        "fail_closed",
        "metadata_service_denied",
        "workload_identity_references",
    ):
        assert invariant in variables

    for binding in (
        "release_id              = var.release_id",
        "git_sha                 = var.git_sha",
        "foundation_attestation  = var.foundation_attestation",
        "foundation_plan         = var.foundation_plan",
        "postgres                = var.postgres",
        "artifact_storage        = var.artifact_storage",
        "temporal                = var.temporal",
        "opa_bundle              = var.opa_bundle",
        "egress                  = var.egress",
        "secret_manager          = var.secret_manager",
    ):
        assert binding in main

    assert 'provider "aws"' not in main
    assert 'provider "google"' not in main
    assert 'provider "azurerm"' not in main
    assert "api_key" not in main.lower()
    assert "password" not in main.lower()


def test_mock_plans_cover_release_environments_and_critical_fail_closed_cases() -> None:
    staging = _read("tests/staging.tftest.hcl")
    production = _read("tests/production.tftest.hcl")

    assert 'mock_provider "kubernetes"' in staging
    assert 'run "staging_mock_plan_satisfies_release_contract"' in staging
    assert "command = plan" in staging

    for run_name in (
        "production_mock_plan_satisfies_release_contract",
        "reject_unsigned_foundation_plan",
        "reject_release_mismatched_foundation_attestation",
        "reject_production_postgres_without_pitr",
        "reject_production_unlocked_final_artifact_bucket",
        "reject_production_locked_multipart_staging_bucket",
        "reject_production_temporal_without_tls",
        "reject_production_opa_fail_open",
        "reject_permissive_production_egress",
        "reject_incomplete_production_secret_references",
    ):
        assert f'run "{run_name}"' in production

    assert production.count("expect_failures") == 9
    assert production.count("command = plan") == 10
