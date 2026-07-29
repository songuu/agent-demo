from __future__ import annotations

import os
from datetime import timedelta

import boto3
import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from temporalio.client import Client

pytestmark = pytest.mark.integration


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        pytest.skip(f"{name} is required for the service-backed CI integration gate")
    return value


@pytest.mark.asyncio
async def test_required_postgres_is_reachable_and_migrated() -> None:
    engine = create_async_engine(_required("AGENT_TEST_DATABASE_URL"))
    try:
        async with engine.connect() as connection:
            revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
    finally:
        await engine.dispose()

    assert isinstance(revision, str)
    assert revision


@pytest.mark.asyncio
async def test_required_temporal_service_passes_health_rpc() -> None:
    client = await Client.connect(_required("AGENT_TEST_TEMPORAL_ADDRESS"))

    assert await client.service_client.check_health(timeout=timedelta(seconds=10))


def test_required_minio_contains_the_ci_bucket() -> None:
    client = boto3.client(
        "s3",
        endpoint_url=_required("AGENT_TEST_MINIO_URL"),
        aws_access_key_id=_required("AGENT_TEST_MINIO_ACCESS_KEY"),
        aws_secret_access_key=_required("AGENT_TEST_MINIO_SECRET_KEY"),
        region_name="us-east-1",
    )

    response = client.head_bucket(Bucket=_required("AGENT_TEST_MINIO_BUCKET"))

    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200


@pytest.mark.asyncio
async def test_required_opa_serves_the_expected_policy_bundle() -> None:
    base_url = _required("AGENT_TEST_OPA_URL").rstrip("/")
    async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
        response = await client.get(f"{base_url}/v1/data/bundle/version")

    response.raise_for_status()
    assert response.json() == {"result": "1.0.0"}
