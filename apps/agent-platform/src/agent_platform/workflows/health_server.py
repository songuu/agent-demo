from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping

from prometheus_client import CollectorRegistry, generate_latest

type DependencyCheck = Callable[[], Awaitable[Mapping[str, str]]]


class WorkerHealthServer:
    """Small bounded HTTP surface for worker liveness, readiness, and metrics."""

    def __init__(
        self,
        *,
        dependency_check: DependencyCheck,
        registry: CollectorRegistry,
        host: str = "0.0.0.0",  # noqa: S104  # nosec B104 - policy limits ingress.
        health_port: int = 8081,
        metrics_port: int = 9464,
    ) -> None:
        if not 1 <= health_port <= 65_535 or not 1 <= metrics_port <= 65_535:
            raise ValueError("WORKER_HEALTH_PORT_INVALID")
        if health_port == metrics_port:
            raise ValueError("WORKER_HEALTH_PORTS_MUST_DIFFER")
        self._dependency_check = dependency_check
        self._registry = registry
        self._host = host
        self._health_port = health_port
        self._metrics_port = metrics_port
        self._health_server: asyncio.Server | None = None
        self._metrics_server: asyncio.Server | None = None
        self.ready = False

    async def start(self) -> None:
        self._health_server = await asyncio.start_server(
            self._handle_health,
            self._host,
            self._health_port,
        )
        try:
            self._metrics_server = await asyncio.start_server(
                self._handle_metrics,
                self._host,
                self._metrics_port,
            )
        except Exception:
            self._health_server.close()
            await self._health_server.wait_closed()
            self._health_server = None
            raise

    async def aclose(self) -> None:
        self.ready = False
        servers = [
            server
            for server in (self._health_server, self._metrics_server)
            if server is not None
        ]
        for server in servers:
            server.close()
        if servers:
            await asyncio.gather(*(server.wait_closed() for server in servers))
        self._health_server = None
        self._metrics_server = None

    async def _handle_health(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        path = await self._request_path(reader)
        if path == "/health":
            await self._respond_json(writer, 200, {"ok": True})
            return
        if path == "/ready":
            statuses: Mapping[str, str]
            try:
                statuses = await self._dependency_check()
            except Exception:
                statuses = {"dependencies": "error"}
            ready = self.ready and all(value == "ok" for value in statuses.values())
            await self._respond_json(
                writer,
                200 if ready else 503,
                {"ready": ready, "dependencies": dict(statuses)},
            )
            return
        await self._respond_json(writer, 404, {"error": "not_found"})

    async def _handle_metrics(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        path = await self._request_path(reader)
        if path != "/metrics":
            await self._respond_json(writer, 404, {"error": "not_found"})
            return
        payload = generate_latest(self._registry)
        await self._respond(
            writer,
            200,
            payload,
            "text/plain; version=0.0.4; charset=utf-8",
        )

    @staticmethod
    async def _request_path(reader: asyncio.StreamReader) -> str:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=2)
        except TimeoutError:
            return ""
        if len(request_line) > 4_096:
            return ""
        parts = request_line.decode("ascii", errors="replace").strip().split()
        if len(parts) != 3 or parts[0] != "GET":
            return ""
        return parts[1].split("?", maxsplit=1)[0]

    @classmethod
    async def _respond_json(
        cls,
        writer: asyncio.StreamWriter,
        status: int,
        body: Mapping[str, object],
    ) -> None:
        await cls._respond(
            writer,
            status,
            json.dumps(body, separators=(",", ":")).encode(),
            "application/json",
        )

    @staticmethod
    async def _respond(
        writer: asyncio.StreamWriter,
        status: int,
        body: bytes,
        content_type: str,
    ) -> None:
        reason = {200: "OK", 404: "Not Found", 503: "Service Unavailable"}[status]
        headers = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        writer.write(headers + body)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
