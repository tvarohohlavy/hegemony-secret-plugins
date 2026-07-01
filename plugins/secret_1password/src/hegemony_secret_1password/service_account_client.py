# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""1Password Service Account secrets backend client.

This module provides a client for 1Password using the (async) ``onepassword-sdk``
Service Account SDK. The SDK's client is authenticated and used entirely through
``async``/``await``; since the :class:`~hegemony_secret_sdk.SecretBackend` contract is
synchronous and the host may already be running its own event loop, a dedicated
background event-loop thread is used to run every SDK coroutine.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

_DEFAULT_INTEGRATION_NAME = "Hegemony"
_INTEGRATION_VERSION = "0.1.0"


def _split_path(path: str) -> tuple[str, str]:
    """Split a ``"<vault>/<item>"`` reference path into its two parts.

    Args:
        path: Reference path in ``"<vault>/<item>"`` form.

    Returns:
        A ``(vault, item)`` tuple.

    Raises:
        ValueError: If ``path`` does not contain exactly two non-empty parts.
    """
    parts = path.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"1Password secret path must be '<vault>/<item>', got: {path!r}")
    return parts[0], parts[1]


class _AsyncLoopRunner:
    """Runs coroutines on a single dedicated background event loop.

    The 1Password Service Account SDK's authenticated client is bound to the event
    loop it was created on. Rather than spinning up a fresh loop per call (which
    would break that binding, and which ``asyncio.run`` cannot safely do from inside
    a host event loop anyway), a single loop runs forever on a background thread and
    every coroutine — including the initial ``authenticate`` call — is submitted to
    it via :func:`asyncio.run_coroutine_threadsafe`.
    """

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, daemon=True, name="hegemony-1password"
        )
        self._thread.start()

    def run(self, coro: Coroutine[Any, Any, _T]) -> _T:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()


_RUNNER: _AsyncLoopRunner | None = None


def _runner() -> _AsyncLoopRunner:
    global _RUNNER
    if _RUNNER is None:
        _RUNNER = _AsyncLoopRunner()
    return _RUNNER


@dataclass
class OnePasswordServiceAccountConfig:
    """Configuration for a 1Password Service Account backend.

    Attributes:
        service_account_token: Service account auth token (``ops_...``)
        integration_name: Integration name reported to 1Password (default: "Hegemony")
    """

    service_account_token: str
    integration_name: str = _DEFAULT_INTEGRATION_NAME

    @classmethod
    def from_dict(cls, config: dict) -> OnePasswordServiceAccountConfig:
        """Create an :class:`OnePasswordServiceAccountConfig` from a dictionary.

        Args:
            config: Dictionary with config values, as resolved by the host.

        Returns:
            OnePasswordServiceAccountConfig instance
        """
        return cls(
            service_account_token=config["service_account_token"],
            integration_name=config.get("integration_name", _DEFAULT_INTEGRATION_NAME),
        )


class OnePasswordServiceAccountBackend:
    """1Password secrets backend using a Service Account token.

    The underlying ``onepassword-sdk`` client is asynchronous; this backend
    authenticates lazily on a dedicated background event-loop thread and runs every
    subsequent SDK call on that same loop, so its synchronous ``read``/``test``
    methods can be safely called even from inside a host event loop.

    Example:
        config = OnePasswordServiceAccountConfig(service_account_token="ops_...")
        backend = OnePasswordServiceAccountBackend(config)

        # Read a secret
        data = backend.read("Engineering/Database")
        password = data["password"]
    """

    def __init__(self, config: OnePasswordServiceAccountConfig):
        """Initialize the 1Password Service Account backend.

        Args:
            config: 1Password Service Account backend configuration

        Raises:
            ImportError: If the onepassword-sdk library is not installed
        """
        try:
            import onepassword.client  # noqa: F401
        except ImportError as e:
            raise ImportError(
                "onepassword-sdk library is required for 1Password Service Account "
                "integration. Install with: pip install onepassword-sdk"
            ) from e

        self._config = config
        self._client: Any = None
        self._lock = threading.Lock()

    async def _authenticate(self) -> Any:
        from onepassword.client import Client

        return await Client.authenticate(
            auth=self._config.service_account_token,
            integration_name=self._config.integration_name,
            integration_version=_INTEGRATION_VERSION,
        )

    def _ensure_client(self) -> Any:
        """Authenticate lazily, on the shared background loop, and cache the client.

        Must be called from a thread other than the loop runner's own thread (i.e.
        from the synchronous ``read``/``test`` entry points, never from within a
        coroutine already scheduled on the runner), since it blocks on
        :meth:`_AsyncLoopRunner.run`.
        """
        if self._client is not None:
            return self._client

        with self._lock:
            if self._client is None:
                self._client = _runner().run(self._authenticate())
            return self._client

    async def _find_vault_id(self, client: Any, vault: str) -> str:
        vault_overviews = await client.vaults.list()
        for overview in vault_overviews:
            if overview.title == vault or overview.id == vault:
                return overview.id
        raise ValueError(f"1Password vault not found: {vault!r}")

    async def _find_item_id(self, client: Any, vault_id: str, item: str) -> str:
        item_overviews = await client.items.list(vault_id)
        for overview in item_overviews:
            if overview.title == item or overview.id == item:
                return overview.id
        raise ValueError(f"1Password item not found: {item!r}")

    async def _read(self, client: Any, vault: str, item: str) -> dict[str, Any]:
        vault_id = await self._find_vault_id(client, vault)
        item_id = await self._find_item_id(client, vault_id, item)
        found_item = await client.items.get(vault_id, item_id)
        return {field.title: field.value for field in found_item.fields if field.value is not None}

    def read(self, path: str) -> dict[str, Any] | None:
        """Read a 1Password item's fields via a Service Account.

        Args:
            path: Reference path in ``"<vault>/<item>"`` form (vault title/id and
                item title/id, split on the first ``/``).

        Returns:
            Mapping of field title to field value, or ``None`` if the item is not
            found.

        Raises:
            ValueError: If ``path`` is not exactly two non-empty parts, or if the
                vault or item cannot be found.
        """
        vault, item = _split_path(path)
        client = self._ensure_client()
        return _runner().run(self._read(client, vault, item))

    def write(self, path: str, data: Mapping[str, Any]) -> None:
        """Not supported: 1Password items are managed in 1Password.

        Raises:
            NotImplementedError: Always.
        """
        raise NotImplementedError(
            "1Password items are managed in 1Password; this backend is read-only"
        )

    def test(self) -> None:
        """Verify connectivity and authentication against 1Password.

        Performs a lightweight check: authenticates (if needed) and lists vaults
        reachable by the configured service account token.

        Raises:
            Exception: If the connectivity/authentication check fails.
        """
        client = self._ensure_client()
        _runner().run(client.vaults.list())
