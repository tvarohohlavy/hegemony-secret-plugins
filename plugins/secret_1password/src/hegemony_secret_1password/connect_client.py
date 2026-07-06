# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""1Password Connect secrets backend client.

This module provides a client for 1Password Connect server, authenticating with a
static Connect API token. It resolves ``"<vault>/<item>"`` references to the field
values of a 1Password item.
"""

from __future__ import annotations

import builtins
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

logger = logging.getLogger(__name__)

# The Connect SDK's title-based lookups embed the HTTP status only in the exception
# message ("Unable to retrieve items. Received 401 ..."); ``status_code`` is attached
# solely by id-based lookups.
_RECEIVED_STATUS_PATTERN = re.compile(r"\bReceived (\d{3})\b")


def _extract_status_code(exc: Exception) -> int | None:
    """Best-effort HTTP status carried by a Connect SDK exception, or ``None``."""
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return status
    match = _RECEIVED_STATUS_PATTERN.search(str(exc))
    return int(match.group(1)) if match else None


def _is_not_found(exc: Exception) -> bool:
    """Whether an SDK lookup failure means "does not exist" rather than a real error.

    The SDK raises ``FailedToRetrieveItemException`` for *any* failure — a missing
    item/vault, but also 401/403/5xx responses. Treating those alike would surface an
    expired Connect token as "secret not found", so only a 404 (or a pure lookup miss
    carrying no HTTP status at all, e.g. "Found 0 items") counts as not-found.
    """
    status = _extract_status_code(exc)
    return status is None or status == 404


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


@dataclass
class OnePasswordConnectConfig:
    """Configuration for a 1Password Connect backend.

    Attributes:
        connect_host: 1Password Connect server address (e.g., "https://connect.example.com")
        connect_token: Connect API token used to authenticate requests
    """

    connect_host: str
    connect_token: str

    @classmethod
    def from_dict(cls, config: dict) -> OnePasswordConnectConfig:
        """Create an :class:`OnePasswordConnectConfig` from a dictionary.

        Args:
            config: Dictionary with config values, as resolved by the host.

        Returns:
            OnePasswordConnectConfig instance
        """
        return cls(
            connect_host=config["connect_host"],
            connect_token=config["connect_token"],
        )


class OnePasswordConnectBackend:
    """1Password secrets backend using a Connect server.

    Example:
        config = OnePasswordConnectConfig(
            connect_host="https://connect.example.com",
            connect_token="eyJhbGciOi...",
        )
        backend = OnePasswordConnectBackend(config)

        # Read a secret
        data = backend.read("Engineering/Database")
        password = data["password"]
    """

    def __init__(self, config: OnePasswordConnectConfig):
        """Initialize the 1Password Connect backend.

        Args:
            config: 1Password Connect backend configuration

        Raises:
            ImportError: If the onepasswordconnectsdk library is not installed
        """
        try:
            from onepasswordconnectsdk.client import Client, new_client
        except ImportError as e:
            raise ImportError(
                "onepasswordconnectsdk library is required for 1Password Connect "
                "integration. Install with: pip install onepasswordconnectsdk"
            ) from e

        self._config = config
        # `new_client(..., is_async=False)` (the default) always returns a synchronous
        # `Client`; the SDK's declared return type is a broader union only because the
        # same function also supports building an `AsyncClient`.
        self._client = cast(Client, new_client(config.connect_host, config.connect_token))

    def read(self, path: str) -> dict[str, Any] | None:
        """Read a 1Password item's fields via Connect.

        Args:
            path: Reference path in ``"<vault>/<item>"`` form (vault title/id and
                item title/id, split on the first ``/``).

        Returns:
            Mapping of field label to field value, or ``None`` if the item is not
            found.

        Raises:
            ValueError: If ``path`` is not exactly two non-empty parts.
            FailedToRetrieveItemException: If the lookup fails for any reason other
                than the vault/item not existing (e.g. auth or server errors).
        """
        from onepasswordconnectsdk.errors import FailedToRetrieveItemException

        vault, item = _split_path(path)

        try:
            result = self._client.get_item(item, vault)
        except FailedToRetrieveItemException as exc:
            if _is_not_found(exc):
                return None
            raise

        return {
            field.label: field.value for field in result.fields or [] if field.value is not None
        }

    def write(self, path: str, data: Mapping[str, Any]) -> None:
        """Create or update the 1Password item at ``path`` with ``data`` as its fields.

        A new item is created as a Secure Note whose concealed custom fields are the
        ``data`` keys; an existing item has its fields replaced with ``data``.

        Args:
            path: Reference path in ``"<vault>/<item>"`` form.
            data: Mapping of field label to value.

        Raises:
            ValueError: If ``path`` is malformed or the vault cannot be found.
        """
        from onepasswordconnectsdk.errors import FailedToRetrieveItemException
        from onepasswordconnectsdk.models import Field, Item, ItemVault

        vault, item_name = _split_path(path)
        vault_id = self._resolve_vault_id(vault)
        if vault_id is None:
            raise ValueError(f"1Password vault not found: {vault!r}")

        fields = [
            Field(label=key, value=str(value), type="CONCEALED") for key, value in data.items()
        ]

        try:
            existing = self._client.get_item(item_name, vault_id)
        except FailedToRetrieveItemException as exc:
            if not _is_not_found(exc):
                raise
            existing = None

        if existing is None:
            self._client.create_item(
                vault_id,
                Item(
                    title=item_name,
                    category="SECURE_NOTE",
                    vault=ItemVault(id=vault_id),
                    fields=fields,
                ),
            )
            return

        existing.fields = fields
        self._client.update_item(existing.id, vault_id, existing)

    def delete(self, path: str) -> None:
        """Delete the 1Password item at ``path``; a missing vault or item is not an error.

        Args:
            path: Reference path in ``"<vault>/<item>"`` form.

        Raises:
            ValueError: If ``path`` is malformed.
        """
        from onepasswordconnectsdk.errors import FailedToRetrieveItemException

        vault, item_name = _split_path(path)
        vault_id = self._resolve_vault_id(vault)
        if vault_id is None:
            return
        try:
            existing = self._client.get_item(item_name, vault_id)
        except FailedToRetrieveItemException as exc:
            if _is_not_found(exc):
                return
            raise
        self._client.delete_item(existing.id, vault_id)

    # builtins.list because the method name shadows the builtin in class scope.
    def list(self, path: str = "") -> builtins.list[str]:
        """List vaults (empty ``path``) or the item titles inside one vault.

        Args:
            path: ``""`` to list vault names (returned with a trailing ``"/"``), or a
                vault title/id to list its item titles (leaf entries).

        Returns:
            The immediate children under ``path``; ``[]`` for an unknown vault or for
            anything deeper (items are leaves).
        """
        normalized = path.strip("/")
        if not normalized:
            return [f"{vault.name}/" for vault in self._client.get_vaults() or []]
        if "/" in normalized:
            return []

        vault_id = self._resolve_vault_id(normalized)
        if vault_id is None:
            return []
        return [item.title for item in self._client.get_items(vault_id) or []]

    def _resolve_vault_id(self, vault: str) -> str | None:
        """Resolve a vault title or id to its id; return ``None`` if not found."""
        for candidate in self._client.get_vaults() or []:
            if candidate.name == vault or candidate.id == vault:
                return candidate.id
        return None

    def test(self) -> None:
        """Verify connectivity and authentication against the Connect server.

        Performs a lightweight check: lists vaults reachable by the configured token.

        Raises:
            Exception: If the connectivity/authentication check fails.
        """
        self._client.get_vaults()
