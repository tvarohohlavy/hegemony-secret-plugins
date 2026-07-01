# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""1Password Connect secrets backend client.

This module provides a client for 1Password Connect server, authenticating with a
static Connect API token. It resolves ``"<vault>/<item>"`` references to the field
values of a 1Password item.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

logger = logging.getLogger(__name__)


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
        """
        vault, item = _split_path(path)

        result = self._client.get_item(item, vault)
        if result is None:
            return None

        return {field.label: field.value for field in result.fields if field.value is not None}

    def write(self, path: str, data: Mapping[str, Any]) -> None:
        """Not supported: 1Password items are managed in 1Password.

        Raises:
            NotImplementedError: Always.
        """
        raise NotImplementedError(
            "1Password items are managed in 1Password; this backend is read-only"
        )

    def test(self) -> None:
        """Verify connectivity and authentication against the Connect server.

        Performs a lightweight check: lists vaults reachable by the configured token.

        Raises:
            Exception: If the connectivity/authentication check fails.
        """
        self._client.get_vaults()
