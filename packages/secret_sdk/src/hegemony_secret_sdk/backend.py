# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The ``SecretBackend`` contract a plugin-provided backend instance implements.

Unlike notification transports, secret backends are *leaf* components: the host does not
inject any services or context into them. A backend is self-contained — it receives its own
resolved configuration at construction time (via the registered factory) and talks directly
to the underlying secret store (Vault, etc.).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable


@runtime_checkable
class SecretBackend(Protocol):
    """A concrete secret backend instance, as built by a plugin's ``BackendFactory``."""

    def read(self, path: str) -> Mapping[str, str] | None:
        """Read the secret stored at ``path``; return ``None`` if it does not exist."""
        ...

    def write(self, path: str, data: Mapping[str, str]) -> None:
        """Write ``data`` to the secret stored at ``path``."""
        ...

    def test(self) -> None:
        """Verify connectivity/authentication against the backend; raise on failure."""
        ...
