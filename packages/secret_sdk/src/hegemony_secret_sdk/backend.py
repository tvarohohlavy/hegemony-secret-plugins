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

import builtins
from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SecretBackend(Protocol):
    """A concrete secret backend instance, as built by a plugin's ``BackendFactory``."""

    def read(self, path: str) -> Mapping[str, Any] | None:
        """Read the secret stored at ``path``; return ``None`` if it does not exist."""
        ...

    def write(self, path: str, data: Mapping[str, Any]) -> None:
        """Write ``data`` to the secret stored at ``path``."""
        ...

    def delete(self, path: str) -> None:
        """Delete the secret stored at ``path``; deleting a missing secret is not an error."""
        ...

    def test(self) -> None:
        """Verify connectivity/authentication against the backend; raise on failure."""
        ...


@runtime_checkable
class ListableSecretBackend(SecretBackend, Protocol):
    """A backend that can additionally enumerate its contents for browsing.

    Implementing this protocol is optional; the host feature-detects it (``hasattr``/
    ``isinstance``) and offers backend browsing only when present.
    """

    # builtins.list because the method name shadows the builtin in class scope.
    def list(self, path: str = "") -> builtins.list[str]:
        """List the names of the immediate children under ``path``.

        Container entries (which can be listed further) end with ``"/"``; leaf entries
        (readable secret paths) do not. An unknown or empty ``path`` returns ``[]``.
        """
        ...
