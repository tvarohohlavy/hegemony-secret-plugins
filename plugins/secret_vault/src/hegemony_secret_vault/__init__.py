# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Hegemony HashiCorp Vault secret backend plugin.

Registers the Vault KV v2 backend under the ``hegemony.secret_backends`` entry-point
group. Two type strings are registered: ``vault`` (the preferred generic type) and
``vault_kv2`` (a hidden legacy alias of it, kept so existing backend rows keep
resolving); both build the same KV v2 :class:`VaultSecretsBackend`.
"""

from __future__ import annotations

from typing import Any

from hegemony_secret_sdk import SecretBackendRegistry

from .vault_client import VaultBackendConfig, VaultSecretsBackend

# Fields holding raw auth material (token/credential values or paths to files containing
# them). The host UI renders these with the secret/variable picker rather than a plain
# text input.
_SECRET_REF_FIELD = {"type": "string", "x_secret_ref": True}

_CONFIG_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["address"],
    "properties": {
        "address": {
            "type": "string",
            "title": "Vault address",
            "description": "Vault server address, e.g. http://vault:8200",
        },
        "kv_mount": {
            "type": "string",
            "title": "KV v2 mount point",
            "default": "hegemony",
        },
        "path_prefix": {
            "type": "string",
            "title": "Path prefix",
            "description": "Optional prefix applied to all secret paths.",
        },
        "token": {
            **_SECRET_REF_FIELD,
            "title": "Vault token",
            "description": "Static Vault token (dev mode). Takes precedence over AppRole.",
        },
        "role_id": {
            **_SECRET_REF_FIELD,
            "title": "AppRole role ID",
        },
        "secret_id": {
            **_SECRET_REF_FIELD,
            "title": "AppRole secret ID",
        },
        "role_id_file": {
            **_SECRET_REF_FIELD,
            "title": "AppRole role ID file",
            "description": "Path to a file containing the AppRole role ID.",
        },
        "secret_id_file": {
            **_SECRET_REF_FIELD,
            "title": "AppRole secret ID file",
            "description": "Path to a file containing the AppRole secret ID.",
        },
        "api_role_id": {
            **_SECRET_REF_FIELD,
            "title": "AppRole role ID (API override)",
            "description": (
                "Overrides role_id for the API component only. Set this when the API and "
                "worker authenticate to Vault with different AppRoles."
            ),
            "x_fallback_of": "role_id",
        },
        "api_secret_id": {
            **_SECRET_REF_FIELD,
            "title": "AppRole secret ID (API override)",
            "description": (
                "Overrides secret_id for the API component only. Set this when the API and "
                "worker authenticate to Vault with different AppRoles."
            ),
            "x_fallback_of": "secret_id",
        },
        "worker_role_id": {
            **_SECRET_REF_FIELD,
            "title": "AppRole role ID (worker override)",
            "description": (
                "Overrides role_id for the worker component only. Set this when the API and "
                "worker authenticate to Vault with different AppRoles."
            ),
            "x_fallback_of": "role_id",
        },
        "worker_secret_id": {
            **_SECRET_REF_FIELD,
            "title": "AppRole secret ID (worker override)",
            "description": (
                "Overrides secret_id for the worker component only. Set this when the API and "
                "worker authenticate to Vault with different AppRoles."
            ),
            "x_fallback_of": "secret_id",
        },
        "ca_cert_file": {
            "type": "string",
            "title": "CA certificate file",
            "description": "Optional path to a CA certificate bundle for TLS verification.",
        },
        "verify_ssl": {
            "type": "boolean",
            "title": "Verify SSL",
            "default": True,
        },
    },
}


def build_vault_backend(config: dict[str, Any]) -> VaultSecretsBackend:
    """Build a :class:`VaultSecretsBackend` from an already-resolved configuration dict."""
    return VaultSecretsBackend(VaultBackendConfig.from_dict(config))


def register(registry: SecretBackendRegistry) -> None:
    """Entry point for the ``hegemony.secret_backends`` group."""
    registry.register_backend_type(
        backend_type="vault",
        display_name="HashiCorp Vault (KV v2)",
        description="Generic HashiCorp Vault KV v2 secrets backend.",
        factory=build_vault_backend,
        config_schema=_CONFIG_SCHEMA,
    )
    registry.register_backend_type(
        backend_type="vault_kv2",
        display_name="HashiCorp Vault (KV v2, legacy type)",
        description=(
            "Legacy alias of the generic vault type; kept resolvable for existing "
            "backends but hidden from create-time type pickers."
        ),
        factory=build_vault_backend,
        config_schema=_CONFIG_SCHEMA,
        hidden=True,
    )


__all__ = ["build_vault_backend", "register"]
