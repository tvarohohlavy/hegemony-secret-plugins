<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-secret-vault

HashiCorp Vault secret backend plugin for Hegemony, packaged as an out-of-tree
wheel. Registers under the `hegemony.secret_backends` entry-point group with
one entry point (`vault`) that contributes three backend type strings:

| Backend type | Notes |
|--------------|-------|
| `vault` | Generic Vault KV v2 backend |
| `vault_kv2` | Explicit KV v2 backend (the same client as `vault`) |
| `vault_kv1` | Reserved for legacy KV v1; the current client speaks the KV v2 API |

All three types build the same `VaultSecretsBackend`, which supports static
token auth (dev mode) and AppRole auth (production), with thread-safe token
caching and automatic re-authentication.

Secret backends are leaf components: unlike notification transports, the host
injects no services or context into a backend. The registered `factory`
receives only an already-resolved configuration dict and returns a backend
instance whose `read`/`write`/`test` methods talk directly to Vault.

This package depends only on `hegemony-secret-sdk` and `hvac`; it never
imports Hegemony platform internals.
