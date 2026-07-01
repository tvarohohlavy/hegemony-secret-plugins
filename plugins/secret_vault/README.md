<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-secret-vault

HashiCorp Vault secret backend plugin for Hegemony, packaged as an out-of-tree
wheel. It is discovered at runtime via the `hegemony.secret_backends`
entry-point group (`vault = "hegemony_secret_vault:register"`) and contributes
three backend type strings:

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

This package depends only on [`hegemony-secret-sdk`](../../packages/secret_sdk)
and [`hvac`](https://pypi.org/project/hvac/) (the official HashiCorp Vault
client); it never imports Hegemony platform internals.

## Install

The wheel is **opt-in** — it is not bundled in the default images. See the root
[Install From A Release](../../README.md#install-from-a-release) guide for Docker
commands, checksum verification, and local-wheel development installs. Both the
**API** (to list/validate the backend type and resolve secrets) and the
**worker** (to resolve secrets at run time) need the wheel installed into
`/opt/venv`; restart both after installing so each registry reloads its entry
points.

For local development against this repository:

```bash
uv pip install hegemony-secret-vault
```

## Configure

Create a secret backend of type `vault` (or `vault_kv2`; see the table above)
pointing at your Vault server. The form is schema-driven, so each field below
is rendered automatically and auth-material fields (`token`, `role_id`,
`secret_id`, `role_id_file`, `secret_id_file`) get a secret/variable picker.

| Field | Required | Default | Notes |
|---|---|---|---|
| `address` | yes | — | Vault server address, e.g. `http://vault:8200` |
| `kv_mount` | no | `hegemony` | KV v2 mount point |
| `path_prefix` | no | — | Optional prefix applied to all secret paths |
| `token` | no | — | Static Vault token (dev mode). Takes precedence over AppRole |
| `role_id` / `secret_id` | no | — | AppRole credentials (production auth) |
| `role_id_file` / `secret_id_file` | no | — | Paths to files containing the AppRole role/secret ID, as an alternative to inline values |
| `ca_cert_file` | no | — | Optional path to a CA certificate bundle for TLS verification |
| `verify_ssl` | no | `true` | Verify the TLS certificate |

Exactly one auth method must resolve: a static `token`, or an AppRole pair
(`role_id`/`role_id_file` plus `secret_id`/`secret_id_file`). Registering the
backend fails with a clear error if neither is configured.

Minimal config (dev mode, static token):

```json
{
  "address": "http://vault:8200",
  "token": "{{ env('VAULT_TOKEN') }}"
}
```

AppRole (production):

```json
{
  "address": "https://vault.example.com:8200",
  "kv_mount": "hegemony",
  "role_id": "{{ env('VAULT_ROLE_ID') }}",
  "secret_id": "{{ env('VAULT_SECRET_ID') }}"
}
```

## Usage

Once a `vault` (or `vault_kv2`/`vault_kv1`) backend is registered under a name
(the *scheme*, e.g. `vault`), reference secrets stored in it from any Hegemony
template field with:

```text
{{ secret('vault://orgs/default/secrets/db/password') }}
```

The portion after `scheme://` splits on the last `/`: everything before it is
the `path` passed to `read(path)` (here `orgs/default/secrets/db`, the KV v2
secret path under `kv_mount`), and the final segment is the `key` looked up in
the returned field mapping (here `password`). `write(path, data)` follows the
same path convention when secrets are managed through the Hegemony API rather
than directly in Vault.
