<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-secret-1password

1Password secret backend plugin for Hegemony, packaged as an out-of-tree wheel.
It is discovered at runtime via the `hegemony.secret_backends` entry-point group
(`onepassword = "hegemony_secret_1password:register"`) and contributes two
backend types:

| Backend type | Notes |
|--------------|-------|
| `onepassword_connect` | Authenticates against a self-hosted [1Password Connect](https://developer.1password.com/docs/connect/) server |
| `onepassword_service_account` | Authenticates with a [1Password Service Account](https://developer.1password.com/docs/service-accounts/) token |

Both types resolve a `{{ secret('scheme://vault/item/field') }}` reference's
`path` as `"<vault>/<item>"` (vault title/id and item title/id, split on the
first `/`) and return a mapping of item field name to field value.

Secret backends are leaf components: unlike notification transports, the host
injects no services or context into a backend. The registered `factory` receives
only an already-resolved configuration dict and returns a backend instance whose
`read`/`write`/`test` methods talk directly to 1Password. Both backends are
read-only: `write` raises `NotImplementedError`, since 1Password items are managed
in 1Password rather than through Hegemony.

The Service Account backend wraps the official `onepassword-sdk`, which is
asynchronous; it authenticates and runs all subsequent SDK calls on a dedicated
background event-loop thread so its `read`/`test` methods remain synchronous and
safe to call even from inside a host event loop.

This package depends only on [`hegemony-secret-sdk`](../../packages/secret_sdk),
[`onepasswordconnectsdk`](https://pypi.org/project/onepasswordconnectsdk/) (the
official Connect client, used by `onepassword_connect`), and
[`onepassword-sdk`](https://pypi.org/project/onepassword-sdk/) (the official
Service Account SDK, used by `onepassword_service_account`); it never imports
Hegemony platform internals. Both third-party SDKs are pulled in as direct
dependencies of this wheel — no separate install step is needed for either
backend type.

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
uv pip install hegemony-secret-1password
```

## Configure

Create a secret backend using whichever type matches your 1Password
deployment. The form is schema-driven, so each field below is rendered
automatically and auth-material fields (`connect_token`,
`service_account_token`) get a secret/variable picker.

### `onepassword_connect`

Requires a running [1Password Connect server](https://developer.1password.com/docs/connect/)
and an issued Connect API token (a Connect *access token*, not an account
password).

| Field | Required | Default | Notes |
|---|---|---|---|
| `connect_host` | yes | — | 1Password Connect server address, e.g. `https://connect.example.com` |
| `connect_token` | yes | — | Connect API token |

```json
{
  "connect_host": "https://connect.example.com",
  "connect_token": "{{ env('OP_CONNECT_TOKEN') }}"
}
```

### `onepassword_service_account`

Requires a [1Password Service Account](https://developer.1password.com/docs/service-accounts/)
token (`ops_...`) with access to the vaults it should read from. No separate
host to run — the SDK talks to 1Password's cloud API directly.

| Field | Required | Default | Notes |
|---|---|---|---|
| `service_account_token` | yes | — | 1Password Service Account token, e.g. `ops_...` |
| `integration_name` | no | `Hegemony` | Integration name reported to 1Password |

```json
{
  "service_account_token": "{{ env('OP_SERVICE_ACCOUNT_TOKEN') }}"
}
```

## Usage

Once a backend of either type is registered under a name (the *scheme*, e.g.
`onepassword`), reference an item field from any Hegemony template field with:

```text
{{ secret('onepassword://Engineering/Database/password') }}
```

The portion after `scheme://` splits on the last `/`: everything before it is
the `path` passed to `read(path)` — here `Engineering/Database`, split on the
first `/` into vault (`Engineering`) and item (`Database`) title-or-id — and
the final segment is the `key` looked up by field name in the item (here
`password`). `write` always raises `NotImplementedError` for both backend
types.
