<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-secret-1password

1Password secret backend plugin for Hegemony, packaged as an out-of-tree wheel.
Registers under the `hegemony.secret_backends` entry-point group with one entry
point (`onepassword`) that contributes two backend types:

| Backend type | Notes |
|--------------|-------|
| `onepassword_connect` | Authenticates against a self-hosted 1Password Connect server |
| `onepassword_service_account` | Authenticates with a 1Password Service Account token |

Both types resolve a `{{ secret('scheme://vault/item') }}` reference's `path` as
`"<vault>/<item>"` (vault title/id and item title/id, split on the first `/`) and
return a mapping of item field name to field value.

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

This package depends only on `hegemony-secret-sdk`, `onepasswordconnectsdk`, and
`onepassword-sdk`; it never imports Hegemony platform internals.
