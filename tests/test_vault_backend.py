# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the Vault secret backend plugin: registration + backend behavior via hvac mocks."""

from typing import Any
from unittest.mock import MagicMock, patch

import hegemony_secret_vault as plugin
from hegemony_secret_vault.vault_client import VaultBackendConfig, VaultSecretsBackend


class FakeRegistry:
    api_version = 1

    def __init__(self) -> None:
        self.types: dict[str, dict[str, Any]] = {}

    def register_backend_type(self, *, backend_type: str, **kwargs: Any) -> None:
        self.types[backend_type] = kwargs


def test_register_adds_expected_backend_types():
    reg = FakeRegistry()
    plugin.register(reg)
    assert set(reg.types) == {"vault", "vault_kv2"}
    assert reg.types["vault"]["factory"] is plugin.build_vault_backend
    assert reg.types["vault_kv2"]["factory"] is plugin.build_vault_backend
    for entry in reg.types.values():
        assert entry["config_schema"]["type"] == "object"
        assert entry["config_schema"]["required"] == ["address"]
        assert entry["display_name"]
        assert entry["description"]


def test_register_uses_distinct_display_names():
    # Every backend type must render as a distinct label in the host's type dropdown;
    # duplicate display names make entries indistinguishable to users.
    reg = FakeRegistry()
    plugin.register(reg)
    display_names = [entry["display_name"] for entry in reg.types.values()]
    assert len(display_names) == len(set(display_names))


def test_register_display_names():
    reg = FakeRegistry()
    plugin.register(reg)
    assert reg.types["vault"]["display_name"] == "HashiCorp Vault (KV v2)"
    assert reg.types["vault_kv2"]["display_name"] == "HashiCorp Vault (KV v2, legacy type)"


def test_register_marks_only_vault_kv2_hidden():
    # vault_kv2 is a legacy alias of vault: resolvable for existing rows, hidden from
    # create-time type pickers. The preferred vault type stays visible.
    reg = FakeRegistry()
    plugin.register(reg)
    assert reg.types["vault_kv2"].get("hidden") is True
    assert reg.types["vault"].get("hidden", False) is False


def test_register_satisfies_sdk_registry_protocol():
    from hegemony_secret_sdk import SecretBackendRegistry

    assert isinstance(FakeRegistry(), SecretBackendRegistry)


def test_config_schema_marks_auth_material_as_secret_refs():
    reg = FakeRegistry()
    plugin.register(reg)
    schema = reg.types["vault"]["config_schema"]
    properties = schema["properties"]
    for field in (
        "token",
        "role_id",
        "secret_id",
        "role_id_file",
        "secret_id_file",
        "api_role_id",
        "api_secret_id",
        "worker_role_id",
        "worker_secret_id",
    ):
        assert properties[field].get("x_secret_ref") is True, field
    assert "x_secret_ref" not in properties["address"]
    assert properties["verify_ssl"]["type"] == "boolean"


def test_config_schema_includes_per_component_approle_overrides():
    # The host remaps api_role_id/api_secret_id and worker_role_id/worker_secret_id to
    # role_id/secret_id before building the client (see apps/api/routers/secrets.py,
    # apps/api/services/git_ops.py, apps/worker/template_resolver.py in the host repo).
    # These must be present in the schema so the schema-driven form can set them.
    reg = FakeRegistry()
    plugin.register(reg)
    schema = reg.types["vault"]["config_schema"]
    properties = schema["properties"]
    for field in ("api_role_id", "api_secret_id", "worker_role_id", "worker_secret_id"):
        assert properties[field]["type"] == "string"
        assert properties[field].get("title")


def test_config_schema_marks_component_overrides_with_fallback_of():
    # x_fallback_of lets the host UI show which base field an override inherits from.
    reg = FakeRegistry()
    plugin.register(reg)
    properties = reg.types["vault"]["config_schema"]["properties"]
    assert properties["api_role_id"]["x_fallback_of"] == "role_id"
    assert properties["worker_role_id"]["x_fallback_of"] == "role_id"
    assert properties["api_secret_id"]["x_fallback_of"] == "secret_id"
    assert properties["worker_secret_id"]["x_fallback_of"] == "secret_id"
    assert "x_fallback_of" not in properties["role_id"]
    assert "x_fallback_of" not in properties["secret_id"]


@patch("hvac.Client")
def test_build_vault_backend_returns_backend_instance(mock_client_cls):
    mock_client_cls.return_value = MagicMock(token="static-token")
    backend = plugin.build_vault_backend({"address": "http://vault:8200", "token": "s3cret"})
    assert isinstance(backend, VaultSecretsBackend)


def _backend_with_mock_client(**config_overrides) -> tuple[VaultSecretsBackend, MagicMock]:
    config = VaultBackendConfig.from_dict(
        {"address": "http://vault:8200", "token": "tok", **config_overrides}
    )
    with patch("hvac.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        backend = VaultSecretsBackend(config)
    return backend, mock_client


def test_read_returns_kv2_data():
    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"password": "hunter2"}}
    }
    result = backend.read("orgs/default/secrets/db")
    assert result == {"password": "hunter2"}
    mock_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path="orgs/default/secrets/db", mount_point="hegemony"
    )


def test_write_calls_create_or_update_secret():
    backend, mock_client = _backend_with_mock_client()
    backend.write("orgs/default/secrets/db", {"password": "new-pass"})
    mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once_with(
        path="orgs/default/secrets/db", secret={"password": "new-pass"}, mount_point="hegemony"
    )


def test_delete_calls_delete_metadata_and_all_versions():
    backend, mock_client = _backend_with_mock_client()
    backend.delete("orgs/default/secrets/db")
    mock_client.secrets.kv.v2.delete_metadata_and_all_versions.assert_called_once_with(
        path="orgs/default/secrets/db", mount_point="hegemony"
    )


def test_delete_ignores_invalid_path():
    from hvac.exceptions import InvalidPath

    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.delete_metadata_and_all_versions.side_effect = InvalidPath()
    backend.delete("orgs/default/secrets/db")  # should not raise


def test_test_calls_auth_check_and_reads_kv_configuration():
    backend, mock_client = _backend_with_mock_client()
    backend.test()
    mock_client.secrets.kv.v2.read_configuration.assert_called_once_with(mount_point="hegemony")


def test_test_raises_vault_error_on_connectivity_failure():
    from hegemony_secret_vault.vault_client import VaultError

    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.read_configuration.side_effect = RuntimeError("connection refused")
    try:
        backend.test()
        raise AssertionError("expected VaultError")
    except VaultError:
        pass


def test_list_returns_kv2_keys():
    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.list_secrets.return_value = {"data": {"keys": ["db", "apps/"]}}
    assert backend.list("orgs/default") == ["db", "apps/"]
    mock_client.secrets.kv.v2.list_secrets.assert_called_once_with(
        path="orgs/default", mount_point="hegemony"
    )


def test_list_unknown_path_returns_empty():
    from hvac.exceptions import InvalidPath

    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.list_secrets.side_effect = InvalidPath()
    assert backend.list("nope") == []


def test_backend_satisfies_listable_protocol():
    from hegemony_secret_sdk import ListableSecretBackend

    backend, _ = _backend_with_mock_client()
    assert isinstance(backend, ListableSecretBackend)


def test_vault_backend_config_defaults():
    config = VaultBackendConfig(address="http://vault:8200")
    assert config.address == "http://vault:8200"
    assert config.kv_mount == "hegemony"
    assert config.path_prefix == ""
    assert config.verify_ssl is True


def test_vault_backend_config_all_fields():
    config = VaultBackendConfig(
        address="https://vault.example.com:8200",
        kv_mount="secrets",
        path_prefix="orgs",
        role_id="test-role-id",
        secret_id="test-secret-id",
        ca_cert_file="/path/to/ca.crt",
        verify_ssl=True,
    )
    assert config.kv_mount == "secrets"
    assert config.path_prefix == "orgs"
    assert config.role_id == "test-role-id"
    assert config.secret_id == "test-secret-id"
    assert config.ca_cert_file == "/path/to/ca.crt"


def test_vault_backend_missing_auth_raises():
    config = VaultBackendConfig(address="http://vault:8200")
    assert config.role_id is None
    assert config.secret_id is None
    with patch("hvac.Client") as mock_client_cls:
        mock_client_cls.return_value = MagicMock(token=None)
        try:
            VaultSecretsBackend(config)
            raise AssertionError("expected ValueError for missing auth")
        except ValueError as exc:
            assert "role_id" in str(exc).lower()


# --- AppRole auth lifecycle -------------------------------------------------------


def _approle_backend_with_mock_client(**config_overrides) -> tuple[VaultSecretsBackend, MagicMock]:
    config = VaultBackendConfig.from_dict({"address": "http://vault:8200", **config_overrides})
    with patch("hvac.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        backend = VaultSecretsBackend(config)
    return backend, mock_client


def test_approle_non_expiring_token_authenticates_once():
    """lease_duration 0 = a token that never expires; it must not force a fresh
    AppRole login (and a new Vault token) on every single operation."""
    backend, mock_client = _approle_backend_with_mock_client(role_id="rid", secret_id="sid")
    mock_client.auth.approle.login.return_value = {"auth": {"lease_duration": 0}}
    mock_client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"k": "v"}}}

    backend.read("a/b")
    backend.read("a/b")

    assert mock_client.auth.approle.login.call_count == 1


def test_approle_positive_lease_reuses_token_within_ttl():
    backend, mock_client = _approle_backend_with_mock_client(role_id="rid", secret_id="sid")
    mock_client.auth.approle.login.return_value = {"auth": {"lease_duration": 3600}}
    mock_client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"k": "v"}}}

    backend.read("a/b")
    backend.read("a/b")

    assert mock_client.auth.approle.login.call_count == 1


def test_approle_reauth_rereads_credential_files(tmp_path):
    """Rotated *_file contents (e.g. a Vault Agent re-writing the secret-id file) must
    be picked up on the next authentication without rebuilding the client."""
    role_file = tmp_path / "role_id"
    secret_file = tmp_path / "secret_id"
    role_file.write_text("rid-1\n")
    secret_file.write_text("sid-1\n")
    backend, mock_client = _approle_backend_with_mock_client(
        role_id_file=str(role_file), secret_id_file=str(secret_file)
    )
    mock_client.auth.approle.login.return_value = {"auth": {"lease_duration": 3600}}
    mock_client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {}}}

    backend.read("a/b")
    assert mock_client.auth.approle.login.call_args.kwargs == {
        "role_id": "rid-1",
        "secret_id": "sid-1",
    }

    secret_file.write_text("sid-2\n")
    backend._token_expiry = 0  # force re-authentication on the next call
    backend.read("a/b")
    assert mock_client.auth.approle.login.call_args.kwargs == {
        "role_id": "rid-1",
        "secret_id": "sid-2",
    }
