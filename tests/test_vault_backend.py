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
    assert set(reg.types) == {"vault", "vault_kv2", "vault_kv1"}
    for entry in reg.types.values():
        assert entry["factory"] is plugin.build_vault_backend
        assert entry["config_schema"]["type"] == "object"
        assert entry["config_schema"]["required"] == ["address"]
        assert entry["display_name"]
        assert entry["description"]


def test_register_satisfies_sdk_registry_protocol():
    from hegemony_secret_sdk import SecretBackendRegistry

    assert isinstance(FakeRegistry(), SecretBackendRegistry)


def test_config_schema_marks_auth_material_as_secret_refs():
    reg = FakeRegistry()
    plugin.register(reg)
    schema = reg.types["vault"]["config_schema"]
    properties = schema["properties"]
    for field in ("token", "role_id", "secret_id", "role_id_file", "secret_id_file"):
        assert properties[field].get("x_secret_ref") is True, field
    assert "x_secret_ref" not in properties["address"]
    assert properties["verify_ssl"]["type"] == "boolean"


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
