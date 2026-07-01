# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the 1Password secret backend plugin: registration + mocked-client behavior."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import hegemony_secret_1password as plugin
from hegemony_secret_1password.connect_client import (
    OnePasswordConnectBackend,
    OnePasswordConnectConfig,
)
from hegemony_secret_1password.service_account_client import (
    OnePasswordServiceAccountBackend,
    OnePasswordServiceAccountConfig,
)


class FakeRegistry:
    api_version = 1

    def __init__(self) -> None:
        self.types: dict[str, dict[str, Any]] = {}

    def register_backend_type(self, *, backend_type: str, **kwargs: Any) -> None:
        self.types[backend_type] = kwargs


def test_register_adds_expected_backend_types():
    reg = FakeRegistry()
    plugin.register(reg)
    assert set(reg.types) == {"onepassword_connect", "onepassword_service_account"}
    for entry in reg.types.values():
        assert entry["config_schema"]["type"] == "object"
        assert entry["display_name"]
        assert entry["description"]
    assert reg.types["onepassword_connect"]["factory"] is plugin.build_onepassword_connect_backend
    assert (
        reg.types["onepassword_service_account"]["factory"]
        is plugin.build_onepassword_service_account_backend
    )


def test_register_satisfies_sdk_registry_protocol():
    from hegemony_secret_sdk import SecretBackendRegistry

    assert isinstance(FakeRegistry(), SecretBackendRegistry)


def test_connect_config_schema_marks_token_as_secret_ref():
    reg = FakeRegistry()
    plugin.register(reg)
    schema = reg.types["onepassword_connect"]["config_schema"]
    assert schema["required"] == ["connect_host", "connect_token"]
    properties = schema["properties"]
    assert properties["connect_token"].get("x_secret_ref") is True
    assert "x_secret_ref" not in properties["connect_host"]


def test_service_account_config_schema_marks_token_as_secret_ref():
    reg = FakeRegistry()
    plugin.register(reg)
    schema = reg.types["onepassword_service_account"]["config_schema"]
    assert schema["required"] == ["service_account_token"]
    properties = schema["properties"]
    assert properties["service_account_token"].get("x_secret_ref") is True
    assert "x_secret_ref" not in properties["integration_name"]
    assert properties["integration_name"]["default"] == "Hegemony"


# --- Connect backend -------------------------------------------------------------


def _fake_field(label: str, value: Any) -> MagicMock:
    field = MagicMock()
    field.label = label
    field.value = value
    return field


def _connect_backend_with_mock_client() -> tuple[OnePasswordConnectBackend, MagicMock]:
    config = OnePasswordConnectConfig(
        connect_host="https://connect.example.com", connect_token="tok"
    )
    with patch("onepasswordconnectsdk.client.new_client") as mock_new_client:
        mock_client = MagicMock()
        mock_new_client.return_value = mock_client
        backend = OnePasswordConnectBackend(config)
    return backend, mock_client


def test_connect_build_backend_returns_backend_instance():
    with patch("onepasswordconnectsdk.client.new_client") as mock_new_client:
        mock_new_client.return_value = MagicMock()
        backend = plugin.build_onepassword_connect_backend(
            {"connect_host": "https://connect.example.com", "connect_token": "tok"}
        )
    assert isinstance(backend, OnePasswordConnectBackend)


def test_connect_read_returns_field_mapping():
    backend, mock_client = _connect_backend_with_mock_client()
    mock_item = MagicMock()
    mock_item.fields = [_fake_field("username", "alice"), _fake_field("password", "hunter2")]
    mock_client.get_item.return_value = mock_item

    result = backend.read("Engineering/Database")

    assert result == {"username": "alice", "password": "hunter2"}
    mock_client.get_item.assert_called_once_with("Database", "Engineering")


def test_connect_read_skips_none_valued_fields():
    backend, mock_client = _connect_backend_with_mock_client()
    mock_item = MagicMock()
    mock_item.fields = [_fake_field("username", "alice"), _fake_field("otp", None)]
    mock_client.get_item.return_value = mock_item

    result = backend.read("Engineering/Database")

    assert result == {"username": "alice"}


def test_connect_read_raises_value_error_for_malformed_path():
    backend, _ = _connect_backend_with_mock_client()
    try:
        backend.read("nokey")
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "vault" in str(exc).lower() or "path" in str(exc).lower()


def test_connect_write_raises_not_implemented():
    backend, _ = _connect_backend_with_mock_client()
    try:
        backend.write("Engineering/Database", {"password": "new"})
        raise AssertionError("expected NotImplementedError")
    except NotImplementedError:
        pass


def test_connect_test_calls_get_vaults():
    backend, mock_client = _connect_backend_with_mock_client()
    backend.test()
    mock_client.get_vaults.assert_called_once()


# --- Service account backend ------------------------------------------------------


def _fake_vault_overview(vault_id: str, title: str) -> MagicMock:
    overview = MagicMock()
    overview.id = vault_id
    overview.title = title
    return overview


def _fake_item_overview(item_id: str, title: str) -> MagicMock:
    overview = MagicMock()
    overview.id = item_id
    overview.title = title
    return overview


def _fake_item_field(title: str, value: Any) -> MagicMock:
    field = MagicMock()
    field.title = title
    field.value = value
    return field


def _service_account_backend_with_mock_client() -> tuple[
    OnePasswordServiceAccountBackend, MagicMock
]:
    config = OnePasswordServiceAccountConfig(service_account_token="ops_test")
    backend = OnePasswordServiceAccountBackend(config)

    mock_client = MagicMock()
    mock_client.vaults.list = AsyncMock(
        return_value=[_fake_vault_overview("vault-1", "Engineering")]
    )
    mock_client.items.list = AsyncMock(return_value=[_fake_item_overview("item-1", "Database")])
    mock_item = MagicMock()
    mock_item.fields = [
        _fake_item_field("username", "alice"),
        _fake_item_field("password", "hunter2"),
        _fake_item_field("otp", None),
    ]
    mock_client.items.get = AsyncMock(return_value=mock_item)

    with patch(
        "onepassword.client.Client.authenticate",
        new=AsyncMock(return_value=mock_client),
    ):
        # Force authentication eagerly within this patch context so the cached
        # client is the mock, regardless of when read()/test() trigger it.
        backend._ensure_client()

    return backend, mock_client


def test_service_account_build_backend_returns_backend_instance():
    backend = plugin.build_onepassword_service_account_backend(
        {"service_account_token": "ops_test"}
    )
    assert isinstance(backend, OnePasswordServiceAccountBackend)


def test_service_account_read_resolves_vault_and_item_to_fields():
    backend, mock_client = _service_account_backend_with_mock_client()

    result = backend.read("Engineering/Database")

    assert result == {"username": "alice", "password": "hunter2"}
    mock_client.vaults.list.assert_called_once()
    mock_client.items.list.assert_called_once_with("vault-1")
    mock_client.items.get.assert_called_once_with("vault-1", "item-1")


def test_service_account_read_raises_value_error_for_malformed_path():
    backend, _ = _service_account_backend_with_mock_client()
    try:
        backend.read("nokey")
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "vault" in str(exc).lower() or "path" in str(exc).lower()


def test_service_account_read_raises_for_unknown_vault():
    backend, mock_client = _service_account_backend_with_mock_client()
    try:
        backend.read("NoSuchVault/Database")
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "NoSuchVault" in str(exc)


def test_service_account_write_raises_not_implemented():
    backend, _ = _service_account_backend_with_mock_client()
    try:
        backend.write("Engineering/Database", {"password": "new"})
        raise AssertionError("expected NotImplementedError")
    except NotImplementedError:
        pass


def test_service_account_test_calls_vaults_list():
    backend, mock_client = _service_account_backend_with_mock_client()
    backend.test()
    assert mock_client.vaults.list.call_count >= 1


def test_service_account_config_defaults():
    config = OnePasswordServiceAccountConfig(service_account_token="ops_test")
    assert config.integration_name == "Hegemony"


def test_service_account_config_from_dict_custom_integration_name():
    config = OnePasswordServiceAccountConfig.from_dict(
        {"service_account_token": "ops_test", "integration_name": "Custom"}
    )
    assert config.integration_name == "Custom"
