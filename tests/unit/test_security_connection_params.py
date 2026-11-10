"""Tests for SecurityValidator.validate_connection_params credential decoding.

config.py builds DATABASE_URL with quote_plus-encoded credentials. The
connection params are passed to pg_dump/psql via PGPASSWORD, so they must
be decoded back to the raw values.
"""

from urllib.parse import quote_plus

import pytest

from app.core.utils.security import SecurityValidator


def _build_url(user: str, password: str) -> str:
    """Build DATABASE_URL the same way app/core/config.py does."""
    return (
        f"postgresql://{quote_plus(user)}:{quote_plus(password)}"
        "@postgres:5432/medical_records"
    )


@pytest.mark.parametrize(
    "password",
    [
        "plainpass",
        "p%ss",
        "100%secure",
        "p@ss:w/rd #1+x",
        "with space",
        "a&b=c?d$e!f",
    ],
)
def test_password_is_decoded_to_raw_value(password):
    params = SecurityValidator.validate_connection_params(
        _build_url("medapp", password)
    )

    assert params["password"] == password
    assert params["username"] == "medapp"
    assert params["hostname"] == "postgres"
    assert params["port"] == "5432"
    assert params["database"] == "medical_records"


def test_missing_password_returns_empty_string():
    params = SecurityValidator.validate_connection_params(
        "postgresql://medapp@postgres:5432/medical_records"
    )

    assert params["password"] == ""


def test_missing_username_defaults_to_postgres():
    params = SecurityValidator.validate_connection_params(
        "postgresql://postgres:5432/medical_records"
    )

    assert params["username"] == "postgres"
