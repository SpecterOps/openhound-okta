import pytest

from openhound_okta.utils.auth import OktaAuth


def test_okta_auth_requires_private_key_source():
    with pytest.raises(ValueError, match="private_key_path or private_key_string"):
        OktaAuth()
