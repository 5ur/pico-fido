import pytest

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.cose import ES256
from fido2.ctap2.extensions import PreviewSignExtension
from fido2.utils import websafe_decode, websafe_encode


@pytest.fixture(scope="function")
def preview_sign_credential(resetdevice):
    result = resetdevice.doMC(
        rk=True,
        extensions={
            "previewSign": {
                "generateKey": {"algorithms": [ES256.ALGORITHM]},
            },
        },
    )
    extension = result["client_extension_results"]["previewSign"]
    return result["res"].attestation_object, extension["generatedKey"]


def test_preview_sign_is_advertised(info):
    assert "previewSign" in info.extensions


def test_preview_sign_generates_and_uses_es256_key(device, preview_sign_credential):
    credential, generated_key = preview_sign_credential
    assert generated_key["algorithm"] == ES256.ALGORITHM
    assert generated_key["keyHandle"]

    tbs = b"Pico FIDO previewSign ES256 test vector"
    credential_id = credential.auth_data.credential_data.credential_id
    assertion_selection = device.doGA(
        allow_list=[{"id": credential_id, "type": "public-key"}],
        extensions={
            "previewSign": {
                "signByCredential": {
                    websafe_encode(credential_id): {
                        "keyHandle": generated_key["keyHandle"],
                        "tbs": tbs,
                    },
                },
            },
        },
    )
    assertion = assertion_selection["res"].get_response(0)
    signature = websafe_decode(
        assertion.client_extension_results["previewSign"]["signature"]
    )

    assert signature
    ES256(cbor.decode(websafe_decode(generated_key["publicKey"]))).verify(tbs, signature)


def test_preview_sign_rejects_a_tampered_key_handle(device, preview_sign_credential):
    credential, generated_key = preview_sign_credential
    credential_id = credential.auth_data.credential_data.credential_id
    tampered_handle = bytearray(websafe_decode(generated_key["keyHandle"]))
    tampered_handle[-1] ^= 1

    with pytest.raises(CtapError) as error:
        device.doGA(
            allow_list=[{"id": credential_id, "type": "public-key"}],
            extensions={
                "previewSign": {
                    "signByCredential": {
                        websafe_encode(credential_id): {
                            "keyHandle": websafe_encode(bytes(tampered_handle)),
                            "tbs": b"must not be signed",
                        },
                    },
                },
            },
        )
    assert error.value.code == CtapError.ERR.INVALID_CREDENTIAL
