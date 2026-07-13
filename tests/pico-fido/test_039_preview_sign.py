import pytest
from cryptography.exceptions import InvalidSignature

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2.base import AttestationResponse
from fido2.cose import ES256, ES384, ES512, EdDSA
from fido2.ctap2.extensions import PreviewSignExtension
from fido2.utils import websafe_decode, websafe_encode
from utils import verify


@pytest.fixture(scope="function")
def preview_sign_credential(resetdevice):
    return _register_preview_key(resetdevice, ES256)


def _bytes(value):
    return websafe_decode(value) if isinstance(value, str) else value


def _register_preview_key(device, cose_algorithm, algorithms=None):
    result = device.doMC(
        rk=True,
        extensions={
            "previewSign": {
                "generateKey": {
                    "algorithms": algorithms or [cose_algorithm.ALGORITHM],
                },
            },
        },
    )
    extension = result["client_extension_results"]["previewSign"]
    return result["res"].attestation_object, extension["generatedKey"]


def _preview_signature(device, credential, generated_key, tbs):
    credential_id = credential.auth_data.credential_data.credential_id
    selection = device.doGA(
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
    response = selection["res"].get_response(0)
    credential.auth_data.credential_data.public_key.verify(
        response.response.authenticator_data + selection["req"]["client_data"].hash,
        response.response.signature,
    )
    return _bytes(response.client_extension_results["previewSign"]["signature"])


@pytest.mark.parametrize("sign_flags", [0, 1, 5])
def test_preview_sign_inner_attestation_preserves_sign_flags(resetdevice, sign_flags):
    result = resetdevice.MC(
        extensions={"previewSign": {3: [ES256.ALGORITHM], 4: sign_flags}}
    )
    response = result["res"]
    outer_extension = response.auth_data.extensions["previewSign"]
    encoded_inner_attestation = response.unsigned_extension_outputs["previewSign"][7]
    inner = AttestationResponse.from_dict(cbor.decode(encoded_inner_attestation))
    inner_credential = inner.auth_data.credential_data

    assert outer_extension[3] == ES256.ALGORITHM
    assert inner.fmt == "packed"
    assert inner.auth_data.counter == 0
    assert inner_credential is not None
    assert inner_credential.credential_id
    assert inner_credential.public_key[3] == ES256.ALGORITHM
    assert inner.auth_data.extensions["previewSign"][4] == sign_flags
    ES256(inner_credential.public_key).verify(
        bytes(inner.auth_data) + result["req"]["client_data_hash"],
        inner.att_stmt["sig"],
    )


@pytest.mark.parametrize(
    ("algorithms", "sign_flags", "expected_error"),
    [
        ([], 1, CtapError.ERR.UNSUPPORTED_ALGORITHM),
        ([ES256.ALGORITHM], 2, CtapError.ERR.INVALID_OPTION),
        ([ES256.ALGORITHM], 3, CtapError.ERR.INVALID_OPTION),
        ([ES256.ALGORITHM], 4, CtapError.ERR.INVALID_OPTION),
    ],
)
def test_preview_sign_rejects_invalid_raw_registration_inputs(
    resetdevice, algorithms, sign_flags, expected_error
):
    with pytest.raises(CtapError) as error:
        resetdevice.MC(
            extensions={"previewSign": {3: algorithms, 4: sign_flags}}
        )

    assert error.value.code == expected_error


def test_preview_sign_unattended_key_signs_without_user_presence(resetdevice):
    registration = resetdevice.MC(
        extensions={"previewSign": {3: [ES256.ALGORITHM], 4: 0}}
    )
    credential = registration["res"]
    credential_id = credential.auth_data.credential_data.credential_id
    inner = AttestationResponse.from_dict(
        cbor.decode(
            credential.unsigned_extension_outputs["previewSign"][7]
        )
    )
    preview_credential = inner.auth_data.credential_data
    tbs = b"unattended previewSign request"

    assertion = resetdevice.GA(
        allow_list=[{"id": credential_id, "type": "public-key"}],
        extensions={"previewSign": {2: preview_credential.credential_id, 6: tbs}},
        options={"up": False},
    )
    response = assertion["res"]

    assert not (response.auth_data.flags & response.auth_data.FLAG.UP)
    verify(credential, response, assertion["req"]["client_data_hash"])
    ES256(preview_credential.public_key).verify(
        tbs, response.auth_data.extensions["previewSign"][6]
    )


@pytest.mark.parametrize("missing_input", [2, 6])
def test_preview_sign_rejects_a_missing_assertion_input(resetdevice, missing_input):
    registration = resetdevice.MC(
        extensions={"previewSign": {3: [ES256.ALGORITHM], 4: 0}}
    )
    credential = registration["res"]
    credential_id = credential.auth_data.credential_data.credential_id
    inner = AttestationResponse.from_dict(
        cbor.decode(credential.unsigned_extension_outputs["previewSign"][7])
    )
    extension_input = {2: inner.auth_data.credential_data.credential_id, 6: b"test"}
    del extension_input[missing_input]

    with pytest.raises(CtapError) as error:
        resetdevice.GA(
            allow_list=[{"id": credential_id, "type": "public-key"}],
            options={"up": False},
            extensions={"previewSign": extension_input},
        )

    assert error.value.code == CtapError.ERR.INVALID_OPTION


def test_preview_sign_requires_user_presence_when_requested(resetdevice):
    registration = resetdevice.MC(
        extensions={"previewSign": {3: [ES256.ALGORITHM], 4: 1}}
    )
    credential = registration["res"]
    credential_id = credential.auth_data.credential_data.credential_id
    inner = AttestationResponse.from_dict(
        cbor.decode(credential.unsigned_extension_outputs["previewSign"][7])
    )

    with pytest.raises(CtapError) as error:
        resetdevice.GA(
            allow_list=[{"id": credential_id, "type": "public-key"}],
            options={"up": False},
            extensions={
                "previewSign": {2: inner.auth_data.credential_data.credential_id, 6: b"UP required"}
            },
        )

    assert error.value.code == CtapError.ERR.UP_REQUIRED


def test_preview_sign_requires_user_verification_when_requested(resetdevice):
    registration = resetdevice.MC(
        extensions={"previewSign": {3: [ES256.ALGORITHM], 4: 5}}
    )
    credential = registration["res"]
    credential_id = credential.auth_data.credential_data.credential_id
    inner = AttestationResponse.from_dict(
        cbor.decode(credential.unsigned_extension_outputs["previewSign"][7])
    )

    with pytest.raises(CtapError) as error:
        resetdevice.GA(
            allow_list=[{"id": credential_id, "type": "public-key"}],
            options={"up": True},
            extensions={
                "previewSign": {2: inner.auth_data.credential_data.credential_id, 6: b"UV required"}
            },
        )

    assert error.value.code == CtapError.ERR.PUAT_REQUIRED


def test_preview_sign_is_advertised(info):
    assert "previewSign" in info.extensions


def test_preview_sign_generates_and_uses_es256_key(device, preview_sign_credential):
    credential, generated_key = preview_sign_credential
    assert generated_key["algorithm"] == ES256.ALGORITHM
    assert generated_key["keyHandle"]

    tbs = b"Pico FIDO previewSign ES256 test vector"
    signature = _preview_signature(device, credential, generated_key, tbs)

    assert signature
    ES256(cbor.decode(websafe_decode(generated_key["publicKey"]))).verify(tbs, signature)


@pytest.mark.parametrize("cose_algorithm", [ES256, ES384, ES512, EdDSA])
def test_preview_sign_signs_with_each_supported_algorithm(device, cose_algorithm):
    credential, generated_key = _register_preview_key(device, cose_algorithm)
    public_key = cbor.decode(_bytes(generated_key["publicKey"]))
    tbs = b"previewSign algorithm matrix: " + str(cose_algorithm.ALGORITHM).encode()
    signature = _preview_signature(device, credential, generated_key, tbs)

    assert generated_key["algorithm"] == cose_algorithm.ALGORITHM
    assert public_key[3] == cose_algorithm.ALGORITHM
    cose_algorithm(public_key).verify(tbs, signature)


def test_preview_sign_uses_the_first_supported_algorithm(device):
    credential, generated_key = _register_preview_key(
        device,
        ES384,
        algorithms=[ES384.ALGORITHM, ES256.ALGORITHM],
    )
    tbs = b"previewSign selection order"
    signature = _preview_signature(device, credential, generated_key, tbs)

    assert generated_key["algorithm"] == ES384.ALGORITHM
    ES384(cbor.decode(_bytes(generated_key["publicKey"]))).verify(tbs, signature)


def test_preview_sign_skips_unsupported_algorithms_before_a_supported_one(device):
    credential, generated_key = _register_preview_key(
        device,
        ES256,
        algorithms=[-47, ES256.ALGORITHM],
    )

    assert generated_key["algorithm"] == ES256.ALGORITHM
    _preview_signature(device, credential, generated_key, b"supported fallback")


def test_preview_sign_rejects_an_algorithm_list_without_a_supported_algorithm(device):
    with pytest.raises(CtapError) as error:
        _register_preview_key(device, ES256, algorithms=[-47, -257])

    assert error.value.code == CtapError.ERR.UNSUPPORTED_ALGORITHM


def test_preview_sign_repeated_signatures_verify(device, preview_sign_credential):
    credential, generated_key = preview_sign_credential
    public_key = ES256(cbor.decode(_bytes(generated_key["publicKey"])))

    for tbs in (b"first previewSign message", b"second previewSign message", b"\x00" * 128):
        signature = _preview_signature(device, credential, generated_key, tbs)
        public_key.verify(tbs, signature)


def test_preview_sign_signs_an_empty_tbs(device, preview_sign_credential):
    credential, generated_key = preview_sign_credential
    signature = _preview_signature(device, credential, generated_key, b"")

    ES256(cbor.decode(_bytes(generated_key["publicKey"]))).verify(b"", signature)


def test_preview_sign_rejects_unsupported_additional_args(device, preview_sign_credential):
    credential, generated_key = preview_sign_credential
    credential_id = credential.auth_data.credential_data.credential_id

    with pytest.raises(CtapError) as error:
        device.doGA(
            allow_list=[{"id": credential_id, "type": "public-key"}],
            extensions={
                "previewSign": {
                    "signByCredential": {
                        websafe_encode(credential_id): {
                            "keyHandle": generated_key["keyHandle"],
                            "tbs": b"unsupported additional arguments",
                            "additionalArgs": b"\x01",
                        },
                    },
                },
            },
        )

    assert error.value.code == CtapError.ERR.UNSUPPORTED_OPTION


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


def test_preview_sign_rejects_a_handle_bound_to_another_credential(device):
    credential_a, generated_key_a = _register_preview_key(device, ES256)
    credential_b, generated_key_b = _register_preview_key(device, ES256)
    credential_b_id = credential_b.auth_data.credential_data.credential_id

    with pytest.raises(CtapError) as error:
        device.doGA(
            allow_list=[{"id": credential_b_id, "type": "public-key"}],
            extensions={
                "previewSign": {
                    "signByCredential": {
                        websafe_encode(credential_b_id): {
                            "keyHandle": generated_key_a["keyHandle"],
                            "tbs": b"must not sign with credential B",
                        },
                    },
                },
            },
        )

    assert credential_a.auth_data.credential_data.credential_id != credential_b_id
    assert generated_key_a["keyHandle"] != generated_key_b["keyHandle"]
    assert error.value.code == CtapError.ERR.INVALID_CREDENTIAL


def test_preview_sign_signature_does_not_verify_with_another_generated_key(device):
    credential_a, generated_key_a = _register_preview_key(device, ES256)
    registration_b = device.MC(
        extensions={"previewSign": {3: [ES256.ALGORITHM], 4: 0}}
    )
    inner_b = AttestationResponse.from_dict(
        cbor.decode(registration_b["res"].unsigned_extension_outputs["previewSign"][7])
    )
    generated_key_b = inner_b.auth_data.credential_data.public_key
    tbs = b"signature must be bound to its generated key"
    signature = _preview_signature(device, credential_a, generated_key_a, tbs)

    with pytest.raises(InvalidSignature):
        ES256(generated_key_b).verify(tbs, signature)
