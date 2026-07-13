/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "picokeys.h"
#include "preview_sign.h"
#include "credential.h"
#include "ctap.h"
#include "ctap2_cbor.h"
#include "fido.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "random.h"

#define PREVIEW_SIGN_MAC_LEN 32
#define PREVIEW_SIGN_AUX_LEN 32

static int valid_flags(uint64_t flags) {
    return flags == PREVIEW_SIGN_FLAG_UNATTENDED || flags == PREVIEW_SIGN_FLAG_REQUIRE_UP || flags == PREVIEW_SIGN_FLAG_REQUIRE_UV;
}

/* Derive p from the credential-specific secret and all kh parameters. */
static int derive_preview_sign_key(const uint8_t *credential_seed, size_t credential_seed_len, int64_t alg, const uint8_t *params, size_t params_len, mbedtls_ecp_keypair *key) {
    uint8_t credential_key[64] = {0};
    uint8_t path[32] = {0};
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = CTAP2_ERR_PROCESSING;

    if (credential_derive_hmac_key(credential_seed, credential_seed_len, credential_key) != 0) {
        goto err;
    }
    if (mbedtls_md_hmac(md, credential_key, 32, (const uint8_t *) "previewSign key", 15, path) != 0) {
        goto err;
    }
    if (mbedtls_md_hmac(md, path, sizeof(path), params, params_len, path) != 0) {
        goto err;
    }
    int curve = FIDO2_CURVE_P256;
    if (alg == FIDO2_ALG_ES384 || alg == FIDO2_ALG_ESP384) {
        curve = FIDO2_CURVE_P384;
    }
    else if (alg == FIDO2_ALG_ES512 || alg == FIDO2_ALG_ESP512) {
        curve = FIDO2_CURVE_P521;
    }
#if defined(MBEDTLS_EDDSA_C)
    else if (alg == FIDO2_ALG_EDDSA) {
        curve = FIDO2_CURVE_ED25519;
    }
#endif
    ret = fido_load_key(curve, path, key) == 0 ? 0 : CTAP2_ERR_PROCESSING;
err:
    mbedtls_platform_zeroize(credential_key, sizeof(credential_key));
    mbedtls_platform_zeroize(path, sizeof(path));
    return ret;
}

static int mac_handle(const uint8_t *credential_seed, size_t credential_seed_len, const uint8_t rp_id_hash[32], const uint8_t *params, size_t params_len, uint8_t mac[PREVIEW_SIGN_MAC_LEN]) {
    uint8_t key[64] = {0};
    uint8_t *message = NULL;
    const size_t name_len = sizeof(PREVIEW_SIGN_NAME) - 1;
    int ret = CTAP2_ERR_PROCESSING;

    if (credential_derive_hmac_key(credential_seed, credential_seed_len, key) != 0) {
        goto err;
    }
    message = calloc(1, params_len + name_len + 32);
    if (!message) {
        goto err;
    }
    memcpy(message, params, params_len);
    memcpy(message + params_len, PREVIEW_SIGN_NAME, name_len);
    memcpy(message + params_len + name_len, rp_id_hash, 32);
    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32, message, params_len + name_len + 32, mac) == 0) {
        ret = 0;
    }
err:
    if (message) {
        mbedtls_platform_zeroize(message, params_len + name_len + 32);
        free(message);
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    return ret;
}

static int load_params(const uint8_t *params, size_t params_len, int64_t *alg, preview_sign_flags_t *flags, uint8_t aux[PREVIEW_SIGN_AUX_LEN]) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    int64_t alg_val = 0;
    uint64_t flags_val = 0;
    CborByteString encoded_aux = {0};

    CBOR_CHECK(cbor_parser_init(params, params_len, 0, &parser, &map));
    size_t item = 0;
    CBOR_PARSE_ARRAY_START(map, 1)
    {
        if (item == 0) {
            CBOR_FIELD_GET_INT(alg_val, 1);
        }
        else if (item == 1) {
            CBOR_FIELD_GET_UINT(flags_val, 1);
        }
        else if (item == 2) {
            CBOR_FIELD_GET_BYTES(encoded_aux, 1);
        }
        else {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        item++;
    }
    CBOR_PARSE_ARRAY_END(map, 1);
    if (item != 3) {
        CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
    }
    if (alg_val != FIDO2_ALG_ES256
        && alg_val != FIDO2_ALG_ESP256
        && alg_val != FIDO2_ALG_ES384
        && alg_val != FIDO2_ALG_ESP384
        && alg_val != FIDO2_ALG_ES512
        && alg_val != FIDO2_ALG_ESP512
#ifdef MBEDTLS_EDDSA_C
        && alg_val != FIDO2_ALG_EDDSA
#endif
    ) {
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_ALGORITHM);
    }
    if (!valid_flags(flags_val)) {
        CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
    }
    if (encoded_aux.len != PREVIEW_SIGN_AUX_LEN) {
        CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
    }
    if (alg) {
        *alg = alg_val;
    }
    if (flags) {
        *flags = (preview_sign_flags_t) flags_val;
    }
    memcpy(aux, encoded_aux.data, PREVIEW_SIGN_AUX_LEN);
err:
    CBOR_FREE_BYTE_STRING(encoded_aux);
    return error;
}

int preview_sign_create(const uint8_t *credential_seed, size_t credential_seed_len, const uint8_t rp_id_hash[32], int64_t alg, preview_sign_flags_t flags, uint8_t **handle, size_t *handle_len, mbedtls_ecp_keypair *key) {
    if (!handle || !handle_len || !key) {
        return CTAP2_ERR_INVALID_OPTION;
    }
    uint8_t aux[PREVIEW_SIGN_AUX_LEN] = {0};
    uint8_t params[64] = {0}, mac[PREVIEW_SIGN_MAC_LEN] = {0};
    CborEncoder encoder, array;
    CborError error = CborNoError;
    size_t params_len;
    int ret = CTAP2_ERR_PROCESSING;

    *handle = NULL;
    *handle_len = 0;
    if (!valid_flags(flags) || random_fill_buffer(aux, sizeof(aux)) != PICOKEYS_OK) {
        return CTAP2_ERR_INVALID_OPTION;
    }
    cbor_encoder_init(&encoder, params, sizeof(params), 0);
    CBOR_CHECK(cbor_encoder_create_array(&encoder, &array, 3));
    CBOR_CHECK(cbor_encode_int(&array, alg));
    CBOR_CHECK(cbor_encode_uint(&array, flags));
    CBOR_CHECK(cbor_encode_byte_string(&array, aux, sizeof(aux)));
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &array));

    params_len = cbor_encoder_get_buffer_size(&encoder, params);
    if (mac_handle(credential_seed, credential_seed_len, rp_id_hash, params, params_len, mac) != 0) {
        goto err;
    }
    *handle = calloc(1, PREVIEW_SIGN_MAC_LEN + params_len);
    if (!*handle) {
        goto err;
    }
    memcpy(*handle, mac, PREVIEW_SIGN_MAC_LEN);
    memcpy(*handle + PREVIEW_SIGN_MAC_LEN, params, params_len);
    *handle_len = PREVIEW_SIGN_MAC_LEN + params_len;
    if (derive_preview_sign_key(credential_seed, credential_seed_len, alg, params, params_len, key) != 0) {
        free(*handle);
        *handle = NULL;
        *handle_len = 0;
        goto err;
    }
    ret = 0;
err:
    mbedtls_platform_zeroize(aux, sizeof(aux));
    mbedtls_platform_zeroize(mac, sizeof(mac));
    return ret;
}

int preview_sign_load(const uint8_t *credential_seed, size_t credential_seed_len, const uint8_t rp_id_hash[32], const uint8_t *handle, size_t handle_len, int64_t *alg, preview_sign_flags_t *flags, mbedtls_ecp_keypair *key) {
    uint8_t expected_mac[PREVIEW_SIGN_MAC_LEN] = {0};
    uint8_t aux[PREVIEW_SIGN_AUX_LEN] = {0};
    const uint8_t *params;
    size_t params_len;
    int ret;

    if (handle_len <= PREVIEW_SIGN_MAC_LEN) {
        return CTAP2_ERR_INVALID_CREDENTIAL;
    }
    params = handle + PREVIEW_SIGN_MAC_LEN;
    params_len = handle_len - PREVIEW_SIGN_MAC_LEN;
    if (mac_handle(credential_seed, credential_seed_len, rp_id_hash, params, params_len, expected_mac) != 0 || mbedtls_ct_memcmp(handle, expected_mac, PREVIEW_SIGN_MAC_LEN) != 0) {
        ret = CTAP2_ERR_INVALID_CREDENTIAL;
        goto err;
    }
    if ((ret = load_params(params, params_len, alg, flags, aux)) != 0) {
        goto err;
    }
    ret = derive_preview_sign_key(credential_seed, credential_seed_len, *alg, params, params_len, key);
err:
    mbedtls_platform_zeroize(expected_mac, sizeof(expected_mac));
    mbedtls_platform_zeroize(aux, sizeof(aux));
    return ret;
}

int preview_sign_attestation(const uint8_t rp_id_hash[32], int64_t sign_alg, uint8_t outer_flags, const uint8_t *client_data_hash, size_t client_data_hash_len, const uint8_t *kh, size_t kh_len, preview_sign_flags_t sign_flags, mbedtls_ecp_keypair *key, uint8_t **att_obj, size_t *att_obj_len) {
    uint8_t cose[256] = {0}, extensions[64] = {0};
    uint8_t hash[64] = {0}, signature[MBEDTLS_ECDSA_MAX_LEN] = {0};
    uint8_t *auth_data = NULL, *signed_data = NULL, *out = NULL;
    size_t cose_len, extensions_len, auth_data_len, signature_len = 0, out_len;
    CborEncoder encoder, map, inner;
    CborError error = CborNoError;
    int ret = CTAP2_ERR_PROCESSING;

    *att_obj = NULL;
    *att_obj_len = 0;
    cbor_encoder_init(&encoder, cose, sizeof(cose), 0);
    CBOR_CHECK(COSE_key(key, &encoder, &map));
    cose_len = cbor_encoder_get_buffer_size(&encoder, cose);

    cbor_encoder_init(&encoder, extensions, sizeof(extensions), 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &map, 1));
    CBOR_CHECK(cbor_encode_text_stringz(&map, PREVIEW_SIGN_NAME));
    CBOR_CHECK(cbor_encoder_create_map(&map, &inner, 1));
    CBOR_CHECK(cbor_encode_uint(&inner, 4));
    CBOR_CHECK(cbor_encode_uint(&inner, sign_flags));
    CBOR_CHECK(cbor_encoder_close_container(&map, &inner));
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &map));

    extensions_len = cbor_encoder_get_buffer_size(&encoder, extensions);
    auth_data_len = 32 + 1 + 4 + 16 + 2 + kh_len + cose_len + extensions_len;
    auth_data = calloc(1, auth_data_len);
    signed_data = calloc(1, auth_data_len + client_data_hash_len);
    if (!auth_data || !signed_data) {
        goto err;
    }
    uint8_t *p = auth_data;
    memcpy(p, rp_id_hash, 32); p += 32;
    *p++ = outer_flags | FIDO2_AUT_FLAG_AT | FIDO2_AUT_FLAG_ED;
    p += put_uint32_be(0, p);
    memcpy(p, aaguid, sizeof(aaguid)); p += sizeof(aaguid);
    p += put_uint16_be((uint16_t)kh_len, p);
    memcpy(p, kh, kh_len); p += kh_len;
    memcpy(p, cose, cose_len); p += cose_len;
    memcpy(p, extensions, extensions_len);

    memcpy(signed_data, auth_data, auth_data_len);
    memcpy(signed_data + auth_data_len, client_data_hash, client_data_hash_len);

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (key->grp.id == MBEDTLS_ECP_DP_SECP384R1) {
        md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_SECP521R1) {
        md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    }
#ifdef MBEDTLS_EDDSA_C
    else if (key->grp.id == MBEDTLS_ECP_DP_ED25519) {
        md = NULL;
    }
#endif
    if (md != NULL) {
        ret = mbedtls_md(md, signed_data, auth_data_len + client_data_hash_len, hash);
        if (ret != 0) {
            goto err;
        }
        ret = mbedtls_ecdsa_write_signature(key, mbedtls_md_get_type(md), hash, mbedtls_md_get_size(md), signature, sizeof(signature), &signature_len, random_fill_iterator, NULL);
    }
#ifdef MBEDTLS_EDDSA_C
    else {
        ret = mbedtls_eddsa_write_signature(key, signed_data, auth_data_len + client_data_hash_len, signature, sizeof(signature), &signature_len, MBEDTLS_EDDSA_PURE, NULL, 0, random_fill_iterator, NULL);
    }
#endif
    if (ret != 0) {
        goto err;
    }

    out = calloc(1, CTAP_MAX_CBOR_PAYLOAD);
    if (!out) {
        goto err;
    }
    cbor_encoder_init(&encoder, out, CTAP_MAX_CBOR_PAYLOAD, 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &map, 3));
    CBOR_CHECK(cbor_encode_uint(&map, 1));
    CBOR_CHECK(cbor_encode_text_stringz(&map, "packed"));
    CBOR_CHECK(cbor_encode_uint(&map, 2));
    CBOR_CHECK(cbor_encode_byte_string(&map, auth_data, auth_data_len));
    CBOR_CHECK(cbor_encode_uint(&map, 3));
    CBOR_CHECK(cbor_encoder_create_map(&map, &inner, 2));
    CBOR_CHECK(cbor_encode_text_stringz(&inner, "alg"));
    CBOR_CHECK(cbor_encode_int(&inner, sign_alg));
    CBOR_CHECK(cbor_encode_text_stringz(&inner, "sig"));
    CBOR_CHECK(cbor_encode_byte_string(&inner, signature, signature_len));
    CBOR_CHECK(cbor_encoder_close_container(&map, &inner));
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &map));

    out_len = cbor_encoder_get_buffer_size(&encoder, out);
    *att_obj = out;
    *att_obj_len = out_len;
    out = NULL;
    ret = 0;
err:
    mbedtls_platform_zeroize(hash, sizeof(hash));
    mbedtls_platform_zeroize(signature, sizeof(signature));
    if (auth_data) {
        mbedtls_platform_zeroize(auth_data, auth_data_len);
        free(auth_data);
    }
    if (signed_data) {
        mbedtls_platform_zeroize(signed_data, auth_data_len + client_data_hash_len);
        free(signed_data);
    }
    if (out) {
        free(out);
    }
    return ret;
}
