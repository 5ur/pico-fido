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

#ifndef _PREVIEW_SIGN_H_
#define _PREVIEW_SIGN_H_

#include <stddef.h>
#include <stdint.h>
#include "mbedtls/ecp.h"

#define PREVIEW_SIGN_NAME "previewSign"

typedef enum {
    PREVIEW_SIGN_FLAG_UNATTENDED = 0x00,
    PREVIEW_SIGN_FLAG_REQUIRE_UP = 0x01,
    PREVIEW_SIGN_FLAG_REQUIRE_UV = 0x05
} preview_sign_flags_t;

int preview_sign_create(const uint8_t *credential_seed, size_t credential_seed_len, const uint8_t rp_id_hash[32], int64_t alg, preview_sign_flags_t flags, uint8_t **handle, size_t *handle_len, mbedtls_ecp_keypair *key);
int preview_sign_load(const uint8_t *credential_seed, size_t credential_seed_len, const uint8_t rp_id_hash[32], const uint8_t *handle, size_t handle_len, int64_t *alg, preview_sign_flags_t *flags, mbedtls_ecp_keypair *key);
int preview_sign_attestation(const uint8_t rp_id_hash[32], int64_t sign_alg, uint8_t outer_flags, const uint8_t *client_data_hash, size_t client_data_hash_len, const uint8_t *kh, size_t kh_len, preview_sign_flags_t sign_flags, mbedtls_ecp_keypair *key, uint8_t **att_obj, size_t *att_obj_len);

#endif // _PREVIEW_SIGN_H_
