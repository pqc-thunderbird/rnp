/*
 * Copyright (c) 2023 MTG AG
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "x25519.h"
#include "ecdh.h"
#include "exdsa_ecdhkem.h"
#include "hkdf.hpp"
#include "botan/ffi.h"
#include "utils.h"

static void x25519_hkdf(std::vector<uint8_t> &derived_key, const std::vector<uint8_t> &shared_key) 
{
    /* The shared secret is passed to HKDF (see {{RFC5869}}) using SHA256, and the UTF-8-encoded string "OpenPGP X25519" as the info parameter. */
    const std::vector<uint8_t> info = {'O', 'p', 'e', 'n', 'P', 'G', 'P', ' ', 'X', '2', '5', '5', '1', '9'};
    auto kdf = rnp::Hkdf::create(PGP_HASH_SHA256);
    derived_key.resize(16); // 128-bit AES key wrap

    kdf->extract_expand(NULL, 0, // no salt
                       shared_key.data(),
                       shared_key.size(),
                       info.data(),
                       info.size(),
                       derived_key.data(),
                       derived_key.size());
}

rnp_result_t generate_x25519_native(rnp::RNG *           rng,
                                    std::vector<uint8_t> &privkey, 
                                    std::vector<uint8_t> &pubkey)
{
    const char *botan_name = "Curve25519";
    const pgp_curve_t curve = PGP_CURVE_25519;
    const ec_curve_desc_t *ec_desc = get_curve_desc(curve);
    const size_t curve_order = BITS_TO_BYTES(ec_desc->bitlen);
    botan_privkey_t botan_priv = NULL;
    botan_pubkey_t botan_pub = NULL;
    rnp_result_t ret = RNP_SUCCESS;

    privkey.resize(curve_order);
    pubkey.resize(curve_order);

    int botan_ret = botan_privkey_create(&botan_priv, botan_name, NULL, rng->handle());
    botan_ret |= botan_privkey_export_pubkey(&botan_pub, botan_priv);
    botan_ret |= botan_privkey_x25519_get_privkey(botan_priv, privkey.data());
    botan_ret |= botan_pubkey_x25519_get_pubkey(botan_pub, pubkey.data());
    if(botan_ret) {
        RNP_LOG("error when generating x25519 key");
        ret = RNP_ERROR_GENERIC;
    }
    if(!botan_pub || botan_pubkey_check_key(botan_pub, rng->handle(), 0)) { 
        RNP_LOG("No valid public key created");
        return RNP_ERROR_KEY_GENERATION;
    }
    
    botan_privkey_destroy(botan_priv);
    botan_pubkey_destroy(botan_pub);

    return ret;
}

rnp_result_t x25519_native_encrypt(rnp::RNG *                 rng,
                                   const std::vector<uint8_t> &pubkey, 
                                   const uint8_t *            in,
                                   size_t                     in_len,
                                   pgp_x25519_encrypted_t     *encrypted)
{
    rnp_result_t ret;
    std::vector<uint8_t> shared_key;
    std::vector<uint8_t> derived_key;

    if(!in_len || (in_len % 8) != 0) {
        RNP_LOG("incorrect size of in, AES key wrap requires a multiple of 8 bytes");
        return RNP_ERROR_BAD_FORMAT;
    }

    ret = ecdh_kem_encaps(rng, encrypted->eph_key, shared_key, pubkey, PGP_CURVE_25519);
    if(ret || encrypted->eph_key.size() != 32) {
        RNP_LOG("Error when doing X25519 key agreement");
        return RNP_ERROR_ENCRYPT_FAILED;
    }

    x25519_hkdf(derived_key, shared_key);

    /* The resulting key is used to encrypt the session key with AES-128 keywrap, defined in {{RFC3394}}. */
    size_t c_len = ((in_len + 7)/8 + 1) * 8; // RFC3394 "Outputs: Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}."
    encrypted->enc_sess_key.resize(c_len);

    if (botan_key_wrap3394(in, in_len, derived_key.data(), derived_key.size(), encrypted->enc_sess_key.data(), &c_len)) {
        RNP_LOG("error when doing AES key wrap");
        return RNP_ERROR_ENCRYPT_FAILED;
    }

    return RNP_SUCCESS;
}

rnp_result_t x25519_native_decrypt(rnp::RNG *                   rng,
                                   const std::vector<uint8_t>   &privkey,
                                   const pgp_x25519_encrypted_t *encrypted,
                                   uint8_t                      *decbuf,
                                   size_t                       *decbuf_len)
{
    rnp_result_t ret;
    std::vector<uint8_t> shared_key;
    std::vector<uint8_t> derived_key;

    if(encrypted->eph_key.size() != 32) {
        RNP_LOG("Wrong ephemeral public key size");
        return RNP_ERROR_BAD_FORMAT;
    }
    if(!encrypted->enc_sess_key.size()) {
        // TODO: could do a check for possible sizes
        RNP_LOG("No encrypted session key provided");
        return RNP_ERROR_BAD_FORMAT;
    }

    ret = ecdh_kem_decaps(rng, shared_key, encrypted->eph_key, privkey, PGP_CURVE_25519);
    if(ret) {
        RNP_LOG("Error when doing X25519 key agreement");
        return RNP_ERROR_ENCRYPT_FAILED;
    }

    x25519_hkdf(derived_key, shared_key);

    if (botan_key_unwrap3394(encrypted->enc_sess_key.data(), encrypted->enc_sess_key.size(), derived_key.data(), derived_key.size(), decbuf, decbuf_len)) {
        RNP_LOG("error when doing AES key unwrap");
        return RNP_ERROR_ENCRYPT_FAILED;
    }

    return RNP_SUCCESS;
}

rnp_result_t
x25519_validate_key_native(rnp::RNG *rng, const pgp_x25519_key_t *key, bool secret)
{
    botan_pubkey_t  bpkey = NULL;
    botan_privkey_t bskey = NULL;
    rnp_result_t    ret = RNP_ERROR_BAD_PARAMETERS;

    if (botan_pubkey_load_x25519(&bpkey, key->pub.data())) {
        goto done;
    }
    if (botan_pubkey_check_key(bpkey, rng->handle(), 0)) {
        goto done;
    }

    if (!secret) {
        ret = RNP_SUCCESS;
        goto done;
    }
    if(botan_privkey_load_x25519(&bskey, key->priv.data())){
        goto done;
    }
    if (botan_privkey_check_key(bskey, rng->handle(), 0)) {
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    botan_privkey_destroy(bskey);
    botan_pubkey_destroy(bpkey);
    return ret;
}