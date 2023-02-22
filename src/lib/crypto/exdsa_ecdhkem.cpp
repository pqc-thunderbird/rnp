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

#include "exdsa_ecdhkem.h"
#include "ecdh.h"
#include "ec.h"
#include "types.h"
#include "logging.h"
#include "string.h"

ec_key_t::~ec_key_t() {}

ec_key_t::ec_key_t(uint8_t *key_buf, size_t key_buf_len, pgp_curve_t curve)
    : key_(std::vector<uint8_t>(key_buf, key_buf + key_buf_len)),
      curve_(curve)
{
    /* TODOMTG validate */
}

ec_key_t::ec_key_t(std::vector<uint8_t> key, pgp_curve_t curve)
    : key_(key),
      curve_(curve)
{
    /* TODOMTG validate */
}

ecdh_kem_public_key_t::ecdh_kem_public_key_t(uint8_t *key_buf, size_t key_buf_len, pgp_curve_t curve)
    : ec_key_t(key_buf, key_buf_len, curve)
{}
ecdh_kem_public_key_t::ecdh_kem_public_key_t(std::vector<uint8_t> key, pgp_curve_t curve)
    : ec_key_t(key, curve)
{}

ecdh_kem_private_key_t::ecdh_kem_private_key_t(uint8_t *key_buf, size_t key_buf_len, pgp_curve_t curve)
    : ec_key_t(key_buf, key_buf_len, curve)
{}
ecdh_kem_private_key_t::ecdh_kem_private_key_t(std::vector<uint8_t> key, pgp_curve_t curve)
    : ec_key_t(key, curve)
{}


rnp_result_t
ecdh_kem_public_key_t::encapsulate(rnp::RNG *rng, ecdh_kem_encap_result_t *result) {
    return ecdh_kem_encaps(rng, result->ciphertext, result->symmetric_key, key_, curve_);
}

rnp_result_t
ecdh_kem_private_key_t::decapsulate(const std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &plaintext) 
{
    return ecdh_kem_decaps(plaintext, ciphertext, key_, curve_);
}

rnp_result_t 
ec_key_t::generate_ecdh_kem_key_pair(rnp::RNG *rng, ecdh_kem_key_t *out, pgp_curve_t curve) 
{
    std::vector<uint8_t> pub, priv;
    rnp_result_t result = ecdh_kem_gen_keypair_sec1(rng, priv, pub, curve);
    if(result != RNP_SUCCESS) {
        RNP_LOG("error when generating EC key pair");
        return result;
    }
    
    out->priv = ecdh_kem_private_key_t(priv, curve);
    out->pub = ecdh_kem_public_key_t(pub, curve);

    return RNP_SUCCESS;
}




exdsa_public_key_t::exdsa_public_key_t(uint8_t *key_buf, size_t key_buf_len, pgp_curve_t curve)
    : ec_key_t(key_buf, key_buf_len, curve)
{}
exdsa_public_key_t::exdsa_public_key_t(std::vector<uint8_t> key, pgp_curve_t curve)
    : ec_key_t(key, curve)
{}

exdsa_private_key_t::exdsa_private_key_t(uint8_t *key_buf, size_t key_buf_len, pgp_curve_t curve)
    : ec_key_t(key_buf, key_buf_len, curve)
{}
exdsa_private_key_t::exdsa_private_key_t(std::vector<uint8_t> key, pgp_curve_t curve)
    : ec_key_t(key, curve)
{}


rnp_result_t 
ec_key_t::generate_exdsa_key_pair(rnp::RNG *rng, exdsa_key_t *out, pgp_curve_t curve) 
{
    std::vector<uint8_t> pub, priv;
    rnp_result_t result = exdsa_gen_keypair_sec1(rng, priv, pub, curve);
    if(result != RNP_SUCCESS) {
        RNP_LOG("error when generating EC key pair");
        return result;
    }
    
    out->priv = exdsa_private_key_t(priv, curve);
    out->pub = exdsa_public_key_t(pub, curve);

    return RNP_SUCCESS;
}
