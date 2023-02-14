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
#ifndef ECDH_KEM_H_
#define ECDH_KEM_H_

#include "config.h"
#include <rnp/rnp_def.h>
#include <vector>
#include <repgp/repgp_def.h>
#include "crypto/rng.h"
#include <memory>

struct ecdh_kem_encap_result_t {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> symmetric_key;
};


class ecdh_kem_public_key_t {

public:
    ecdh_kem_public_key_t(uint8_t *pubkey_buf, size_t pubkey_buf_len, pgp_curve_t curve);
    ecdh_kem_public_key_t(std::vector<uint8_t> pubkey_buf, pgp_curve_t curve);
    ecdh_kem_public_key_t() = default;
    std::vector<uint8_t> get_encoded() const
    {
        return key;
    }

    pgp_curve_t get_curve() const 
    {
        return curve;
    }
    
    rnp_result_t encapsulate(rnp::RNG *rng, ecdh_kem_encap_result_t *result);

private:
    std::vector<uint8_t> key; // sec1 encoding
    pgp_curve_t curve;
};


class ecdh_kem_private_key_t {

public:
    ecdh_kem_private_key_t(uint8_t *privkey_buf, size_t privkey_buf_len, pgp_curve_t curve);
    ecdh_kem_private_key_t(std::vector<uint8_t> privkey_buf, pgp_curve_t curve);
    ecdh_kem_private_key_t() = default;
    std::vector<uint8_t> get_encoded() const
    {
        return key;
    }

    pgp_curve_t get_curve() const 
    {
        return curve;
    }

    rnp_result_t decapsulate(const std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &plaintext);

private:
    std::vector<uint8_t> key; // sec1 encoding
    pgp_curve_t curve;
};

typedef struct ecdh_kem_key_t {
    ecdh_kem_private_key_t priv;
    ecdh_kem_public_key_t pub;
} ecdh_kem_key_t;

rnp_result_t generate_ecdh_kem_key_pair(rnp::RNG *rng, ecdh_kem_key_t *out, pgp_curve_t curve);

#endif