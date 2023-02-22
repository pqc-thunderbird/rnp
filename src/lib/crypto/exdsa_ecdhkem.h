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

struct ecdh_kem_key_t; /* forward declaration */
struct exdsa_key_t; /* forward declaration */

class ec_key_t {

public:
    virtual ~ec_key_t() = 0;
    ec_key_t(uint8_t *key_buf, size_t key_buf_len, pgp_curve_t curve);
    ec_key_t(std::vector<uint8_t> key_buf, pgp_curve_t curve);
    ec_key_t() = default;

    static rnp_result_t generate_ecdh_kem_key_pair(rnp::RNG *rng, ecdh_kem_key_t *out, pgp_curve_t curve);
    static rnp_result_t generate_exdsa_key_pair(rnp::RNG *rng, exdsa_key_t *out, pgp_curve_t curve);

    std::vector<uint8_t> get_encoded() const
    {
        return key_;
    }

    pgp_curve_t get_curve() const 
    {
        return curve_;
    }

protected:
    std::vector<uint8_t> key_; // sec1 encoding
    pgp_curve_t curve_;
};

struct ecdh_kem_encap_result_t {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> symmetric_key;
};

struct exdsa_signature_t {
    std::vector<uint8_t> signature;
};

class ecdh_kem_public_key_t : public ec_key_t {

public:
    ecdh_kem_public_key_t(uint8_t *key_buf, size_t key_buf_len, pgp_curve_t curve);
    ecdh_kem_public_key_t(std::vector<uint8_t> key_buf, pgp_curve_t curve);
    ecdh_kem_public_key_t() = default;

    rnp_result_t encapsulate(rnp::RNG *rng, ecdh_kem_encap_result_t *result);
};


class ecdh_kem_private_key_t : public ec_key_t {

public:
    ecdh_kem_private_key_t(uint8_t *key_buf, size_t key_buf_len, pgp_curve_t curve);
    ecdh_kem_private_key_t(std::vector<uint8_t> key_buf, pgp_curve_t curve);
    ecdh_kem_private_key_t() = default;
    
    rnp_result_t decapsulate(const std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &plaintext);
};

typedef struct ecdh_kem_key_t {
    ecdh_kem_private_key_t priv;
    ecdh_kem_public_key_t pub;
} ecdh_kem_key_t;


class exdsa_public_key_t : public ec_key_t {

public:
    exdsa_public_key_t(uint8_t *key_buf, size_t key_buf_len, pgp_curve_t curve);
    exdsa_public_key_t(std::vector<uint8_t> key_buf, pgp_curve_t curve);
    exdsa_public_key_t() = default;

    rnp_result_t verify(const exdsa_signature_t &sig);
};

class exdsa_private_key_t : public ec_key_t {

public:
    exdsa_private_key_t(uint8_t *key_buf, size_t key_buf_len, pgp_curve_t curve);
    exdsa_private_key_t(std::vector<uint8_t> key_buf, pgp_curve_t curve);
    exdsa_private_key_t() = default;

    rnp_result_t sign(exdsa_signature_t &sig_out, std::vector<uint8_t> msg);
};

typedef struct exdsa_key_t {
    exdsa_private_key_t priv;
    exdsa_public_key_t pub;
} exdsa_key_t;



#endif