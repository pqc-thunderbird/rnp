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

#ifndef KYBER_ECC_COMPOSITE_H_
#define KYBER_ECC_COMPOSITE_H_

#include "config.h"
#include <rnp/rnp_def.h>
#include <vector>
#include <repgp/repgp_def.h>
#include "crypto/rng.h"
#include "crypto/kyber.h"
#include "crypto/kyber_common.h"
#include "crypto/ecdh.h"
#include <memory>

kyber_parameter_e pk_alg_to_kyber_id(pgp_pubkey_alg_t pk_alg);
pgp_curve_t pk_alg_to_curve_id(pgp_pubkey_alg_t pk_alg);


class pgp_kyber_ecc_composite_private_key_t {
  public:
    pgp_kyber_ecc_composite_private_key_t(const uint8_t *key_encoded, size_t key_encoded_len, pgp_pubkey_alg_t pk_alg);
    pgp_kyber_ecc_composite_private_key_t(std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t pk_alg);
    //pgp_kyber_ecc_composite_private_key_t(pgp_kyber_ecc_composite_private_key_t &other);
    pgp_kyber_ecc_composite_private_key_t& operator=(const pgp_kyber_ecc_composite_private_key_t &other);
    pgp_kyber_ecc_composite_private_key_t() = default;


    std::vector<uint8_t> decapsulate(const uint8_t *ciphertext, size_t ciphertext_len);

    std::vector<uint8_t>
    get_encoded()
    {
        return key_encoded_;
    };

    pgp_pubkey_alg_t pk_alg(pgp_pubkey_alg_t) const 
    {
      return pk_alg_;
    }

    static size_t encoded_size(pgp_pubkey_alg_t pk_alg);

  private:
    pgp_kyber_private_key_t kyber_key_from_encoded();
    std::vector<uint8_t> ecc_key_from_encoded();

    std::vector<uint8_t> key_encoded_;
    pgp_pubkey_alg_t pk_alg_;

    /* kyber part */
    pgp_kyber_private_key_t kyber_key;

    /* ecc part*/
    std::vector<uint8_t> ecc_key;
};


typedef struct pgp_kyber_ecc_encrypted_t {
    std::vector<uint8_t> ciphertext;
} pgp_kyber_ecc_encrypted_t;

class pgp_kyber_ecc_composite_public_key_t {
  public:
    pgp_kyber_ecc_composite_public_key_t(const uint8_t *key_encoded, size_t key_encoded_len, pgp_pubkey_alg_t pk_alg);
    pgp_kyber_ecc_composite_public_key_t(std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t pk_alg);
    //pgp_kyber_ecc_composite_public_key_t(pgp_kyber_ecc_composite_public_key_t &other);
    pgp_kyber_ecc_composite_public_key_t& operator=(const pgp_kyber_ecc_composite_public_key_t &other);
    pgp_kyber_ecc_composite_public_key_t() = default;

    pgp_kyber_ecc_encrypted_t encapsulate(const uint8_t * in, size_t in_len);

    std::vector<uint8_t>
    get_encoded()
    {
        return key_encoded_;
    };

    pgp_pubkey_alg_t pk_alg(pgp_pubkey_alg_t) const 
    {
      return pk_alg_;
    }

    static size_t encoded_size(pgp_pubkey_alg_t pk_alg);

  private:
    pgp_kyber_private_key_t kyber_key_from_encoded();
    std::vector<uint8_t> ecc_key_from_encoded();

    std::vector<uint8_t> key_encoded_;
    pgp_pubkey_alg_t pk_alg_;

    /* kyber part */
    pgp_kyber_private_key_t kyber_key;

    /* ecc part*/
    std::vector<uint8_t> ecc_key;
};


typedef struct pgp_kyber_ecc_key_t {
    pgp_kyber_ecc_composite_private_key_t priv;
    pgp_kyber_ecc_composite_public_key_t pub;
} pgp_kyber_ecc_key_t;

rnp_result_t kyber_ecc_gen_keypair(rnp::RNG *rng, pgp_kyber_ecc_key_t *key, pgp_pubkey_alg_t alg);

rnp_result_t kyber_ecc_validate_key(rnp::RNG *rng, const pgp_kyber_ecc_key_t *key, bool secret);

#endif
