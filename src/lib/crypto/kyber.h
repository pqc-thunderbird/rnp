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

#ifndef KYBER_H_
#define KYBER_H_

#include "config.h"
#include <rnp/rnp_def.h>
#include <vector>
#include <repgp/repgp_def.h>
#include "crypto/rng.h"

enum kyber_parameter_e { kyber_768, kyber_1024 };

struct kem_encap_result_t {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> symmetric_key;
};

class pgp_kyber_private_key_t {
  public:
    pgp_kyber_private_key_t(const uint8_t *key_encoded, size_t key_encoded_len, kyber_parameter_e mode);
    pgp_kyber_private_key_t(std::vector<uint8_t> const &key_encoded, kyber_parameter_e mode);
    pgp_kyber_private_key_t() = default;

    std::vector<uint8_t> decapsulate(const uint8_t *ciphertext, size_t ciphertext_len);
    std::vector<uint8_t>
    get_encoded()
    {
        return key_encoded_;
    };

  private:
    // TODOMTG: BETTER USE SECUREVECTOR HERE IN A BOTAN-SPECIFIC IMPLEMENTATIONS. OTHER RNP
    // OBJECTS DO NOT SUPPORT ANY SECURE-MEMORY TECHNIQUE
    std::vector<uint8_t> key_encoded_;
    kyber_parameter_e kyber_mode_;
};

class pgp_kyber_public_key_t {
  public:
    pgp_kyber_public_key_t(const uint8_t *key_encoded, size_t key_encoded_len, kyber_parameter_e mode);
    pgp_kyber_public_key_t(std::vector<uint8_t> const &key_encoded, kyber_parameter_e mode);
    pgp_kyber_public_key_t() = default;
    kem_encap_result_t encapsulate();

    std::vector<uint8_t>
    get_encoded()
    {
        return key_encoded_;
    };

  private:
    std::vector<uint8_t> key_encoded_;
    kyber_parameter_e kyber_mode_;
};
// TODOMTG: should provide RNG as parameter. But how to get the Botan rng in this case from the
// ffi-type rng object? (defined in botan/src/lib/ffi/ffi_rng.h)
std::pair<pgp_kyber_public_key_t, pgp_kyber_private_key_t> kyber_generate_keypair(
  /*rnp::RNG *rng,*/ kyber_parameter_e kyber_param);

#endif
