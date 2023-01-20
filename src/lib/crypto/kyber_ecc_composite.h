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
#include "crypto/ecdh.h"

kyber_parameter_e pk_alg_to_kyber_id(pgp_pubkey_alg_t pk_alg);
pgp_curve_t pk_alg_to_curve_id(pgp_pubkey_alg_t pk_alg);



struct kem_kyber_ecc_composite_result_t {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> symmetric_key;
};

/* 
    const pgp_ecdh_encrypted_t *in,
    const pgp_ec_key_t *        key,
*/

/*
  Botan KDF: 
    SP800-56C

    KDF from NIST SP 800-56C.

    Available if BOTAN_HAS_SP800_56C is defined.

*/

// go: https://github.com/ProtonMail/go-crypto/pull/135/files 
  // has kdf etc

  // also https://github.com/openpgpjs/openpgpjs/tree/v6 ?
  // https://github.com/twiss/openpgpjs/tree/v5-direct-key-sigs


  /* MB = KMAC256(domSeparation, encKeyShares, oBits, customizationString) 
  
    Botan:
    SP800_56C::kdf(uint8_t key[], size_t key_len,
                    const uint8_t secret[], size_t secret_len,
                    const uint8_t salt[], size_t salt_len,
                    const uint8_t label[], size_t label_len) const

    salt: domSeparation
    secret: encKeyShares = counter || eccKeyShare || kyberKeyShare || fixedInfo
    key_len: oBits (key=outBuf)
    label: "KDF"
  */




class pgp_kyber_ecc_composite_private_key_t {
  public:
    pgp_kyber_ecc_composite_private_key_t(const uint8_t *key_encoded, size_t key_encoded_len, pgp_pubkey_alg_t pk_alg);
    pgp_kyber_ecc_composite_private_key_t(std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t pk_alg);

    std::vector<uint8_t> decapsulate(const uint8_t *ciphertext, size_t ciphertext_len);
    std::vector<uint8_t>
    get_encoded()
    {
        // TODO encode kyber + encode ecc
        return std::vector<uint8_t>();
    };

  private:
    pgp_pubkey_alg_t pk_alg_;

    /* ecc part*/
    pgp_ec_key_t ecc_priv;

    /* kyber part */
    pgp_kyber_private_key_t keyber_priv;

};

class pgp_kyber_ecc_composite_public_key_t {
  // TODO
};


#endif
