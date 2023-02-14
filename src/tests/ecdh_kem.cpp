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


#include "rnp_tests.h"
#include "crypto/ecdh_kem.h"
#include "crypto/bn.h"

TEST_F(rnp_tests, test_ecdh_kem_direct)
{
    std::vector<uint8_t> pubkey_buf;
    std::vector<uint8_t> privkey_buf;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> plaintext2;

    pgp_curve_t curve_list[] = {PGP_CURVE_NIST_P_256, PGP_CURVE_NIST_P_384, PGP_CURVE_NIST_P_521, PGP_CURVE_BP256, PGP_CURVE_BP384, PGP_CURVE_BP512, PGP_CURVE_25519};

    for (auto curve : curve_list) {
        ecdh_kem_gen_keypair_sec1(&global_ctx.rng, privkey_buf, pubkey_buf, curve);

        /* kem encaps / decaps */
        assert_rnp_success(ecdh_kem_encaps(&global_ctx.rng, ciphertext, plaintext, pubkey_buf, curve));
        assert_rnp_success(ecdh_kem_decaps(plaintext2, ciphertext, privkey_buf, curve));

        /* both parties should have the same key share */
        assert_int_equal(plaintext.size(), plaintext2.size());
        assert_memory_equal(plaintext.data(), plaintext2.data(), plaintext.size());
    }
}

TEST_F(rnp_tests, test_ecdh_kem_class)
{
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> plaintext;
    ecdh_kem_key_t key_pair;
    pgp_curve_t curve_list[] = {PGP_CURVE_NIST_P_256, PGP_CURVE_NIST_P_384, PGP_CURVE_NIST_P_521, PGP_CURVE_BP256, PGP_CURVE_BP384, PGP_CURVE_BP512, PGP_CURVE_25519};

    for (auto curve : curve_list) {
        /* keygen */
        assert_rnp_success(generate_ecdh_kem_key_pair(&global_ctx.rng, &key_pair, curve));

        /* kem encaps / decaps */
        ecdh_kem_encap_result_t encap;
        assert_rnp_success(key_pair.pub.encapsulate(&global_ctx.rng, &encap));
        assert_rnp_success(key_pair.priv.decapsulate(encap.ciphertext, plaintext));

        /* both parties should have the same key share */
        assert_int_equal(plaintext.size(), encap.symmetric_key.size());
        assert_memory_equal(plaintext.data(), encap.symmetric_key.data(), plaintext.size());
    }
}