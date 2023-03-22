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
#include "crypto/exdsa_ecdhkem.h"
#include "crypto/bn.h"

#if defined(ENABLE_CRYPTO_REFRESH)

TEST_F(rnp_tests, test_ecdh_kem_direct)
{
    std::vector<uint8_t> pubkey_buf;
    std::vector<uint8_t> privkey_buf;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> plaintext2;

    pgp_curve_t curve_list[] = {PGP_CURVE_NIST_P_256, PGP_CURVE_NIST_P_384, PGP_CURVE_NIST_P_521, PGP_CURVE_BP256, PGP_CURVE_BP384, PGP_CURVE_BP512, PGP_CURVE_25519};

    for (auto curve : curve_list) {
        ecdh_kem_gen_keypair_native(&global_ctx.rng, privkey_buf, pubkey_buf, curve);

        /* kem encaps / decaps */
        assert_rnp_success(ecdh_kem_encaps(&global_ctx.rng, ciphertext, plaintext, pubkey_buf, curve));
        assert_rnp_success(ecdh_kem_decaps(&global_ctx.rng, plaintext2, ciphertext, privkey_buf, curve));

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
        assert_rnp_success(ec_key_t::generate_ecdh_kem_key_pair(&global_ctx.rng, &key_pair, curve));

        /* kem encaps / decaps */
        ecdh_kem_encap_result_t encap;
        assert_rnp_success(key_pair.pub.encapsulate(&global_ctx.rng, &encap));
        assert_rnp_success(key_pair.priv.decapsulate(&global_ctx.rng, encap.ciphertext, plaintext));

        /* both parties should have the same key share */
        assert_int_equal(plaintext.size(), encap.symmetric_key.size());
        assert_memory_equal(plaintext.data(), encap.symmetric_key.data(), plaintext.size());

        /* test invalid ciphertext */
        encap.ciphertext.data()[4] += 1;
        if(curve != PGP_CURVE_25519) {
            assert_throw(key_pair.priv.decapsulate(&global_ctx.rng, encap.ciphertext, plaintext));
        }
    }
}

TEST_F(rnp_tests, test_exdsa)
{
    pgp_hash_alg_t hash_alg = PGP_HASH_SHA256;
    std::vector<uint8_t> msg(32);
    exdsa_key_t key_pair;
    pgp_curve_t curve_list[] = {PGP_CURVE_NIST_P_256, PGP_CURVE_NIST_P_384, PGP_CURVE_NIST_P_521, PGP_CURVE_BP256, PGP_CURVE_BP384, PGP_CURVE_BP512, PGP_CURVE_ED25519};
    //pgp_curve_t curve_list[] = {PGP_CURVE_ED25519};

    for (auto curve : curve_list) {
        /* keygen */
        assert_rnp_success(ec_key_t::generate_exdsa_key_pair(&global_ctx.rng, &key_pair, curve));
        
        /* sign and verify */
        std::vector<uint8_t> sig;
        assert_rnp_success(key_pair.priv.sign(&global_ctx.rng, sig, msg.data(), msg.size(), hash_alg));
        assert_rnp_success(key_pair.pub.verify(sig, msg.data(), msg.size(), hash_alg));

        /* test invalid msg / hash */
        msg.data()[4] -= 1;
        assert_rnp_failure(key_pair.pub.verify(sig, msg.data(), msg.size(), hash_alg));

        /* test invalid sig */
        msg.data()[4] += 1;
        sig.data()[4] -= 1;
        assert_rnp_failure(key_pair.pub.verify(sig, msg.data(), msg.size(), hash_alg));
    }
}

#endif