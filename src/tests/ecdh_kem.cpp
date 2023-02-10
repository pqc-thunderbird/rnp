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

/* TODOMTG: wrap all this with the ECDH KEM classes and test them instead */
TEST_F(rnp_tests, test_ecdh_kem_x25519)
{
    std::vector<uint8_t> pubkey_buf(32);
    std::vector<uint8_t> privkey_buf(32);

    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> plaintext2;

    botan_privkey_t botan_priv = NULL;
    botan_pubkey_t  botan_pub = NULL;

    /* Setup key */
    assert_int_equal(0, botan_privkey_create(&botan_priv, "Curve25519", "", global_ctx.rng.handle()));
    assert_int_equal(0, botan_privkey_export_pubkey(&botan_pub, botan_priv));
    assert_int_equal(0, botan_privkey_x25519_get_privkey(botan_priv, privkey_buf.data()));
    assert_int_equal(0, botan_pubkey_x25519_get_pubkey(botan_pub, pubkey_buf.data()));
    botan_privkey_destroy(botan_priv);
    botan_pubkey_destroy(botan_pub);

    /* kem encaps / decaps */
    assert_rnp_success(ecdh_kem_encaps(&global_ctx.rng, ciphertext, plaintext, pubkey_buf, PGP_CURVE_25519));
    assert_rnp_success(ecdh_kem_decaps(plaintext2, ciphertext, privkey_buf, PGP_CURVE_25519));

    /* both parties should have the same key share */
    assert_int_equal(plaintext.size(), plaintext2.size());
    assert_memory_equal(plaintext.data(), plaintext2.data(), plaintext.size());
}


TEST_F(rnp_tests, test_ecdh_kem_generic)
{
    std::vector<uint8_t> pubkey_buf;
    std::vector<uint8_t> privkey_buf;

    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> plaintext2;

    botan_privkey_t botan_priv = NULL;
    botan_pubkey_t  botan_pub = NULL;

    bignum_t *      px = NULL;
    bignum_t *      py = NULL;
    bignum_t *      x = NULL;

    pgp_curve_t curve_list[] = {PGP_CURVE_NIST_P_256, PGP_CURVE_NIST_P_384, PGP_CURVE_NIST_P_521, PGP_CURVE_BP256, PGP_CURVE_BP384, PGP_CURVE_BP512};

    for (auto curve : curve_list) {
        const ec_curve_desc_t *ec_desc = get_curve_desc(curve);
        const size_t curve_order = BITS_TO_BYTES(ec_desc->bitlen);

        /* initialize */
        pubkey_buf.resize(2 * curve_order + 1);
        privkey_buf.resize(curve_order);
        ciphertext.resize(curve_order);
        plaintext.resize(curve_order);
        plaintext2.resize(curve_order);

        /* Setup key */
        assert_int_equal(0, botan_privkey_create(&botan_priv, "ECDH", ec_desc->botan_name, global_ctx.rng.handle()));
        assert_int_equal(0, botan_privkey_export_pubkey(&botan_pub, botan_priv));

        px = bn_new();
        py = bn_new();
        x = bn_new();
        assert_int_equal(0, botan_pubkey_get_field(BN_HANDLE_PTR(px), botan_pub, "public_x"));
        assert_int_equal(0, botan_pubkey_get_field(BN_HANDLE_PTR(py), botan_pub, "public_y"));
        assert_int_equal(0, botan_privkey_get_field(BN_HANDLE_PTR(x), botan_priv, "x"));
        //assert_int_equal(curve_order, bn_num_bytes(*px));
        //assert_int_equal(curve_order, bn_num_bytes(*py));
        pubkey_buf.data()[0] = 0x04;

        /* if the px/py/x elements are less than curve order, we have to zero-pad them */
        size_t offset =  curve_order - bn_num_bytes(*px);
        if (offset) {
            memset(&pubkey_buf.data()[1], 0, offset);
        }
        bn_bn2bin(px, &pubkey_buf.data()[1 + offset]);
        offset =  curve_order - bn_num_bytes(*py);
        if (offset) {
            memset(&pubkey_buf.data()[1 + curve_order], 0, offset);
        }
        bn_bn2bin(py, &pubkey_buf.data()[1 + curve_order + offset]);

        offset =  curve_order - bn_num_bytes(*x);
        if (offset) {
            memset(privkey_buf.data(), 0, offset);
        }
        bn_bn2bin(x, privkey_buf.data() + offset);


        botan_privkey_destroy(botan_priv);
        botan_pubkey_destroy(botan_pub);
        bn_free(px);
        bn_free(py);
        bn_free(x);

        /* kem encaps / decaps */
        assert_rnp_success(ecdh_kem_encaps(&global_ctx.rng, ciphertext, plaintext, pubkey_buf, curve));
        assert_rnp_success(ecdh_kem_decaps(plaintext2, ciphertext, privkey_buf, curve));

        /* both parties should have the same key share */
        assert_int_equal(plaintext.size(), plaintext2.size());
        assert_memory_equal(plaintext.data(), plaintext2.data(), plaintext.size());
    }
}
