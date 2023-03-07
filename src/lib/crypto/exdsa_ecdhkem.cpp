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
#include "utils.h"
#include <botan/pubkey.h>
#include <botan/ecdsa.h>
#include <botan/ed25519.h>
#include <botan/system_rng.h>

// TODO: remove when ffi is removed
#include <botan/ffi.h>


ec_key_t::~ec_key_t() {}

ec_key_t::ec_key_t(uint8_t *key_buf, size_t key_buf_len, pgp_curve_t curve)
    : key_(std::vector<uint8_t>(key_buf, key_buf + key_buf_len)),
      curve_(curve)
{}

ec_key_t::ec_key_t(std::vector<uint8_t> key, pgp_curve_t curve)
    : key_(key),
      curve_(curve)
{}

bool ec_key_t::is_edwards_curve(pgp_curve_t curve) {
    switch(curve) {
        case PGP_CURVE_25519: [[fallthrough]];
        case PGP_CURVE_ED25519:
            return true;
        default: 
            return false;
    }
}

/* TODOMTG: de-duplicate this */
const char *
ec_key_t::ecdsa_padding_str_for(pgp_hash_alg_t hash_alg)
{
    switch (hash_alg) {
        case PGP_HASH_MD5:
            return "Raw(MD5)";
        case PGP_HASH_SHA1:
            return "Raw(SHA-1)";
        case PGP_HASH_RIPEMD:
            return "Raw(RIPEMD-160)";

        case PGP_HASH_SHA256:
            return "Raw(SHA-256)";
        case PGP_HASH_SHA384:
            return "Raw(SHA-384)";
        case PGP_HASH_SHA512:
            return "Raw(SHA-512)";
        case PGP_HASH_SHA224:
            return "Raw(SHA-224)";
        case PGP_HASH_SHA3_256:
            return "Raw(SHA3(256))";
        case PGP_HASH_SHA3_512:
            return "Raw(SHA3(512))";

        case PGP_HASH_SM3:
            return "Raw(SM3)";
        default:
            return "Raw";
    }
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
    rnp_result_t result = ecdh_kem_gen_keypair_native(rng, priv, pub, curve);
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
    rnp_result_t result = exdsa_gen_keypair_native(rng, priv, pub, curve);
    if(result != RNP_SUCCESS) {
        RNP_LOG("error when generating EC key pair");
        return result;
    }
    
    out->priv = exdsa_private_key_t(priv, curve);
    out->pub = exdsa_public_key_t(pub, curve);

    return RNP_SUCCESS;
}

/* NOTE hash_alg unused for edwards curves */
rnp_result_t
exdsa_private_key_t::sign(std::vector<uint8_t> &sig_out, const uint8_t *hash, size_t hash_len, pgp_hash_alg_t hash_alg) const
{
    //Botan::System_RNG rng;
    //Botan::Null_RNG null_rng;
    botan_privkey_t    privkey = NULL;
    botan_pk_op_sign_t sign_op = NULL;
    rnp_result_t res = RNP_SUCCESS;
    botan_rng_t rng;
    botan_rng_init(&rng, NULL);
    botan_mp_t x = NULL;

    // std::unique_ptr<Botan::PK_Signer> signer;
    if(is_edwards_curve(curve_)) {
        sig_out.resize(64);
        size_t sig_size = 64;
        res = RNP_ERROR_SIGNING_FAILED;
        if (botan_privkey_load_ed25519(&privkey, key_.data()) != 0) { goto end; }
        if (botan_pk_op_sign_create(&sign_op, privkey, "Pure", 0) != 0) { goto end; }
        if (botan_pk_op_sign_update(sign_op, hash, hash_len) != 0) { goto end; }
        if (botan_pk_op_sign_finish(sign_op, rng, sig_out.data(), &sig_size) != 0) { goto end; }
        res = RNP_SUCCESS;

        //Botan::secure_vector<uint8_t> sv_key(key_.data(), key_.data() + key_.size());
        //Botan::Ed25519_PrivateKey priv_key(sv_key);
        //if(!priv_key.check_key(rng, false)) { return 5; }
        //signer = std::make_unique<Botan::PK_Signer>(priv_key, rng, "Pure");
    }
    else {
        res = RNP_ERROR_SIGNING_FAILED;
        const ec_curve_desc_t *ec_desc = get_curve_desc(curve_);
        const size_t curve_order = BITS_TO_BYTES(ec_desc->bitlen);
        sig_out.resize(2*curve_order);
        size_t sig_len = 2*curve_order;
        if (botan_mp_init(&x)) { goto end; } 
        if (botan_mp_from_bin(x, key_.data(), key_.size())) { goto end; }
        if (botan_privkey_load_ecdsa(&privkey, x, ec_desc->botan_name)) { goto end; }
        if (botan_pk_op_sign_create(&sign_op, privkey, ecdsa_padding_str_for(hash_alg), 0)) { goto end; }
        if (botan_pk_op_sign_update(sign_op, hash, hash_len)) { goto end; }
        if (botan_pk_op_sign_finish(sign_op, rng, sig_out.data(), &sig_len)) { goto end; }

        res = RNP_SUCCESS;

        //const ec_curve_desc_t *ec_desc = get_curve_desc(curve_);
        //Botan::BigInt scalar(key_);
        //Botan::ECDSA_PrivateKey priv_key(null_rng, Botan::EC_Group(ec_desc->botan_name), scalar);
        //if(!priv_key.check_key(rng, false)) { return 5; }
        //signer = std::make_unique<Botan::PK_Signer>(priv_key, rng, ecdsa_padding_str_for(hash_alg));
    }

    //sig_out->signature = signer.get()->sign_message(hash, hash_len, rng);

end:
    botan_pk_op_sign_destroy(sign_op);
    botan_privkey_destroy(privkey);
    botan_mp_destroy(x);
    botan_rng_destroy(rng);

    return res;
    // return RNP_SUCCESS;
}

rnp_result_t
exdsa_public_key_t::verify(const std::vector<uint8_t> &sig, const uint8_t *hash, size_t hash_len, pgp_hash_alg_t hash_alg) const
{
    rnp_result_t res = RNP_SUCCESS;
    botan_pk_op_verify_t verify_op = NULL;
    botan_pubkey_t pubkey = NULL;
    botan_mp_t px = NULL;
    botan_mp_t py = NULL;

    std::unique_ptr<Botan::PK_Verifier> verifier;
    if(is_edwards_curve(curve_)) {
        res = RNP_ERROR_VERIFICATION_FAILED; 
        if (botan_pubkey_load_ed25519(&pubkey, key_.data())) { goto end; }
        if (botan_pk_op_verify_create(&verify_op, pubkey, "Pure", 0)) { goto end; }
        if (botan_pk_op_verify_update(verify_op, hash, hash_len)) { goto end; }
        if (botan_pk_op_verify_finish(verify_op, sig.data(), sig.size())) { goto end; }
        res = RNP_SUCCESS;

        //Botan::Ed25519_PublicKey pub_key(key_);
        //Botan::System_RNG rng; 
        //if(pub_key.check_key(rng, false)) { 
        //    return RNP_ERROR_BAD_PARAMETERS; 
        //}
        //verifier = std::make_unique<Botan::PK_Verifier>(pub_key, "Pure");
    }
    else {
        res = RNP_ERROR_VERIFICATION_FAILED;
        const ec_curve_desc_t *ec_desc = get_curve_desc(curve_);
        const size_t curve_order = BITS_TO_BYTES(ec_desc->bitlen);
        if (botan_mp_init(&px)) { goto end; } 
        if (botan_mp_init(&py)) { goto end; } 
        if (botan_mp_from_bin(px, key_.data() + 1, curve_order)) { goto end; }
        if (botan_mp_from_bin(py, key_.data() + 1 + curve_order, curve_order)) { goto end; }
        if (botan_pubkey_load_ecdsa(&pubkey, px, py, ec_desc->botan_name)) { goto end; }
        if (botan_pk_op_verify_create(&verify_op, pubkey, ecdsa_padding_str_for(hash_alg), 0)) { goto end; }
        if (botan_pk_op_verify_update(verify_op, hash, hash_len)) { goto end; }
        if (botan_pk_op_verify_finish(verify_op, sig.data(), sig.size())) { goto end; }
        res = RNP_SUCCESS;

        // // format: 04 | X | Y
        // const ec_curve_desc_t *ec_desc = get_curve_desc(curve_);
        // Botan::EC_Group group(ec_desc->botan_name);
        // const size_t curve_order = BITS_TO_BYTES(ec_desc->bitlen);
        // Botan::BigInt x(key_.data() + 1, curve_order);
        // Botan::BigInt y(key_.data() + 1 + curve_order, curve_order);
        // Botan::ECDSA_PublicKey pub_key(group, group.point(x, y));
        // Botan::System_RNG rng; if(pub_key.check_key(rng, false)) { return 5; }
        // verifier = std::make_unique<Botan::PK_Verifier>(pub_key, ecdsa_padding_str_for(hash_alg));
    }
    //if(verifier.get()->verify_message(hash, hash_len, sig->signature.data(), sig->signature.size())) {
    //    return RNP_SUCCESS;
    //}

end: 
    botan_pk_op_verify_destroy(verify_op);
    botan_pubkey_destroy(pubkey);
    botan_mp_destroy(px);
    botan_mp_destroy(py);
    return res;

    // return RNP_ERROR_VERIFICATION_FAILED; 
}

bool
exdsa_public_key_t::is_valid() const {
    /* TODOMTG load and check in botan */
    return true;
}

bool
exdsa_private_key_t::is_valid() const {
    /* TODOMTG load and check in botan */
    return true;
}

bool
ecdh_kem_public_key_t::is_valid() const {
    /* TODOMTG load and check in botan */
    return true;
}

bool 
ecdh_kem_private_key_t::is_valid() const {
    /* TODOMTG load and check in botan */
    return true;
}

