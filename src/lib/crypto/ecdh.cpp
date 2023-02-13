/*-
 * Copyright (c) 2017-2022 Ribose Inc.
 * All rights reserved.
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

#include <string.h>
#include <botan/ffi.h>
#include "hash_botan.hpp"
#include "ecdh.h"
#include "ecdh_utils.h"
#include "symmetric.h"
#include "types.h"
#include "utils.h"
#include "mem.h"
#include "bn.h"

// Produces kek of size kek_len which corresponds to length of wrapping key
static bool
compute_kek(uint8_t *              kek,
            size_t                 kek_len,
            const uint8_t *        other_info,
            size_t                 other_info_size,
            const ec_curve_desc_t *curve_desc,
            const pgp_mpi_t *      ec_pubkey,
            const botan_privkey_t  ec_prvkey,
            const pgp_hash_alg_t   hash_alg)
{
    const uint8_t *p = ec_pubkey->mpi;
    uint8_t        p_len = ec_pubkey->len;

    if (curve_desc->rnp_curve_id == PGP_CURVE_25519) {
        if ((p_len != 33) || (p[0] != 0x40)) {
            return false;
        }
        p++;
        p_len--;
    }

    rnp::secure_array<uint8_t, MAX_CURVE_BYTELEN * 2 + 1> s;

    botan_pk_op_ka_t op_key_agreement = NULL;
    bool             ret = false;
    char             kdf_name[32] = {0};
    size_t           s_len = s.size();

    if (botan_pk_op_key_agreement_create(&op_key_agreement, ec_prvkey, "Raw", 0) ||
        botan_pk_op_key_agreement(op_key_agreement, s.data(), &s_len, p, p_len, NULL, 0)) {
        goto end;
    }

    snprintf(
      kdf_name, sizeof(kdf_name), "SP800-56A(%s)", rnp::Hash_Botan::name_backend(hash_alg));
    ret = !botan_kdf(
      kdf_name, kek, kek_len, s.data(), s_len, NULL, 0, other_info, other_info_size);
end:
    return ret && !botan_pk_op_key_agreement_destroy(op_key_agreement);
}

static bool
ecdh_load_public_key(botan_pubkey_t *pubkey, const pgp_ec_key_t *key)
{
    bool res = false;

    const ec_curve_desc_t *curve = get_curve_desc(key->curve);
    if (!curve) {
        RNP_LOG("unknown curve");
        return false;
    }

    if (curve->rnp_curve_id == PGP_CURVE_25519) {
        if ((key->p.len != 33) || (key->p.mpi[0] != 0x40)) {
            return false;
        }
        rnp::secure_array<uint8_t, 32> pkey;
        memcpy(pkey.data(), key->p.mpi + 1, 32);
        return !botan_pubkey_load_x25519(pubkey, pkey.data());
    }

    if (!mpi_bytes(&key->p) || (key->p.mpi[0] != 0x04)) {
        RNP_LOG("Failed to load public key");
        return false;
    }

    botan_mp_t   px = NULL;
    botan_mp_t   py = NULL;
    const size_t curve_order = BITS_TO_BYTES(curve->bitlen);

    if (botan_mp_init(&px) || botan_mp_init(&py) ||
        botan_mp_from_bin(px, &key->p.mpi[1], curve_order) ||
        botan_mp_from_bin(py, &key->p.mpi[1 + curve_order], curve_order)) {
        goto end;
    }

    if (!(res = !botan_pubkey_load_ecdh(pubkey, px, py, curve->botan_name))) {
        RNP_LOG("failed to load ecdh public key");
    }
end:
    botan_mp_destroy(px);
    botan_mp_destroy(py);
    return res;
}

static bool
ecdh_load_secret_key(botan_privkey_t *seckey, const pgp_ec_key_t *key)
{
    const ec_curve_desc_t *curve = get_curve_desc(key->curve);

    if (!curve) {
        return false;
    }

    if (curve->rnp_curve_id == PGP_CURVE_25519) {
        if (key->x.len != 32) {
            RNP_LOG("wrong x25519 key");
            return false;
        }
        /* need to reverse byte order since in mpi we have big-endian */
        rnp::secure_array<uint8_t, 32> prkey;
        for (int i = 0; i < 32; i++) {
            prkey[i] = key->x.mpi[31 - i];
        }
        return !botan_privkey_load_x25519(seckey, prkey.data());
    }

    bignum_t *x = NULL;
    if (!(x = mpi2bn(&key->x))) {
        return false;
    }
    bool res = !botan_privkey_load_ecdh(seckey, BN_HANDLE_PTR(x), curve->botan_name);
    bn_free(x);
    return res;
}

rnp_result_t
ecdh_validate_key(rnp::RNG *rng, const pgp_ec_key_t *key, bool secret)
{
    botan_pubkey_t  bpkey = NULL;
    botan_privkey_t bskey = NULL;
    rnp_result_t    ret = RNP_ERROR_BAD_PARAMETERS;

    const ec_curve_desc_t *curve_desc = get_curve_desc(key->curve);
    if (!curve_desc) {
        return RNP_ERROR_NOT_SUPPORTED;
    }

    if (!ecdh_load_public_key(&bpkey, key) ||
        botan_pubkey_check_key(bpkey, rng->handle(), 0)) {
        goto done;
    }
    if (!secret) {
        ret = RNP_SUCCESS;
        goto done;
    }

    if (!ecdh_load_secret_key(&bskey, key) ||
        botan_privkey_check_key(bskey, rng->handle(), 0)) {
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    botan_privkey_destroy(bskey);
    botan_pubkey_destroy(bpkey);
    return ret;
}

rnp_result_t
ecdh_encrypt_pkcs5(rnp::RNG *               rng,
                   pgp_ecdh_encrypted_t *   out,
                   const uint8_t *const     in,
                   size_t                   in_len,
                   const pgp_ec_key_t *     key,
                   const pgp_fingerprint_t &fingerprint)
{
    botan_privkey_t eph_prv_key = NULL;
    rnp_result_t    ret = RNP_ERROR_GENERIC;
    uint8_t         other_info[MAX_SP800_56A_OTHER_INFO];
    uint8_t         kek[32] = {0}; // Size of SHA-256 or smaller
    // 'm' is padded to the 8-byte granularity
    uint8_t      m[MAX_SESSION_KEY_SIZE];
    const size_t m_padded_len = ((in_len / 8) + 1) * 8;

    if (!key || !out || !in || (in_len > sizeof(m))) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
#if !defined(ENABLE_SM2)
    if (key->curve == PGP_CURVE_SM2_P_256) {
        RNP_LOG("SM2 curve support is disabled.");
        return RNP_ERROR_NOT_IMPLEMENTED;
    }
#endif
    const ec_curve_desc_t *curve_desc = get_curve_desc(key->curve);
    if (!curve_desc) {
        RNP_LOG("unsupported curve");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    // +8 because of AES-wrap adds 8 bytes
    if (ECDH_WRAPPED_KEY_SIZE < (m_padded_len + 8)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // See 13.5 of RFC 4880 for definition of other_info_size
    const size_t other_info_size = curve_desc->OIDhex_len + 46;
    const size_t kek_len = pgp_key_size(key->key_wrap_alg);
    size_t       tmp_len = kdf_other_info_serialize(
      other_info, curve_desc, fingerprint, key->kdf_hash_alg, key->key_wrap_alg);

    if (tmp_len != other_info_size) {
        RNP_LOG("Serialization of other info failed");
        return RNP_ERROR_GENERIC;
    }

    if (!strcmp(curve_desc->botan_name, "curve25519")) {
        if (botan_privkey_create(&eph_prv_key, "Curve25519", "", rng->handle())) {
            goto end;
        }
    } else {
        if (botan_privkey_create(
              &eph_prv_key, "ECDH", curve_desc->botan_name, rng->handle())) {
            goto end;
        }
    }

    if (!compute_kek(kek,
                     kek_len,
                     other_info,
                     other_info_size,
                     curve_desc,
                     &key->p,
                     eph_prv_key,
                     key->kdf_hash_alg)) {
        RNP_LOG("KEK computation failed");
        goto end;
    }

    memcpy(m, in, in_len);
    if (!pad_pkcs7(m, m_padded_len, in_len)) {
        // Should never happen
        goto end;
    }

    out->mlen = sizeof(out->m);
    if (botan_key_wrap3394(m, m_padded_len, kek, kek_len, out->m, &out->mlen)) {
        goto end;
    }

    /* we need to prepend 0x40 for the x25519 */
    if (key->curve == PGP_CURVE_25519) {
        out->p.len = sizeof(out->p.mpi) - 1;
        if (botan_pk_op_key_agreement_export_public(
              eph_prv_key, out->p.mpi + 1, &out->p.len)) {
            goto end;
        }
        out->p.mpi[0] = 0x40;
        out->p.len++;
    } else {
        out->p.len = sizeof(out->p.mpi);
        if (botan_pk_op_key_agreement_export_public(eph_prv_key, out->p.mpi, &out->p.len)) {
            goto end;
        }
    }

    // All OK
    ret = RNP_SUCCESS;
end:
    botan_privkey_destroy(eph_prv_key);
    return ret;
}

rnp_result_t
ecdh_decrypt_pkcs5(uint8_t *                   out,
                   size_t *                    out_len,
                   const pgp_ecdh_encrypted_t *in,
                   const pgp_ec_key_t *        key,
                   const pgp_fingerprint_t &   fingerprint)
{
    if (!out_len || !in || !key || !mpi_bytes(&key->x)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const ec_curve_desc_t *curve_desc = get_curve_desc(key->curve);
    if (!curve_desc) {
        RNP_LOG("unknown curve");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    const pgp_symm_alg_t wrap_alg = key->key_wrap_alg;
    const pgp_hash_alg_t kdf_hash = key->kdf_hash_alg;
    /* Ensure that AES is used for wrapping */
    if ((wrap_alg != PGP_SA_AES_128) && (wrap_alg != PGP_SA_AES_192) &&
        (wrap_alg != PGP_SA_AES_256)) {
        RNP_LOG("non-aes wrap algorithm");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    // See 13.5 of RFC 4880 for definition of other_info_size
    uint8_t      other_info[MAX_SP800_56A_OTHER_INFO];
    const size_t other_info_size = curve_desc->OIDhex_len + 46;
    const size_t tmp_len =
      kdf_other_info_serialize(other_info, curve_desc, fingerprint, kdf_hash, wrap_alg);

    if (other_info_size != tmp_len) {
        RNP_LOG("Serialization of other info failed");
        return RNP_ERROR_GENERIC;
    }

    botan_privkey_t prv_key = NULL;
    if (!ecdh_load_secret_key(&prv_key, key)) {
        RNP_LOG("failed to load ecdh secret key");
        return RNP_ERROR_GENERIC;
    }

    // Size of SHA-256 or smaller
    rnp::secure_array<uint8_t, MAX_SYMM_KEY_SIZE>    kek;
    rnp::secure_array<uint8_t, MAX_SESSION_KEY_SIZE> deckey;

    size_t       deckey_len = deckey.size();
    size_t       offset = 0;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    /* Security: Always return same error code in case compute_kek,
     *           botan_key_unwrap3394 or unpad_pkcs7 fails
     */
    size_t kek_len = pgp_key_size(wrap_alg);
    if (!compute_kek(kek.data(),
                     kek_len,
                     other_info,
                     other_info_size,
                     curve_desc,
                     &in->p,
                     prv_key,
                     kdf_hash)) {
        goto end;
    }

    if (botan_key_unwrap3394(
          in->m, in->mlen, kek.data(), kek_len, deckey.data(), &deckey_len)) {
        goto end;
    }

    if (!unpad_pkcs7(deckey.data(), deckey_len, &offset)) {
        goto end;
    }

    if (*out_len < offset) {
        ret = RNP_ERROR_SHORT_BUFFER;
        goto end;
    }

    *out_len = offset;
    memcpy(out, deckey.data(), *out_len);
    ret = RNP_SUCCESS;
end:
    botan_privkey_destroy(prv_key);
    return ret;
}


static rnp_result_t ecdh_kem_gen_keypair_sec1_x25519(rnp::RNG *           rng,
                                                     std::vector<uint8_t> &privkey, 
                                                     std::vector<uint8_t> &pubkey)
{
    const ec_curve_desc_t *ec_desc = get_curve_desc(PGP_CURVE_25519);
    const size_t curve_order = BITS_TO_BYTES(ec_desc->bitlen);
    botan_privkey_t botan_priv = NULL;
    botan_pubkey_t  botan_pub = NULL;
    rnp_result_t res = RNP_SUCCESS;

    privkey.resize(curve_order);
    pubkey.resize(curve_order);

    if(botan_privkey_create(&botan_priv, "Curve25519", "", rng->handle())
        || botan_privkey_export_pubkey(&botan_pub, botan_priv) 
        || botan_privkey_x25519_get_privkey(botan_priv, privkey.data())
        || botan_pubkey_x25519_get_pubkey(botan_pub, pubkey.data())) 
    {
        RNP_LOG("error when generating x25519 key");
        res = RNP_ERROR_GENERIC;
    }

    botan_privkey_destroy(botan_priv);
    botan_pubkey_destroy(botan_pub);

    return res;
}

static bool is_generic_prime_curve(pgp_curve_t curve) {
    switch(curve) {
        case PGP_CURVE_NIST_P_256: [[fallthrough]];
        case PGP_CURVE_NIST_P_384: [[fallthrough]];
        case PGP_CURVE_NIST_P_521: [[fallthrough]];
        case PGP_CURVE_BP256: [[fallthrough]];
        case PGP_CURVE_BP384: [[fallthrough]];
        case PGP_CURVE_BP512:
            return true;
        default: 
            return false;
    }
}
static rnp_result_t ecdh_kem_gen_keypair_sec1_generic(rnp::RNG *           rng,
                                                      std::vector<uint8_t> &privkey, 
                                                      std::vector<uint8_t> &pubkey,
                                                      pgp_curve_t          curve)
{
    if(!is_generic_prime_curve(curve)) {
        RNP_LOG("expected generic prime curve");
        return RNP_ERROR_GENERIC;
    }

    rnp_result_t res = RNP_SUCCESS;

    botan_privkey_t botan_priv = NULL;
    botan_pubkey_t  botan_pub = NULL;

    bignum_t *      px = NULL;
    bignum_t *      py = NULL;
    bignum_t *      x = NULL;
    size_t offset;

    const ec_curve_desc_t *ec_desc = get_curve_desc(curve);
    const size_t curve_order = BITS_TO_BYTES(ec_desc->bitlen);

    pubkey.resize(2 * curve_order + 1);
    privkey.resize(curve_order);

    if (botan_privkey_create(&botan_priv, "ECDH", ec_desc->botan_name, rng->handle()) 
        || botan_privkey_export_pubkey(&botan_pub, botan_priv))
    {
        RNP_LOG("error when generating ECDH key");
        res = RNP_ERROR_GENERIC;
        goto end;
    }

    px = bn_new();
    py = bn_new();
    x = bn_new();
    if (botan_pubkey_get_field(BN_HANDLE_PTR(px), botan_pub, "public_x")
        || botan_pubkey_get_field(BN_HANDLE_PTR(py), botan_pub, "public_y")
        || botan_privkey_get_field(BN_HANDLE_PTR(x), botan_priv, "x"))
    {
        RNP_LOG("error when generating ECDH key");
        res = RNP_ERROR_GENERIC;
        goto end;
    }

    pubkey.data()[0] = 0x04;

    /* if the px/py/x elements are less than curve order, we have to zero-pad them */
    offset =  curve_order - bn_num_bytes(*px);
    if (offset) {
        memset(&pubkey.data()[1], 0, offset);
    }
    bn_bn2bin(px, &pubkey.data()[1 + offset]);
    offset =  curve_order - bn_num_bytes(*py);
    if (offset) {
        memset(&pubkey.data()[1 + curve_order], 0, offset);
    }
    bn_bn2bin(py, &pubkey.data()[1 + curve_order + offset]);

    offset =  curve_order - bn_num_bytes(*x);
    if (offset) {
        memset(privkey.data(), 0, offset);
    }
    bn_bn2bin(x, privkey.data() + offset);

end:
        botan_privkey_destroy(botan_priv);
        botan_pubkey_destroy(botan_pub);
        bn_free(px);
        bn_free(py);
        bn_free(x);

        return res;
}

rnp_result_t ecdh_kem_gen_keypair_sec1(rnp::RNG *           rng,
                                       std::vector<uint8_t> &privkey, 
                                       std::vector<uint8_t> &pubkey,
                                       pgp_curve_t          curve)
{
    if(curve == PGP_CURVE_25519) {
        return ecdh_kem_gen_keypair_sec1_x25519(rng, privkey, pubkey);
    }
    return ecdh_kem_gen_keypair_sec1_generic(rng, privkey, pubkey, curve);
}

rnp_result_t ecdh_kem_encaps(rnp::RNG *                 rng,
                             std::vector<uint8_t>       &ciphertext,   /* encrypted shared secret */
                             std::vector<uint8_t>       &plaintext,    /* plaintext / shared secret / key share */
                             const std::vector<uint8_t> &pubkey_in,    /* public key */
                             pgp_curve_t                curve)
{
    // TODOMTG: can probably share code with the existing code in ecdh_load_public_key() and ecdh_encrypt_pkcs5()
    rnp_result_t ret;
    int botan_ret;
    botan_privkey_t eph_prv_key = NULL;
    botan_pk_op_ka_t op_key_agreement = NULL;
    rnp::secure_array<uint8_t, MAX_CURVE_BYTELEN * 2 + 1> s;
    size_t s_len = s.size();
    size_t len;
    const ec_curve_desc_t *curve_desc = get_curve_desc(curve);
    if (!curve_desc) {
        RNP_LOG("unknown curve");
        return RNP_ERROR_NOT_SUPPORTED;
    }
    const size_t curve_order = BITS_TO_BYTES(curve_desc->bitlen);

    /* create ephemeral key */
    if (curve == PGP_CURVE_25519) {
        botan_ret = botan_privkey_create(&eph_prv_key, "Curve25519", "", rng->handle());
    }
    else {
        botan_ret = botan_privkey_create(&eph_prv_key, "ECDH", curve_desc->botan_name, rng->handle());
    }
    if (botan_ret) {
        RNP_LOG("failed to generate ephemeral private key");
        ret = RNP_ERROR_GENERIC;
        goto end;
    }

    /* do the actual operation */
    botan_ret = botan_pk_op_key_agreement_create(&op_key_agreement, eph_prv_key, "Raw", 0);
    if (botan_ret) {
        RNP_LOG("failed to create key agreement op, %d", botan_ret);
        ret = RNP_ERROR_GENERIC;
        goto end;
    }
    botan_ret = botan_pk_op_key_agreement(op_key_agreement, s.data(), &s_len, pubkey_in.data(), pubkey_in.size(), NULL, 0);
    if(botan_ret)  {
        RNP_LOG("ECDH key agreement failed, %d", botan_ret);
        ret = RNP_ERROR_GENERIC;
        goto end;
    }

    /* set ciphertext output */
    if (curve == PGP_CURVE_25519) {
        ciphertext.resize(curve_order);
    } else {
        ciphertext.resize(2*curve_order + 1);
    }
    len = ciphertext.size();
    ret = botan_pk_op_key_agreement_export_public(eph_prv_key, ciphertext.data(), &len);
    if(ret) {
        RNP_LOG("botan_pk_op_key_agreement_export_public() failed");
        ret = RNP_ERROR_GENERIC;
        goto end; 
    }
    if(len != ciphertext.size()) {
        RNP_LOG("expected different length for botan_pk_op_key_agreement_export_public() (expect: %zu, got: %zu)", ciphertext.size(), len);
        ret = RNP_ERROR_GENERIC;
        goto end;    
    }

    if (curve == PGP_CURVE_25519) {
        plaintext.assign(s.data(), s.data() + curve_order);
    } else {
        /*  draft-wussler-openpgp-pqc-00: 
            Extract the X coordinate from the SEC1 encoded point S = 04 || X || Y as defined in section Section 1.3.3
        */
        plaintext.assign(s.data() + 1, s.data() + curve_order + 1);
    }

end:
    botan_pk_op_key_agreement_destroy(op_key_agreement);
    botan_privkey_destroy(eph_prv_key);
    return ret;
}

rnp_result_t ecdh_kem_decaps(std::vector<uint8_t>       &plaintext,  /* plaintext shared secret */
                             const std::vector<uint8_t> &ciphertext, /* encrypted shared secret */
                             const std::vector<uint8_t> &privkey_in, /* private key */
                             pgp_curve_t curve) 
{
    rnp_result_t ret = RNP_SUCCESS;
    int botan_ret;
    const ec_curve_desc_t *curve_desc = get_curve_desc(curve);
    if (!curve_desc) {
        RNP_LOG("unknown curve");
        return RNP_ERROR_NOT_SUPPORTED;
    }
    botan_pk_op_ka_t op_key_agreement = NULL;
    rnp::secure_array<uint8_t, MAX_CURVE_BYTELEN * 2 + 1> s;
    size_t s_len = s.size();
    const size_t curve_order = BITS_TO_BYTES(curve_desc->bitlen);

    botan_privkey_t prv_key = NULL;
    if (curve == PGP_CURVE_25519) {
        botan_ret = botan_privkey_load_x25519(&prv_key, privkey_in.data());
    } else {
        botan_mp_t x;
        if(botan_mp_init(&x) || botan_mp_from_bin(x, privkey_in.data(), privkey_in.size())) {
            botan_mp_destroy(x);
            RNP_LOG("failed to load ecdh secret key");
            ret = RNP_ERROR_GENERIC;
            goto end;
        }
        botan_ret = botan_privkey_load_ecdh(&prv_key, x, curve_desc->botan_name);
        botan_mp_destroy(x);
    }
    if(botan_ret) {
        RNP_LOG("failed to load ecdh secret key");
        ret = RNP_ERROR_GENERIC;
        goto end;
    }

    /* do the actual operation */
    if (botan_pk_op_key_agreement_create(&op_key_agreement, prv_key, "Raw", 0) ||
        botan_pk_op_key_agreement(op_key_agreement, s.data(), &s_len, ciphertext.data(), ciphertext.size(), NULL, 0)) 
    {
        printf("FAILED: %d, curve: %s\n", botan_pk_op_key_agreement(op_key_agreement, s.data(), &s_len, ciphertext.data(), ciphertext.size(), NULL, 0), curve_desc->pgp_name);
        RNP_LOG("ECDH key agreement failed");
        ret = RNP_ERROR_GENERIC;
        goto end;
    }

    if (curve == PGP_CURVE_25519) {
        plaintext.assign(s.data(), s.data() + curve_order);
    } else {
        /*  draft-wussler-openpgp-pqc-00: 
            Extract the X coordinate from the SEC1 encoded point S = 04 || X || Y as defined in section Section 1.3.3
        */
        plaintext.assign(s.data() + 1, s.data() + curve_order + 1);
    }

end:
    botan_pk_op_key_agreement_destroy(op_key_agreement);
    botan_privkey_destroy(prv_key);
    return ret;
}