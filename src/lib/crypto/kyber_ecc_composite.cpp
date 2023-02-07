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

#include "kyber_ecc_composite.h"
#include "logging.h"
#include "types.h"

pgp_kyber_ecc_composite_key_t::~pgp_kyber_ecc_composite_key_t() {}

void
pgp_kyber_ecc_composite_key_t::initialized_or_throw() {
    if(!is_initialized()) {
        RNP_LOG("Trying to use uninitialized kyber-ecc key");
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);  /* TODO better return error */
    }
}

rnp_result_t
pgp_kyber_ecc_composite_key_t::gen_keypair(rnp::RNG *rng, pgp_kyber_ecc_key_t *key, pgp_pubkey_alg_t alg) {
    // TODOMTG: actually generate the keys
   key->priv = pgp_kyber_ecc_composite_private_key_t(std::vector<uint8_t>(pgp_kyber_ecc_composite_private_key_t::encoded_size(alg)), alg);
   key->pub = pgp_kyber_ecc_composite_public_key_t(std::vector<uint8_t>(pgp_kyber_ecc_composite_public_key_t::encoded_size(alg)), alg);
   return RNP_SUCCESS;
}

size_t
pgp_kyber_ecc_composite_key_t::ecdh_curve_privkey_size(pgp_curve_t curve) {
    switch(curve) {
        case PGP_CURVE_25519:
            return 32;
        /* TODOMTG */
        // case PGP_CURVE_X448:
        //   return 56;
        case PGP_CURVE_NIST_P_256:
            return 32;
        case PGP_CURVE_NIST_P_384:
            return 48;
        case PGP_CURVE_BP256:
            return 32;
        case PGP_CURVE_BP384:
            return 48;
        default: 
            RNP_LOG("invalid curve given");
            throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS); 
    }
}

size_t
pgp_kyber_ecc_composite_key_t::ecdh_curve_pubkey_size(pgp_curve_t curve) {
    switch(curve) {
        case PGP_CURVE_25519:
            return 32;
        /* TODOMTG */
        //  case PGP_CURVE_X448:
        //    return 56;
        case PGP_CURVE_NIST_P_256:
            return 65;
        case PGP_CURVE_NIST_P_384:
            return 97;
        case PGP_CURVE_BP256:
            return 65;
        case PGP_CURVE_BP384:
            return 97;
        default:
            RNP_LOG("invalid curve given");
            throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
}

size_t
pgp_kyber_ecc_composite_key_t::ecdh_curve_ephemeral_size(pgp_curve_t curve) {
    switch(curve) {
        case PGP_CURVE_25519:
            return 32;
        /* TODOMTG */
        //  case PGP_CURVE_X448:
        //    return 56;
        case PGP_CURVE_NIST_P_256:
            return 65;
        case PGP_CURVE_NIST_P_384:
            return 97;
        case PGP_CURVE_BP256:
            return 65;
        case PGP_CURVE_BP384:
            return 97;
        default:
            RNP_LOG("invalid curve given");
            throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
}

size_t
pgp_kyber_ecc_composite_key_t::ecdh_curve_keyshare_size(pgp_curve_t curve) {
    switch(curve) {
        case PGP_CURVE_25519:
            return 32;
        /* TODOMTG */
        //  case PGP_CURVE_X448:
        //    return 56;
        case PGP_CURVE_NIST_P_256:
            return 32;
        case PGP_CURVE_NIST_P_384:
            return 48;
        case PGP_CURVE_BP256:
            return 32;
        case PGP_CURVE_BP384:
            return 48;
        default:
            RNP_LOG("invalid curve given");
            throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS); 
    }
}

kyber_parameter_e
pgp_kyber_ecc_composite_key_t::pk_alg_to_kyber_id(pgp_pubkey_alg_t pk_alg) {
    switch(pk_alg)
    {
      case PGP_PKA_KYBER768_X25519:
        [[fallthrough]];
      case PGP_PKA_KYBER768_P256:
        [[fallthrough]];
      case PGP_PKA_KYBER768_BP256:
          return kyber_768;
      case PGP_PKA_KYBER1024_BP384:
        [[fallthrough]];
      case PGP_PKA_KYBER1024_P384:
        [[fallthrough]];
      case PGP_PKA_KYBER1024_X448:
        return kyber_1024;
      default:
        RNP_LOG("invalid PK alg given");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS); 
    }
}

pgp_curve_t
pgp_kyber_ecc_composite_key_t::pk_alg_to_curve_id(pgp_pubkey_alg_t pk_alg) {
    switch(pk_alg)
    {
      case PGP_PKA_KYBER768_X25519:
        return PGP_CURVE_25519;
      case PGP_PKA_KYBER768_P256:
        return PGP_CURVE_NIST_P_256;
      case PGP_PKA_KYBER768_BP256:
          return PGP_CURVE_BP256;
      case PGP_PKA_KYBER1024_BP384:
        return PGP_CURVE_BP384;
      case PGP_PKA_KYBER1024_P384:
        return PGP_CURVE_NIST_P_384;
      case PGP_PKA_KYBER1024_X448:
        return PGP_CURVE_UNKNOWN; /* TODOMTG: Not yet implemented */
      default:
        RNP_LOG("invalid PK alg given");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS); 
    }
}

namespace {
    void dummy_kmac_kdf() {}; /* TODO: replace with real functionality */
}


/* copy assignment operator is used on key materials struct and thus needs to be defined for this class as well */
pgp_kyber_ecc_composite_private_key_t& pgp_kyber_ecc_composite_private_key_t::operator=(const pgp_kyber_ecc_composite_private_key_t& other)
{
    pgp_kyber_ecc_composite_key_t::operator=(other);
    pk_alg_ = other.pk_alg_,
    kyber_key = other.kyber_key;
    ecc_key = other.ecc_key;
    
    return *this;
}

/* copy assignment operator is used on materials struct and thus needs to be defined for this class as well */
pgp_kyber_ecc_composite_public_key_t& pgp_kyber_ecc_composite_public_key_t::operator=(const pgp_kyber_ecc_composite_public_key_t& other)
{
    pgp_kyber_ecc_composite_key_t::operator=(other);
    pk_alg_ = other.pk_alg_,
    kyber_key = kyber_key;
    ecc_key = ecc_key;
    
    return *this;
}


pgp_kyber_ecc_composite_private_key_t::pgp_kyber_ecc_composite_private_key_t(const uint8_t *key_encoded, size_t key_encoded_len, pgp_pubkey_alg_t pk_alg):
    pk_alg_(pk_alg)
{
    kyber_key_from_encoded(std::vector<uint8_t>(key_encoded, key_encoded + key_encoded_len));
    ecc_key_from_encoded(std::vector<uint8_t>(key_encoded, key_encoded + key_encoded_len));
}

pgp_kyber_ecc_composite_private_key_t::pgp_kyber_ecc_composite_private_key_t(std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t pk_alg):
    pk_alg_(pk_alg)
{
    kyber_key_from_encoded(key_encoded);
    ecc_key_from_encoded(key_encoded);
}

size_t
pgp_kyber_ecc_composite_private_key_t::encoded_size(pgp_pubkey_alg_t pk_alg)
{
  kyber_parameter_e kyber_param = pk_alg_to_kyber_id(pk_alg);
  pgp_curve_t curve = pk_alg_to_curve_id(pk_alg);
  return ecdh_curve_privkey_size(curve) + kyber_privkey_size(kyber_param);
}

void 
pgp_kyber_ecc_composite_private_key_t::kyber_key_from_encoded(std::vector<uint8_t> key_encoded) 
{
    if (key_encoded.size() != encoded_size(pk_alg_)) {
        RNP_LOG("Kyber composite key format invalid: length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }

    // make private key from second part of the composite structure
    size_t offset = ecdh_curve_privkey_size(pk_alg_to_curve_id(pk_alg_));
    kyber_parameter_e param = pk_alg_to_kyber_id(pk_alg_);
    
    kyber_key = pgp_kyber_private_key_t(key_encoded.data() + offset, key_encoded.size() - offset, param);
    is_kyber_initialized_ = true;
}

void
pgp_kyber_ecc_composite_private_key_t::ecc_key_from_encoded(std::vector<uint8_t> key_encoded) 
{
    if (key_encoded.size() != encoded_size(pk_alg_)) {
        RNP_LOG("Kyber composite key format invalid: length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }

    // make private key from first part of the composite structure
    size_t len = ecdh_curve_privkey_size(pk_alg_to_curve_id(pk_alg_));
    ecc_key = std::vector<uint8_t>(key_encoded.data(), key_encoded.data() + len);
    is_ecc_initialized_ = true;
}


rnp_result_t
pgp_kyber_ecc_composite_private_key_t::decrypt(uint8_t *out, size_t *out_len, const pgp_kyber_ecc_encrypted_t *enc)
{
    initialized_or_throw();

    /* TODO: implement*/
    memcpy(out, enc->ct, enc->ct_len);
    *out_len = enc->ct_len;
    return RNP_SUCCESS;
}

void
pgp_kyber_ecc_composite_private_key_t::secure_clear() {
    // TODOMTG: securely erase the data
    is_ecc_initialized_ = false;
    is_kyber_initialized_ = false;
}

std::vector<uint8_t>
pgp_kyber_ecc_composite_private_key_t::get_encoded() {
    initialized_or_throw();
    std::vector<uint8_t> result;
    std::vector<uint8_t> kyber_key_encoded = kyber_key.get_encoded();

    result.insert(result.end(), std::begin(ecc_key), std::end(ecc_key));
    result.insert(result.end(), std::begin(kyber_key_encoded), std::end(kyber_key_encoded));
    return result;
};


pgp_kyber_ecc_composite_public_key_t::pgp_kyber_ecc_composite_public_key_t(const uint8_t *key_encoded, size_t key_encoded_len, pgp_pubkey_alg_t pk_alg):
    pk_alg_(pk_alg)
{
    kyber_key_from_encoded(std::vector<uint8_t>(key_encoded, key_encoded + key_encoded_len));
    ecc_key_from_encoded(std::vector<uint8_t>(key_encoded, key_encoded + key_encoded_len));
}

pgp_kyber_ecc_composite_public_key_t::pgp_kyber_ecc_composite_public_key_t(std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t pk_alg):
    pk_alg_(pk_alg)
{
    kyber_key_from_encoded(key_encoded);
    ecc_key_from_encoded(key_encoded);
}

size_t
pgp_kyber_ecc_composite_public_key_t::encoded_size(pgp_pubkey_alg_t pk_alg)
{
  kyber_parameter_e kyber_param = pk_alg_to_kyber_id(pk_alg);
  pgp_curve_t curve = pk_alg_to_curve_id(pk_alg);
  return ecdh_curve_pubkey_size(curve) + kyber_pubkey_size(kyber_param);
}

void 
pgp_kyber_ecc_composite_public_key_t::kyber_key_from_encoded(std::vector<uint8_t> key_encoded) 
{
    if (key_encoded.size() != encoded_size(pk_alg_)) {
        RNP_LOG("Kyber composite key format invalid: length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }

    // make private key from second part of the composite structure
    size_t offset = ecdh_curve_pubkey_size(pk_alg_to_curve_id(pk_alg_));
    kyber_parameter_e param = pk_alg_to_kyber_id(pk_alg_);
    kyber_key = pgp_kyber_private_key_t(key_encoded.data() + offset, key_encoded.size() - offset, param);
    is_kyber_initialized_ = true;
}

void
pgp_kyber_ecc_composite_public_key_t::ecc_key_from_encoded(std::vector<uint8_t> key_encoded)
{
    if (key_encoded.size() != encoded_size(pk_alg_)) {
        RNP_LOG("Kyber composite key format invalid: length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }

    // make private key from first part of the composite structure
    size_t len = ecdh_curve_pubkey_size(pk_alg_to_curve_id(pk_alg_));
    ecc_key = std::vector<uint8_t>(key_encoded.data(), key_encoded.data() + len);
    is_ecc_initialized_ = true;
}

rnp_result_t
pgp_kyber_ecc_composite_public_key_t::encrypt(pgp_kyber_ecc_encrypted_t *out, const uint8_t *in, size_t in_len)
{
    initialized_or_throw();
    /* encrypt with kyber component key */


    /* encrypt with ecc component key */


    /* compute KEK with combiner */
    dummy_kmac_kdf(); /* TODOMTG */
    
    /* TODOMTG: implement*/
    memcpy(out->ct, in, in_len);
    out->ct_len = in_len;
    return RNP_SUCCESS;
}

std::vector<uint8_t>
pgp_kyber_ecc_composite_public_key_t::get_encoded() {
    initialized_or_throw();
    std::vector<uint8_t> result;
    std::vector<uint8_t> kyber_key_encoded = kyber_key.get_encoded();

    result.insert(result.end(), std::begin(ecc_key), std::end(ecc_key));
    result.insert(result.end(), std::begin(kyber_key_encoded), std::end(kyber_key_encoded));
    return result;
};



rnp_result_t kyber_ecc_validate_key(rnp::RNG *rng, const pgp_kyber_ecc_key_t *key, bool secret) {
    // TODOMTG: implement
    return RNP_SUCCESS;
}