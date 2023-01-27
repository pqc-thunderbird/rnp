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

namespace {
    
size_t ecdh_curve_privkey_size(pgp_curve_t curve) {
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

size_t ecdh_curve_pubkey_size(pgp_curve_t curve) {
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

size_t ecdh_curve_ephemeral_size(pgp_curve_t curve) {
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

size_t ecdh_curve_keyshare_size(pgp_curve_t curve) {
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
}

/* copy assignment operator is used on materials struct and thus needs to be defined for this class as well */
pgp_kyber_ecc_composite_private_key_t& pgp_kyber_ecc_composite_private_key_t::operator=(const pgp_kyber_ecc_composite_private_key_t& other)
{
    if(key_encoded_.size())
    {
        key_encoded_= std::vector<uint8_t>(other.key_encoded_.data(), other.key_encoded_.data() + other.key_encoded_.size()),
        pk_alg_ = other.pk_alg_,
        kyber_key = kyber_key_from_encoded();
        ecc_key = ecc_key_from_encoded();
    }
    return *this;
}

/* copy assignment operator is used on materials struct and thus needs to be defined for this class as well */
pgp_kyber_ecc_composite_public_key_t& pgp_kyber_ecc_composite_public_key_t::operator=(const pgp_kyber_ecc_composite_public_key_t& other)
{
    if(key_encoded_.size())
    {
        key_encoded_= std::vector<uint8_t>(other.key_encoded_.data(), other.key_encoded_.data() + other.key_encoded_.size()),
        pk_alg_ = other.pk_alg_,
        kyber_key = kyber_key_from_encoded();
        ecc_key = ecc_key_from_encoded();
    }
    return *this;
}


pgp_kyber_ecc_composite_private_key_t::pgp_kyber_ecc_composite_private_key_t(const uint8_t *key_encoded, size_t key_encoded_len, pgp_pubkey_alg_t pk_alg):
    key_encoded_(key_encoded, key_encoded + key_encoded_len),
    pk_alg_(pk_alg),
    kyber_key(kyber_key_from_encoded()),
    ecc_key(ecc_key_from_encoded())
{
}

pgp_kyber_ecc_composite_private_key_t::pgp_kyber_ecc_composite_private_key_t(std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t pk_alg):
    key_encoded_(key_encoded),
    pk_alg_(pk_alg),
    kyber_key(kyber_key_from_encoded()),
    ecc_key(ecc_key_from_encoded())
{
}

size_t
pgp_kyber_ecc_composite_private_key_t::encoded_size(pgp_pubkey_alg_t pk_alg)
{
  kyber_parameter_e kyber_param = pk_alg_to_kyber_id(pk_alg);
  pgp_curve_t curve = pk_alg_to_curve_id(pk_alg);
  return ecdh_curve_privkey_size(curve) + kyber_privkey_size(kyber_param);
}

pgp_kyber_private_key_t 
pgp_kyber_ecc_composite_private_key_t::kyber_key_from_encoded() 
{
    if (key_encoded_.size() != encoded_size(pk_alg_)) {
        RNP_LOG("Kyber composite key format invalid: length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }

    // make private key from second part of the composite structure
    size_t offset = ecdh_curve_privkey_size(pk_alg_to_curve_id(pk_alg_));
    kyber_parameter_e param = pk_alg_to_kyber_id(pk_alg_);
    return pgp_kyber_private_key_t(key_encoded_.data() + offset, key_encoded_.size() - offset, param);
}

std::vector<uint8_t>
pgp_kyber_ecc_composite_private_key_t::ecc_key_from_encoded() 
{
    if (key_encoded_.size() != encoded_size(pk_alg_)) {
        RNP_LOG("Kyber composite key format invalid: length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }

    // make private key from first part of the composite structure
    size_t len = ecdh_curve_privkey_size(pk_alg_to_curve_id(pk_alg_));
    return std::vector<uint8_t>(key_encoded_.data(), key_encoded_.data() + len);
}


std::vector<uint8_t>
pgp_kyber_ecc_composite_private_key_t::decapsulate(const uint8_t *ciphertext, size_t ciphertext_len)
{
    /* TODO: implement*/
    return std::vector<uint8_t>(ciphertext, ciphertext + ciphertext_len); // do nothing
}



pgp_kyber_ecc_composite_public_key_t::pgp_kyber_ecc_composite_public_key_t(const uint8_t *key_encoded, size_t key_encoded_len, pgp_pubkey_alg_t pk_alg):
    key_encoded_(key_encoded, key_encoded + key_encoded_len),
    pk_alg_(pk_alg),
    kyber_key(kyber_key_from_encoded()),
    ecc_key(ecc_key_from_encoded())
{
}

pgp_kyber_ecc_composite_public_key_t::pgp_kyber_ecc_composite_public_key_t(std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t pk_alg):
    key_encoded_(key_encoded),
    pk_alg_(pk_alg),
    kyber_key(kyber_key_from_encoded()),
    ecc_key(ecc_key_from_encoded())
{
}

size_t
pgp_kyber_ecc_composite_public_key_t::encoded_size(pgp_pubkey_alg_t pk_alg)
{
  kyber_parameter_e kyber_param = pk_alg_to_kyber_id(pk_alg);
  pgp_curve_t curve = pk_alg_to_curve_id(pk_alg);
  return ecdh_curve_pubkey_size(curve) + kyber_pubkey_size(kyber_param);
}

pgp_kyber_private_key_t 
pgp_kyber_ecc_composite_public_key_t::kyber_key_from_encoded() 
{
    if (key_encoded_.size() != encoded_size(pk_alg_)) {
        RNP_LOG("Kyber composite key format invalid: length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }

    // make private key from second part of the composite structure
    size_t offset = ecdh_curve_pubkey_size(pk_alg_to_curve_id(pk_alg_));
    kyber_parameter_e param = pk_alg_to_kyber_id(pk_alg_);
    return pgp_kyber_private_key_t(key_encoded_.data() + offset, key_encoded_.size() - offset, param);
}

std::vector<uint8_t>
pgp_kyber_ecc_composite_public_key_t::ecc_key_from_encoded() 
{
    if (key_encoded_.size() != encoded_size(pk_alg_)) {
        RNP_LOG("Kyber composite key format invalid: length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }

    // make private key from first part of the composite structure
    size_t len = ecdh_curve_pubkey_size(pk_alg_to_curve_id(pk_alg_));
    return std::vector<uint8_t>(key_encoded_.data(), key_encoded_.data() + len);
}

pgp_kyber_ecc_encrypted_t
pgp_kyber_ecc_composite_public_key_t::encapsulate(const uint8_t* in, size_t in_len)
{
    /* TODO: implement*/
    pgp_kyber_ecc_encrypted_t result;
    result.ciphertext = std::vector<uint8_t>(in, in + in_len); // do nothing
    return result;
}


kyber_parameter_e pk_alg_to_kyber_id(pgp_pubkey_alg_t pk_alg) {
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

pgp_curve_t pk_alg_to_curve_id(pgp_pubkey_alg_t pk_alg) {
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


rnp_result_t kyber_ecc_gen_keypair(rnp::RNG *rng, pgp_kyber_ecc_key_t *key, pgp_pubkey_alg_t alg) {
    // TODOMTG: actually generate the keys
   key->priv = pgp_kyber_ecc_composite_private_key_t(std::vector<uint8_t>(pgp_kyber_ecc_composite_private_key_t::encoded_size(alg)), alg);
   key->pub = pgp_kyber_ecc_composite_public_key_t(std::vector<uint8_t>(pgp_kyber_ecc_composite_public_key_t::encoded_size(alg)), alg);
   return RNP_SUCCESS;
}

rnp_result_t kyber_ecc_validate_key(rnp::RNG *rng, const pgp_kyber_ecc_key_t *key, bool secret) {
    // TODOMTG: implement
    return RNP_SUCCESS;
}