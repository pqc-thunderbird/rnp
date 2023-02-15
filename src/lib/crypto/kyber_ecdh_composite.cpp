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

#include "kyber_ecdh_composite.h"
#include "logging.h"
#include "types.h"
#include "ecdh_utils.h"
#include <botan/ffi.h>

pgp_kyber_ecdh_composite_key_t::~pgp_kyber_ecdh_composite_key_t() {}

void
pgp_kyber_ecdh_composite_key_t::initialized_or_throw() const {
    if(!is_initialized()) {
        RNP_LOG("Trying to use uninitialized kyber-ecdh key");
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);  /* TODO better return error */
    }
}

rnp_result_t
pgp_kyber_ecdh_composite_key_t::gen_keypair(rnp::RNG *rng, pgp_kyber_ecdh_key_t *key, pgp_pubkey_alg_t alg) 
{
    rnp_result_t res;
    pgp_curve_t curve = pk_alg_to_curve_id(alg);
    kyber_parameter_e kyber_id = pk_alg_to_kyber_id(alg);

    ecdh_kem_key_t ecdh_key_pair;

    res = generate_ecdh_kem_key_pair(rng, &ecdh_key_pair, curve);
    if(res != RNP_SUCCESS) {
        RNP_LOG("generating kyber ecdh composite key failed when generating ecdh key");
        return res;
    }

    auto kyber_key_pair = kyber_generate_keypair(kyber_id);

    key->priv = pgp_kyber_ecdh_composite_private_key_t(ecdh_key_pair.priv.get_encoded(), kyber_key_pair.second.get_encoded(), alg);
    key->pub = pgp_kyber_ecdh_composite_public_key_t(ecdh_key_pair.pub.get_encoded(), kyber_key_pair.first.get_encoded(), alg);

    return RNP_SUCCESS;
}

size_t
pgp_kyber_ecdh_composite_key_t::ecdh_curve_privkey_size(pgp_curve_t curve) {
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
pgp_kyber_ecdh_composite_key_t::ecdh_curve_pubkey_size(pgp_curve_t curve) {
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
pgp_kyber_ecdh_composite_key_t::ecdh_curve_ephemeral_size(pgp_curve_t curve) {
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
pgp_kyber_ecdh_composite_key_t::ecdh_curve_keyshare_size(pgp_curve_t curve) {
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
pgp_kyber_ecdh_composite_key_t::pk_alg_to_kyber_id(pgp_pubkey_alg_t pk_alg) {
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
pgp_kyber_ecdh_composite_key_t::pk_alg_to_curve_id(pgp_pubkey_alg_t pk_alg) {
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
    /* TODO: replace with real functionality */
    std::vector<uint8_t> dummy_kmac_kdf(std::vector<uint8_t> key1, std::vector<uint8_t> key2) {
        std::vector<uint8_t> out(32);
        for (int i = 0; i < 32; i++)
        {
            out.data()[i] = key1.data()[i] ^ key2.data()[i];
        }
        return out;
    }
}


/* copy assignment operator is used on key materials struct and thus needs to be defined for this class as well */
pgp_kyber_ecdh_composite_private_key_t& pgp_kyber_ecdh_composite_private_key_t::operator=(const pgp_kyber_ecdh_composite_private_key_t& other)
{
    pgp_kyber_ecdh_composite_key_t::operator=(other);
    pk_alg_ = other.pk_alg_,
    kyber_key = other.kyber_key;
    ecdh_key = other.ecdh_key;
    
    return *this;
}

/* copy assignment operator is used on materials struct and thus needs to be defined for this class as well */
pgp_kyber_ecdh_composite_public_key_t& pgp_kyber_ecdh_composite_public_key_t::operator=(const pgp_kyber_ecdh_composite_public_key_t& other)
{
    pgp_kyber_ecdh_composite_key_t::operator=(other);
    pk_alg_ = other.pk_alg_,
    kyber_key = other.kyber_key;
    ecdh_key = other.ecdh_key;
    
    return *this;
}


pgp_kyber_ecdh_composite_private_key_t::pgp_kyber_ecdh_composite_private_key_t(const uint8_t *key_encoded, size_t key_encoded_len, pgp_pubkey_alg_t pk_alg):
    pk_alg_(pk_alg)
{
    kyber_key_from_encoded(std::vector<uint8_t>(key_encoded, key_encoded + key_encoded_len));
    ecdh_key_from_encoded(std::vector<uint8_t>(key_encoded, key_encoded + key_encoded_len));
}

pgp_kyber_ecdh_composite_private_key_t::pgp_kyber_ecdh_composite_private_key_t(std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t pk_alg):
    pk_alg_(pk_alg)
{
    kyber_key_from_encoded(key_encoded);
    ecdh_key_from_encoded(key_encoded);
}

pgp_kyber_ecdh_composite_private_key_t::pgp_kyber_ecdh_composite_private_key_t(std::vector<uint8_t> const &ecdh_key_encoded, std::vector<uint8_t> const &kyber_key_encoded, pgp_pubkey_alg_t pk_alg)
    : pk_alg_(pk_alg),
      kyber_key(kyber_key_encoded, pk_alg_to_kyber_id(pk_alg)),
      ecdh_key(ecdh_key_encoded, pk_alg_to_curve_id(pk_alg))
{
    if(ecdh_curve_privkey_size(pk_alg_to_curve_id(pk_alg)) != ecdh_key_encoded.size()
        || kyber_privkey_size(pk_alg_to_kyber_id(pk_alg)) != kyber_key_encoded.size())
    {
        RNP_LOG("ecdh or kyber key length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }
    is_kyber_initialized_ = true;
    is_ecc_initialized_ = true;
}


size_t
pgp_kyber_ecdh_composite_private_key_t::encoded_size(pgp_pubkey_alg_t pk_alg)
{
  kyber_parameter_e kyber_param = pk_alg_to_kyber_id(pk_alg);
  pgp_curve_t curve = pk_alg_to_curve_id(pk_alg);
  return ecdh_curve_privkey_size(curve) + kyber_privkey_size(kyber_param);
}

void 
pgp_kyber_ecdh_composite_private_key_t::kyber_key_from_encoded(std::vector<uint8_t> key_encoded) 
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
pgp_kyber_ecdh_composite_private_key_t::ecdh_key_from_encoded(std::vector<uint8_t> key_encoded) 
{
    if (key_encoded.size() != encoded_size(pk_alg_)) {
        RNP_LOG("Kyber composite key format invalid: length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }

    // make private key from first part of the composite structure
    size_t len = ecdh_curve_privkey_size(pk_alg_to_curve_id(pk_alg_));
    ecdh_key = ecdh_kem_private_key_t(key_encoded.data(), len, pk_alg_to_curve_id(pk_alg_));
    is_ecc_initialized_ = true;
}


rnp_result_t
pgp_kyber_ecdh_composite_private_key_t::decrypt(uint8_t *out, size_t *out_len, const pgp_kyber_ecdh_encrypted_t *enc)
{
    initialized_or_throw();
    rnp_result_t res;
    std::vector<uint8_t> ecdh_keyshare;
    std::vector<uint8_t> kyber_keyshare;
    size_t padded_session_key_len = MAX_SESSION_KEY_SIZE;
    std::vector<uint8_t> padded_session_key(padded_session_key_len);

    // Compute (eccKeyShare) := eccKem.decap(eccCipherText, eccPrivateKey)
    pgp_curve_t curve = pk_alg_to_curve_id(pk_alg_);
    std::vector<uint8_t> ecdh_encapsulated_keyshare = std::vector<uint8_t>(enc->composite_ciphertext.data(), enc->composite_ciphertext.data() + ecdh_curve_ephemeral_size(curve));
    res = ecdh_key.decapsulate(ecdh_encapsulated_keyshare, ecdh_keyshare);
    if(res) {
        RNP_LOG("error when decrypting kyber-ecdh encrypted session key");
        return res;
    }
    
    // Compute (kyberKeyShare) := kyberKem.decap(kyberCipherText, kyberPrivateKey)
    std::vector<uint8_t> kyber_encapsulated_keyshare = std::vector<uint8_t>(enc->composite_ciphertext.begin() + ecdh_curve_ephemeral_size(curve), enc->composite_ciphertext.end());
    kyber_keyshare = kyber_key.decapsulate(kyber_encapsulated_keyshare.data(), kyber_encapsulated_keyshare.size());
    if(res) {
        RNP_LOG("error when decrypting kyber-ecdh encrypted session key");
        return res;
    }

    // Compute KEK := multiKeyCombine(eccKeyShare, kyberKeyShare, fixedInfo) as defined in Section 4.2.2
    std::vector<uint8_t> kek = dummy_kmac_kdf(ecdh_keyshare, kyber_keyshare); 

    // Compute sessionKey := AESKeyUnwrap(KEK, C) with AES-256 as per [RFC3394], aborting if the 64 bit integrity check fails
    if(botan_key_unwrap3394(enc->wrapped_sesskey.data(), enc->wrapped_sesskey.size(), kek.data(), kek.size(), padded_session_key.data(), &padded_session_key_len)) {
        RNP_LOG("error when unwrapping encrypted session key");
        return RNP_ERROR_DECRYPT_FAILED;
    }
    if (!unpad_pkcs7(padded_session_key.data(), padded_session_key_len, &padded_session_key_len)) {
        RNP_LOG("Failed to unpad key after unwrapping");
        return RNP_ERROR_DECRYPT_FAILED;
    }
    memcpy(out, padded_session_key.data(), padded_session_key_len);
    *out_len = padded_session_key_len;

    return RNP_SUCCESS;
}

void
pgp_kyber_ecdh_composite_private_key_t::secure_clear() {
    // TODOMTG: securely erase the data
    is_ecc_initialized_ = false;
    is_kyber_initialized_ = false;
}

std::vector<uint8_t>
pgp_kyber_ecdh_composite_private_key_t::get_encoded() const {
    initialized_or_throw();
    std::vector<uint8_t> result;
    std::vector<uint8_t> ecdh_key_encoded = ecdh_key.get_encoded();
    std::vector<uint8_t> kyber_key_encoded = kyber_key.get_encoded();

    result.insert(result.end(), std::begin(ecdh_key_encoded), std::end(ecdh_key_encoded));
    result.insert(result.end(), std::begin(kyber_key_encoded), std::end(kyber_key_encoded));
    return result;
};


pgp_kyber_ecdh_composite_public_key_t::pgp_kyber_ecdh_composite_public_key_t(const uint8_t *key_encoded, size_t key_encoded_len, pgp_pubkey_alg_t pk_alg):
    pk_alg_(pk_alg)
{
    kyber_key_from_encoded(std::vector<uint8_t>(key_encoded, key_encoded + key_encoded_len));
    ecdh_key_from_encoded(std::vector<uint8_t>(key_encoded, key_encoded + key_encoded_len));
}

pgp_kyber_ecdh_composite_public_key_t::pgp_kyber_ecdh_composite_public_key_t(std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t pk_alg):
    pk_alg_(pk_alg)
{
    kyber_key_from_encoded(key_encoded);
    ecdh_key_from_encoded(key_encoded);
}

pgp_kyber_ecdh_composite_public_key_t::pgp_kyber_ecdh_composite_public_key_t(std::vector<uint8_t> const &ecdh_key_encoded, std::vector<uint8_t> const &kyber_key_encoded, pgp_pubkey_alg_t pk_alg)
    : pk_alg_(pk_alg),
      kyber_key(kyber_key_encoded, pk_alg_to_kyber_id(pk_alg)),
      ecdh_key(ecdh_key_encoded, pk_alg_to_curve_id(pk_alg))
{
    if(ecdh_curve_pubkey_size(pk_alg_to_curve_id(pk_alg)) != ecdh_key_encoded.size()
        || kyber_pubkey_size(pk_alg_to_kyber_id(pk_alg)) != kyber_key_encoded.size())
    {
        RNP_LOG("ecdh or kyber key length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }
    is_kyber_initialized_ = true;
    is_ecc_initialized_ = true;
}

size_t
pgp_kyber_ecdh_composite_public_key_t::encoded_size(pgp_pubkey_alg_t pk_alg)
{
  kyber_parameter_e kyber_param = pk_alg_to_kyber_id(pk_alg);
  pgp_curve_t curve = pk_alg_to_curve_id(pk_alg);
  return ecdh_curve_pubkey_size(curve) + kyber_pubkey_size(kyber_param);
}

void 
pgp_kyber_ecdh_composite_public_key_t::kyber_key_from_encoded(std::vector<uint8_t> key_encoded) 
{
    if (key_encoded.size() != encoded_size(pk_alg_)) {
        RNP_LOG("Kyber composite key format invalid: length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }

    // make private key from second part of the composite structure
    size_t offset = ecdh_curve_pubkey_size(pk_alg_to_curve_id(pk_alg_));
    kyber_parameter_e param = pk_alg_to_kyber_id(pk_alg_);
    kyber_key = pgp_kyber_public_key_t(key_encoded.data() + offset, key_encoded.size() - offset, param);
    is_kyber_initialized_ = true;
}

void
pgp_kyber_ecdh_composite_public_key_t::ecdh_key_from_encoded(std::vector<uint8_t> key_encoded)
{
    if (key_encoded.size() != encoded_size(pk_alg_)) {
        RNP_LOG("Kyber composite key format invalid: length mismatch");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);  
    }

    // make private key from first part of the composite structure
    size_t len = ecdh_curve_pubkey_size(pk_alg_to_curve_id(pk_alg_));
    ecdh_key = ecdh_kem_public_key_t(key_encoded.data(), len, pk_alg_to_curve_id(pk_alg_));
    is_ecc_initialized_ = true;
}

rnp_result_t
pgp_kyber_ecdh_composite_public_key_t::encrypt(rnp::RNG *rng, pgp_kyber_ecdh_encrypted_t *out, const uint8_t *session_key, size_t session_key_len)
{
    initialized_or_throw();

    rnp_result_t res;
    ecdh_kem_encap_result_t ecdh_encap;

    const size_t padded_session_key_len = (session_key_len / 8 + 1) * 8;
    std::vector<uint8_t> padded_session_key(padded_session_key_len);
	
    // Compute (eccCipherText, eccKeyShare) := eccKem.encap(eccPublicKey)
    res = ecdh_key.encapsulate(rng, &ecdh_encap);
    if(res) {
        RNP_LOG("error when encapsulating with ECDH");
        return res;
    }

    // Compute (kyberCipherText, kyberKeyShare) := kyberKem.encap(kyberPublicKey)
    kyber_encap_result_t kyber_encap = kyber_key.encapsulate();

    // Compute KEK := multiKeyCombine(eccKeyShare, kyberKeyShare, fixedInfo) as defined in Section 4.2.2
    std::vector<uint8_t> kek = dummy_kmac_kdf(ecdh_encap.symmetric_key, kyber_encap.symmetric_key); 

    // Compute C := AESKeyWrap(KEK, sessionKey) with AES-256 as per [RFC3394] that includes a 64 bit integrity check
    size_t c_len = ((padded_session_key_len + 7)/8 + 1) * 8; // RFC3394 "Outputs:     Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}."
    out->wrapped_sesskey.resize(c_len);

    memcpy(padded_session_key.data(), session_key, session_key_len);
    if (!pad_pkcs7(padded_session_key.data(), padded_session_key_len, session_key_len)) {
        RNP_LOG("error when doing padding session key for key wrap");
        return RNP_ERROR_ENCRYPT_FAILED;
    }
    if (botan_key_wrap3394(padded_session_key.data(), padded_session_key_len, kek.data(), kek.size(), out->wrapped_sesskey.data(), &c_len)) {
        RNP_LOG("error when doing AES key wrap");
        return RNP_ERROR_ENCRYPT_FAILED;
    }
    
    out->composite_ciphertext.assign(ecdh_encap.ciphertext.data(), ecdh_encap.ciphertext.data() + ecdh_encap.ciphertext.size());
    out->composite_ciphertext.insert(out->composite_ciphertext.end(), kyber_encap.ciphertext.begin(), kyber_encap.ciphertext.end());
    return RNP_SUCCESS;
}

std::vector<uint8_t>
pgp_kyber_ecdh_composite_public_key_t::get_encoded() const {
    initialized_or_throw();
    std::vector<uint8_t> result;
    std::vector<uint8_t> ecdh_key_encoded = ecdh_key.get_encoded();
    std::vector<uint8_t> kyber_key_encoded = kyber_key.get_encoded();

    result.insert(result.end(), std::begin(ecdh_key_encoded), std::end(ecdh_key_encoded));
    result.insert(result.end(), std::begin(kyber_key_encoded), std::end(kyber_key_encoded));
    return result;
};

rnp_result_t kyber_ecdh_validate_key(rnp::RNG *rng, const pgp_kyber_ecdh_key_t *key, bool secret) {
    // TODOMTG: implement as member of pgp_kyber_ecdh_composite_public_key_t and pgp_kyber_ecdh_composite_private_key_t
    return RNP_SUCCESS;
}