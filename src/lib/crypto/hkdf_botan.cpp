/*
 * Copyright (c) 2022 MTG AG
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

#include "hkdf_botan.hpp"
#include "hash_botan.hpp"

namespace rnp {

Hkdf_Botan::Hkdf_Botan(pgp_hash_alg_t hash_alg) : Hkdf(hash_alg)
{
}

std::unique_ptr<Hkdf_Botan>
Hkdf_Botan::create(pgp_hash_alg_t alg)
{
    return std::unique_ptr<Hkdf_Botan>(new Hkdf_Botan(alg));
}


std::string Hkdf_Botan::alg() const
{
    return std::string("HMAC(") + Hash_Botan::name_backend(Hkdf::alg()) + ")";
}

void
Hkdf_Botan::extract_expand(const uint8_t *salt,
                           size_t         salt_len,
                           const uint8_t *ikm,
                           size_t         ikm_len,
                           const uint8_t *info,
                           size_t         info_len,
                           uint8_t *      output_buf,
                           size_t         output_length)
{
    if (output_length > size() * 255) {
        throw rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    std::vector<uint8_t> salt_vec(salt, salt+salt_len);
    std::vector<uint8_t> ikm_vec(ikm, ikm+ikm_len);
    std::vector<uint8_t> info_vec(info, info+info_len);

    Botan::secure_vector<uint8_t> PRK = extract(salt_vec, ikm_vec);
    std::vector<uint8_t>          OKM = expand(PRK, info_vec, output_length);

    memcpy(output_buf, OKM.data(), output_length);
}

Botan::secure_vector<uint8_t>
Hkdf_Botan::extract(std::vector<uint8_t> salt,
                    std::vector<uint8_t> ikm)
{
    /* rfc5869: PRK = HMAC-Hash(salt, IKM) */
    auto hmac = Botan::MessageAuthenticationCode::create_or_throw(alg()); // Hash_Botan::name_backend(alg())
    hmac->set_key(salt);
    hmac->update(ikm);
    return hmac->final();
}

std::vector<uint8_t>
Hkdf_Botan::expand(Botan::secure_vector<uint8_t> PRK,
                   std::vector<uint8_t>          info,
                   size_t                        output_length)
{
    /* N = ceil(L/HashLen) */
    size_t N = output_length / size() + (output_length % size() != 0);

    /* T = T(1) | T(2) | T(3) | ... | T(N)

       where:
   T(0) = empty string (zero length)
   T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
   T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
   T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
   */
    std::vector<uint8_t> T;
    std::vector<uint8_t> T_i(0);    // initialize T_i as T(0) = empty string
    for(unsigned i = 0; i < N; i++)
    {
        /* T(i) = HMAC-Hash(PRK, T(i-1) | info | i)*/
        std::vector<uint8_t> hmac_input(T_i);
        std::copy(info.begin(), info.end(), std::back_inserter(hmac_input));
        hmac_input.push_back(i+1);
        auto hmac = Botan::MessageAuthenticationCode::create_or_throw(alg());
        hmac->set_key(PRK);
        hmac->update(hmac_input);
        T_i = Botan::unlock(hmac->final());

        /* append T(i) to T */
        std::copy(T_i.begin(), T_i.end(), std::back_inserter(T));
    }

    /* OKM = first L octets of T */
    T.resize(output_length);
    return T;
}


Hkdf_Botan::~Hkdf_Botan()
{
}

} // namespace rnp
