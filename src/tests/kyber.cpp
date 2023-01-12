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
#include "crypto/kyber.h"

TEST_F(rnp_tests, test_kyber_key_function)
{
    kyber_parameter_e params[2] = {kyber_768, kyber_1024};
    for(kyber_parameter_e param : params)
    {

    auto public_and_private_key = kyber_generate_keypair(param);

    kem_encap_result_t encap_res = public_and_private_key.first.encapsulate();
    
    std::vector<uint8_t> decrypted = public_and_private_key.second.decapsulate(encap_res.ciphertext.data(), encap_res.ciphertext.size());
    assert_int_equal(encap_res.symmetric_key.size(), decrypted.size());
    assert_memory_equal(encap_res.symmetric_key.data(), decrypted.data(), decrypted.size());

    }

}
