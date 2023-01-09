
#include "config.h"
#include "hkdf.hpp"

#if defined(CRYPTO_BACKEND_BOTAN)
#include "hkdf_botan.hpp"
#endif
#if defined(CRYPTO_BACKEND_OPENSSL)
#error HKDF not implemented for OpenSSL Backend
#endif

namespace rnp {
std::unique_ptr<Hkdf>
Hkdf::create(pgp_hash_alg_t alg)
{
#if defined(CRYPTO_BACKEND_OPENSSL)
#error HKDF not implemented for OpenSSL
    // return Hash_OpenSSL::create(alg);
#elif defined(CRYPTO_BACKEND_BOTAN)
    return Hkdf_Botan::create(alg);
#else
#error "Crypto backend not specified"
#endif
}

size_t
Hkdf::size() const
{
    return size_;
}

Hkdf::~Hkdf()
{
}

} // namespace rnp
