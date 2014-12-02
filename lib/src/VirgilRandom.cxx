#include <virgil/crypto/VirgilRandom.h>
using virgil::crypto::VirgilRandom;

#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/crypto/PolarsslException.h>
using virgil::crypto::PolarsslException;

namespace virgil { namespace crypto {

class VirgilRandomImpl {
public:
    ctr_drbg_context ctr_drbg;
    entropy_context entropy;
};

}}

VirgilRandom::VirgilRandom(const VirgilByteArray& personalInfo) : impl_(new VirgilRandomImpl()) {
    entropy_init(&impl_->entropy);

    POLARSSL_ERROR_HANDLER_DISPOSE(
        ::ctr_drbg_init(&impl_->ctr_drbg, entropy_func, &impl_->entropy,
                VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(personalInfo)),
        {
            ::entropy_free(&impl_->entropy);
            delete impl_;
        }
    );
}

VirgilByteArray VirgilRandom::randomize(size_t bytesNum) {
    unsigned char * buf = new unsigned char[bytesNum];

    POLARSSL_ERROR_HANDLER_DISPOSE(
        ::ctr_drbg_random(&impl_->ctr_drbg, buf, bytesNum),
        {
            delete[] buf;
        }
    );

    VirgilByteArray randomBytes =  VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(buf, bytesNum);
    delete[] buf;
    return randomBytes;
}

VirgilRandom::~VirgilRandom() throw() {
    ::ctr_drbg_free(&impl_->ctr_drbg);
    ::entropy_free(&impl_->entropy);
    delete impl_;
}

