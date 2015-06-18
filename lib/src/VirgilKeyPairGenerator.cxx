/**
 * Copyright (C) 2014 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <virgil/crypto/base/VirgilKeyPairGenerator.h>
using virgil::crypto::base::VirgilKeyPairGenerator;

#include <polarssl/pk.h>
#include <polarssl/ecp.h>
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#include <virgil/crypto/base/PolarsslException.h>
using virgil::crypto::base::PolarsslException;

/// @name Private functions
static ecp_group_id _ecKeyGroupToEcpGroupId(VirgilKeyPairGenerator::ECKeyGroup ecKey) {
    switch (ecKey) {
        case VirgilKeyPairGenerator::ECKeyGroup_DP_SECP192R1:
            return POLARSSL_ECP_DP_SECP192R1;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_SECP224R1:
            return POLARSSL_ECP_DP_SECP224R1;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_SECP256R1:
            return POLARSSL_ECP_DP_SECP256R1;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_SECP384R1:
            return POLARSSL_ECP_DP_SECP384R1;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_SECP521R1:
            return POLARSSL_ECP_DP_SECP521R1;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_BP256R1:
            return POLARSSL_ECP_DP_BP256R1;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_BP384R1:
            return POLARSSL_ECP_DP_BP384R1;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_BP512R1:
            return POLARSSL_ECP_DP_BP512R1;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_M221:
            return POLARSSL_ECP_DP_M221;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_M255:
            return POLARSSL_ECP_DP_M255;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_M383:
            return POLARSSL_ECP_DP_M383;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_M511:
            return POLARSSL_ECP_DP_M511;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_SECP192K1:
            return POLARSSL_ECP_DP_SECP192K1;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_SECP224K1:
            return POLARSSL_ECP_DP_SECP224K1;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_SECP256K1:
            return POLARSSL_ECP_DP_SECP256K1;
        case VirgilKeyPairGenerator::ECKeyGroup_DP_NONE:
        default:
            return POLARSSL_ECP_DP_NONE;
    }
}

/// @name Class implementation
VirgilKeyPairGenerator::VirgilKeyPairGenerator(VirgilKeyPairType type, size_t value): type_(type), value_(value) {
}

VirgilKeyPairGenerator VirgilKeyPairGenerator::rsa(size_t nbits) {
    return VirgilKeyPairGenerator(VirgilKeyPairType_RSA, nbits);
}

VirgilKeyPairGenerator VirgilKeyPairGenerator::ec(ECKeyGroup ecKeyGroup) {
    return VirgilKeyPairGenerator(VirgilKeyPairType_EC, static_cast<size_t>(ecKeyGroup));
}

VirgilKeyPairGenerator::VirgilKeyPairType VirgilKeyPairGenerator::type() const {
    return type_;
}

size_t VirgilKeyPairGenerator::rsaKeySize() const {
    if (type() == VirgilKeyPairType_RSA) {
        return value_;
    }
    return 0;
}

VirgilKeyPairGenerator::ECKeyGroup VirgilKeyPairGenerator::ecKeyGroup() const {
    if (type() == VirgilKeyPairType_EC) {
        return static_cast<ECKeyGroup>(value_);
    }
    return ECKeyGroup_DP_NONE;
}

void VirgilKeyPairGenerator::generate(void *ctx) const {
    const char *pers = "gen_keypair";
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    int result = 0;
    pk_context *pk_ctx = (pk_context *)ctx;

    ::entropy_init(&entropy);

    result = ::ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

    switch (::pk_get_type(pk_ctx)) {
#if defined(POLARSSL_RSA_C)
    case POLARSSL_PK_RSA:
        result = ::rsa_gen_key(pk_rsa(*pk_ctx), ctr_drbg_random, &ctr_drbg, rsaKeySize(), 65537);
        break;
#endif /* POLARSSL_RSA_C */
#if defined(POLARSSL_ECP_C)
    case POLARSSL_PK_ECKEY:
        result = ::ecp_gen_key(_ecKeyGroupToEcpGroupId(ecKeyGroup()), pk_ec(*pk_ctx), ctr_drbg_random, &ctr_drbg);
        break;
#endif /* POLARSSL_ECP_C */
    default:
        // Do nothing - unknown PK type.
        break;
    }

    ::entropy_free(&entropy);
    POLARSSL_ERROR_HANDLER(result);

}

