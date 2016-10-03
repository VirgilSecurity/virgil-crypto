/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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

#include <virgil/crypto/foundation/cms/VirgilCMSContentInfo.h>

#include <mbedtls/asn1.h>

#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::cms::VirgilCMSContentInfo;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

/**
 * @name ASN.1 Constants
 */
///@{
static const unsigned char kAsn1_CustomParamsTag = 0;
static const int kAsn1_ContentInfoVersion = 0;
///@}

size_t VirgilCMSContentInfo::defineSize(const VirgilByteArray& data) {
    if (data.empty()) {
        return 0;
    }
    VirgilByteArray::const_pointer p_begin = data.data();
    VirgilByteArray::const_pointer p_end = p_begin + data.size();
    VirgilByteArray::pointer p = const_cast<VirgilByteArray::pointer>(p_begin);
    // Validate TAG
    if (*p != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return 0;
    }
    ++p;
    // Read length
    size_t size = 0;
    int result = mbedtls_asn1_get_len(&p, p_end, &size);
    if (result == 0 || result == MBEDTLS_ERR_ASN1_OUT_OF_DATA) {
        size += p - p_begin;
    } else {
        return 0;
    }
    // Validate ContentInfo version
    int version = 0;
    result = mbedtls_asn1_get_int(&p, p_end, &version);
    if (result != 0 || version != kAsn1_ContentInfoVersion) {
        return 0;
    }
    return size;
}

size_t VirgilCMSContentInfo::asn1Write(VirgilAsn1Writer& asn1Writer, size_t childWrittenBytes) const {
    size_t len = 0;
    if (!customParams.isEmpty()) {
        len += customParams.asn1Write(asn1Writer);
        len += asn1Writer.writeContextTag(kAsn1_CustomParamsTag, len);
    }

    len += cmsContent.asn1Write(asn1Writer);
    len += asn1Writer.writeInteger(kAsn1_ContentInfoVersion);
    len += asn1Writer.writeSequence(len);

    return len + childWrittenBytes;
}

void VirgilCMSContentInfo::asn1Read(VirgilAsn1Reader& asn1Reader) {
    (void) asn1Reader.readSequence();
    const int version = asn1Reader.readInteger();
    if (version != kAsn1_ContentInfoVersion) {
        throw make_error(VirgilCryptoError::UnsupportedAlgorithm, "Unsupported version of CMS Content Info.");
    }
    cmsContent.asn1Read(asn1Reader);
    if (asn1Reader.readContextTag(kAsn1_CustomParamsTag) > 0) {
        customParams.asn1Read(asn1Reader);
    }
}
