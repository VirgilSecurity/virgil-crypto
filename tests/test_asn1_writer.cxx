/**
 * Copyright (C) 2015 Virgil Security Inc.
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

/**
 * @file test_asn1_writer.cxx
 * @brief Covers class VirgilAsn1Writer
 */

#include "catch.hpp"

#include <string>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilCryptoException.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilCryptoException;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

const size_t kAsn1LengthMax = 65535; // According to MbedTLS restriction on TAG: LENGTH
const size_t kAsn1SizeMax = kAsn1LengthMax + 1 + 3;

TEST_CASE("ASN.1 write: use small buffer", "[asn1-writer]") {
    VirgilAsn1Writer asn1Writer(1);

    SECTION ("with big integer positive") {
        int number = 0x7fffffff;
        asn1Writer.writeInteger(number);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == "02047fffffff");
    }

    SECTION ("with big integer negative") {
        int number = -0x7fffffff;
        asn1Writer.writeInteger(number);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == "020480000001");
    }

    SECTION ("with bool true") {
        asn1Writer.writeBool(true);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == "0101ff");
    }

    SECTION ("with bool false") {
        asn1Writer.writeBool(false);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == "010100");
    }

    SECTION ("with NULL") {
        asn1Writer.writeNull();
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == "0500");
    }

    SECTION ("with octet string") {
        asn1Writer.writeOctetString(VirgilByteArrayUtils::hexToBytes("112233445566778899aabbccddeeff"));
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == "040f112233445566778899aabbccddeeff");
    }

    SECTION ("with max octet string") {
        VirgilByteArray octetString = VirgilByteArray(kAsn1LengthMax, 0xAB);
        VirgilByteArray asn1Expected = VirgilByteArrayUtils::hexToBytes("0482ffff");
        asn1Expected.insert(asn1Expected.end(), octetString.begin(), octetString.end());
        asn1Writer.writeOctetString(octetString);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == VirgilByteArrayUtils::bytesToHex(asn1Expected));
    }

    SECTION ("with UTF8 string") {
        asn1Writer.writeUTF8String(VirgilByteArrayUtils::hexToBytes("4142434445464748494a4b4c4d4e4f"));
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == "0c0f4142434445464748494a4b4c4d4e4f");
    }

    SECTION ("with max UTF8 string") {
        VirgilByteArray utf8String = VirgilByteArray(kAsn1LengthMax, 0x41);
        VirgilByteArray asn1Expected = VirgilByteArrayUtils::hexToBytes("0c82ffff");
        asn1Expected.insert(asn1Expected.end(), utf8String.begin(), utf8String.end());
        asn1Writer.writeUTF8String(utf8String);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == VirgilByteArrayUtils::bytesToHex(asn1Expected));
    }

    SECTION ("with oversized UTF8 string") {
        VirgilByteArray utf8String = VirgilByteArray(kAsn1SizeMax + 1, 0x41);
        REQUIRE_THROWS(asn1Writer.writeUTF8String(utf8String));
    }

    SECTION ("with context tag over UTF8 string") {
        size_t len = asn1Writer.writeUTF8String(VirgilByteArrayUtils::hexToBytes("4142434445464748494a4b4c4d4e4f"));
        asn1Writer.writeContextTag(1, len);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == "a1110c0f4142434445464748494a4b4c4d4e4f");
    }

    SECTION ("with corrupted context tag") {
        REQUIRE_THROWS(asn1Writer.writeContextTag(31, 0));
    }

    SECTION ("with max RAW buffer") {
        VirgilByteArray data = VirgilByteArray(kAsn1SizeMax, 0x41);
        asn1Writer.writeData(data);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == VirgilByteArrayUtils::bytesToHex(data));
    }

    SECTION ("with oversized RAW buffer") {
        VirgilByteArray data = VirgilByteArray(kAsn1SizeMax + 1, 0x41);
        REQUIRE_THROWS(asn1Writer.writeData(data));
    }

    SECTION ("with OID") {
        std::string oid =
                VirgilByteArrayUtils::bytesToString(VirgilByteArrayUtils::hexToBytes("4142434445464748494a4b4c4d4e4f"));
        asn1Writer.writeOID(oid);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == "060f4142434445464748494a4b4c4d4e4f");
    }

    SECTION ("with max OID") {
        std::string oid = VirgilByteArrayUtils::bytesToString(VirgilByteArray(kAsn1LengthMax, 0x41));
        VirgilByteArray asn1Expected = VirgilByteArrayUtils::hexToBytes("0682ffff");
        asn1Expected.insert(asn1Expected.end(), oid.begin(), oid.end());
        asn1Writer.writeOID(oid);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == VirgilByteArrayUtils::bytesToHex(asn1Expected));
    }

    SECTION ("with oversized OID") {
        std::string oid = VirgilByteArrayUtils::bytesToString(VirgilByteArray(kAsn1SizeMax + 1, 0x41));
        REQUIRE_THROWS(asn1Writer.writeOID(oid));
    }

    SECTION ("with sequence over UTF8 string") {
        size_t len = asn1Writer.writeUTF8String(VirgilByteArrayUtils::hexToBytes("4142434445464748494a4b4c4d4e4f"));
        asn1Writer.writeSequence(len);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == "30110c0f4142434445464748494a4b4c4d4e4f");
    }

    SECTION("with set") {
        std::vector<VirgilByteArray> set;
        for (size_t i = 0; i < 5; ++i) {
            set.push_back(VirgilByteArrayUtils::hexToBytes("30110c0f4142434445464748494a4b4c4d4e4f"));
        }
        asn1Writer.writeSet(set);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) ==
            "315f"
            "30110c0f4142434445464748494a4b4c4d4e4f"
            "30110c0f4142434445464748494a4b4c4d4e4f"
            "30110c0f4142434445464748494a4b4c4d4e4f"
            "30110c0f4142434445464748494a4b4c4d4e4f"
            "30110c0f4142434445464748494a4b4c4d4e4f"
        );
    }

    SECTION("with max set") {
        VirgilByteArray utf8StringHead = VirgilByteArrayUtils::hexToBytes("0c82fffb");
        VirgilByteArray utf8StringBody = VirgilByteArray(kAsn1LengthMax - utf8StringHead.size(), 0x41);
        VirgilByteArray utf8String;
        utf8String.insert(utf8String.end(), utf8StringHead.begin(), utf8StringHead.end());
        utf8String.insert(utf8String.end(), utf8StringBody.begin(), utf8StringBody.end());

        VirgilByteArray asn1Expected = VirgilByteArrayUtils::hexToBytes("3182ffff");
        asn1Expected.insert(asn1Expected.end(), utf8String.begin(), utf8String.end());

        std::vector<VirgilByteArray> set;
        set.push_back(utf8String);

        asn1Writer.writeSet(set);
        VirgilByteArray asn1 = asn1Writer.finish();
        REQUIRE(VirgilByteArrayUtils::bytesToHex(asn1) == VirgilByteArrayUtils::bytesToHex(asn1Expected));
    }
}

TEST_CASE("ASN.1 write: check overflows ", "[asn1-writer]") {
    VirgilAsn1Writer asn1Writer;

    VirgilByteArray data(kAsn1SizeMax);
    asn1Writer.writeData(data);

    SECTION("with integer") {
        REQUIRE_THROWS(asn1Writer.writeInteger(1));
    }

    SECTION("with bool") {
        REQUIRE_THROWS(asn1Writer.writeBool(true));
    }

    SECTION("with NULL") {
        REQUIRE_THROWS(asn1Writer.writeNull());
    }

    SECTION("with octet string") {
        REQUIRE_THROWS(asn1Writer.writeOctetString(VirgilByteArray(1, 0xff)));
    }

    SECTION("with UTF8 string") {
        REQUIRE_THROWS(asn1Writer.writeUTF8String(VirgilByteArray(1, 0x41)));
    }

    SECTION("with context tag") {
        REQUIRE_THROWS(asn1Writer.writeContextTag(1, data.size()));
    }

    SECTION("with RAW buffer") {
        REQUIRE_THROWS(asn1Writer.writeData(VirgilByteArray(1, 0xff)));
    }

    SECTION("with OID") {
        REQUIRE_THROWS(asn1Writer.writeOID(std::string("\x2A")));
    }

    SECTION("with sequence") {
        REQUIRE_THROWS(asn1Writer.writeSequence(data.size()));
    }

    SECTION("with set") {
        std::vector<VirgilByteArray> set;
        set.push_back(VirgilByteArrayUtils::hexToBytes("0500"));
        REQUIRE_THROWS(asn1Writer.writeSet(set));
    }
}

TEST_CASE("ASN.1 write: check step by step ASN.1 buffer grows", "[asn1-writer]") {
    VirgilAsn1Writer asn1Writer(1);
    size_t len = 0;
    REQUIRE_THROWS(for(;;) { len += asn1Writer.writeSequence(len); });
}
