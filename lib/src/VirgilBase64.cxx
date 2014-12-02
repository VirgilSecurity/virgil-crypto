#include <virgil/crypto/VirgilBase64.h>
using virgil::crypto::VirgilBase64;

#include <string>
using std::string;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/crypto/PolarsslException.h>

#include <polarssl/base64.h>

string VirgilBase64::encode(const VirgilByteArray& data) {
    if (data.empty()) {
        return string();
    }
    // Define output length
    size_t bufLen = 0;
    ::base64_encode(NULL, &bufLen, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(data));
    // Encode
    unsigned char *buf = new unsigned char[bufLen];
    ::base64_encode(buf, &bufLen, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(data));
    // Return result
    string result(reinterpret_cast<const char *>(buf), bufLen);
    delete[] buf;
    return result;
}

VirgilByteArray VirgilBase64::decode(const string& base64str) {
    if (base64str.empty()) {
        return VirgilByteArray();
    }
    // Define output length
    size_t bufLen = 0;
    ::base64_decode(NULL, &bufLen, reinterpret_cast<const unsigned char *>(base64str.data()), base64str.size());
    // Decode
    unsigned char *buf = new unsigned char[bufLen];
    ::base64_decode(buf, &bufLen, reinterpret_cast<const unsigned char *>(base64str.data()), base64str.size());
    // Return result
    VirgilByteArray result = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(buf, bufLen);
    delete[] buf;
    return result;
}
