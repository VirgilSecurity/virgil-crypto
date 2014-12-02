#include <virgil/crypto/VirgilAsn1Reader.h>
using virgil::crypto::VirgilAsn1Reader;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/crypto/PolarsslException.h>
#include <virgil/VirgilException.h>
using virgil::VirgilException;

#include <cstddef>
#include <polarssl/asn1.h>

VirgilAsn1Reader::VirgilAsn1Reader() : p_(0), end_(0), data_() {
}

VirgilAsn1Reader::VirgilAsn1Reader(const VirgilByteArray& data) :p_(0), end_(0), data_() {
    this->reset(data);
}

VirgilAsn1Reader::~VirgilAsn1Reader() throw() {
    p_ = 0;
    end_ = 0;
}

void VirgilAsn1Reader::reset(const VirgilByteArray& data) {
    data_ = data;
    p_ = const_cast<unsigned char *>(data_.data());
    end_ = p_ + data_.size();
}

size_t VirgilAsn1Reader::readSequence() {
    checkState();
    size_t len;
    POLARSSL_ERROR_HANDLER(
        ::asn1_get_tag(&p_, end_, &len, ASN1_CONSTRUCTED | ASN1_SEQUENCE)
    );
    return len;
}

int VirgilAsn1Reader::readInteger() {
    checkState();
    int result;
    POLARSSL_ERROR_HANDLER(
        ::asn1_get_int(&p_, end_, &result);
    );
    return result;
}

size_t VirgilAsn1Reader::readContextTag(unsigned char tag) {
    if (tag > 0x1F) {
        throw VirgilCryptoException("Tag value is too big, MAX value is 31.");
    }
    checkState();
    size_t len;
    int result = ::asn1_get_tag(&p_, end_, &len, ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | tag);
    if (result == 0) {
        return len;
    } else if (result == POLARSSL_ERR_ASN1_UNEXPECTED_TAG) {
        return 0;
    } else {
        throw PolarsslException(result);
    }
}

VirgilByteArray VirgilAsn1Reader::readOctetString() {
    checkState();
    size_t len;
    POLARSSL_ERROR_HANDLER(
        ::asn1_get_tag(&p_, end_, &len, ASN1_OCTET_STRING)
    );
    p_ += len;
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(p_ - len, len);
}

VirgilByteArray VirgilAsn1Reader::readUTF8String() {
    checkState();
    size_t len;
    POLARSSL_ERROR_HANDLER(
        ::asn1_get_tag(&p_, end_, &len, ASN1_UTF8_STRING)
    );
    p_ += len;
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(p_ - len, len);
}

void VirgilAsn1Reader::checkState() {
    if (p_ == 0 || end_ == 0) {
        throw VirgilException("Reader was not initialized - 'reset' method was not called.");
    }
    if (p_ >= end_) {
        throw VirgilException("ASN.1 structure was totally read, so no data left to be processed.");
    }
}


