#include <virgil/crypto/VirgilAsn1Writer.h>
using virgil::crypto::VirgilAsn1Writer;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/crypto/PolarsslException.h>
#include <virgil/crypto/VirgilCryptoException.h>
using virgil::crypto::VirgilCryptoException;

#include <cstddef>
#include <cstring>
#include <polarssl/asn1write.h>

static const size_t kBufLenDefault = 2048;

static const size_t kAsn1TagValueSize = 1;
static const size_t kAsn1LengthValueSize = 2;
static const size_t kAsn1IntegerValueSize = kAsn1TagValueSize + kAsn1LengthValueSize + 8;

#define RETURN_POINTER_DIFF_AFTER_INVOCATION(pointer,invocation) \
do { \
    unsigned char *before = pointer; \
    invocation; \
    unsigned char *after = pointer; \
    return (ptrdiff_t)(before - after); \
} while(0);

VirgilAsn1Writer::VirgilAsn1Writer() : p_(0), start_(0), buf_(0), bufLen_(0) {
    this->reset();
}

VirgilAsn1Writer::~VirgilAsn1Writer() throw() {
    dispose();
}

void VirgilAsn1Writer::reset() {
    dispose();
    relocateBuffer(kBufLenDefault);
}

VirgilByteArray VirgilAsn1Writer::finish() {
    checkState();
    VirgilByteArray result = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(p_, bufLen_ - (p_ - start_));
    dispose();
    return result;
}

size_t VirgilAsn1Writer::writeInteger(int value) {
    checkState();
    ensureBufferEnough(kAsn1IntegerValueSize);
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
        POLARSSL_ERROR_HANDLER(
            ::asn1_write_int(&p_, start_, value)
        )
    );
}

size_t VirgilAsn1Writer::writeOctetString(const VirgilByteArray& data) {
    checkState();
    ensureBufferEnough(kAsn1TagValueSize + kAsn1LengthValueSize + data.size());
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
        POLARSSL_ERROR_HANDLER(
            ::asn1_write_octet_string(&p_, start_, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(data))
        )
    );
}

size_t VirgilAsn1Writer::writeUTF8String(const VirgilByteArray& data) {
    checkState();
    ensureBufferEnough(kAsn1TagValueSize + kAsn1LengthValueSize + data.size());
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
        {
            POLARSSL_ERROR_HANDLER(
                ::asn1_write_raw_buffer(&p_, start_, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(data))
            );
            POLARSSL_ERROR_HANDLER(
                ::asn1_write_len(&p_, start_, data.size())
            );
            POLARSSL_ERROR_HANDLER(
                ::asn1_write_tag(&p_, start_, ASN1_UTF8_STRING)
            );
        }
    );
}

size_t VirgilAsn1Writer::writeContextTag(unsigned char tag, size_t len) {
    if (tag > 0x1F) {
        throw VirgilCryptoException("Tag value is too big, MAX value is 31.");
    }
    checkState();
    ensureBufferEnough(kAsn1TagValueSize);
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
        {
            POLARSSL_ERROR_HANDLER(
                ::asn1_write_len(&p_, start_, len)
            );
            POLARSSL_ERROR_HANDLER(
                ::asn1_write_tag(&p_, start_, ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | tag);
            );
        }
    );
}

size_t VirgilAsn1Writer::writeSequence(size_t len) {
    checkState();
    ensureBufferEnough(kAsn1TagValueSize + kAsn1LengthValueSize);
    RETURN_POINTER_DIFF_AFTER_INVOCATION(p_,
        {
            POLARSSL_ERROR_HANDLER(
                ::asn1_write_len(&p_, start_, len)
            );
            POLARSSL_ERROR_HANDLER(
                ::asn1_write_tag(&p_, start_, ASN1_CONSTRUCTED | ASN1_SEQUENCE)
            );
        }
    );
}

void VirgilAsn1Writer::checkState() {
    if (p_ == 0 || start_ == 0) {
        throw VirgilCryptoException("Writer was not initialized - 'reset' method was not called.");
    }
}

void VirgilAsn1Writer::relocateBuffer(size_t newBufLen) {
    if (newBufLen < bufLen_) {
        throw VirgilCryptoException("ASN.1 buffer relocation failed: could not reserve space less than current.");
    }
    unsigned char *newBuf = new unsigned char[newBufLen];
    size_t writtenBytes = 0;
    memset(newBuf, newBufLen, 0x00);
    if (buf_ && p_ && start_) {
        writtenBytes = bufLen_ - (p_ - start_);
        memcpy(newBuf + newBufLen - writtenBytes, p_, writtenBytes);
        delete buf_;
    }
    buf_ = newBuf;
    bufLen_ = newBufLen;
    p_ = buf_ + bufLen_ - writtenBytes;
    start_ = buf_;
}

void VirgilAsn1Writer::ensureBufferEnough(size_t len) {
    checkState();
    ptrdiff_t unusedSpace = (p_ - start_);
    if (unusedSpace < (ptrdiff_t)len) {
        ptrdiff_t usedSpace = (start_ + bufLen_ - p_);
        size_t newBufLen = bufLen_;
        do {
            newBufLen <<= 1;
        } while ((int)newBufLen - (int)usedSpace - (int)len < 0);
        relocateBuffer(newBufLen);
    }
}

void VirgilAsn1Writer::dispose() throw() {
    p_ = 0;
    start_ = 0;
    bufLen_ = 0;
    if (buf_) {
        delete buf_;
        buf_ = 0;
    }
}

