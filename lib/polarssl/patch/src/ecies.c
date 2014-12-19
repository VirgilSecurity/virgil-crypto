/**
 * Copyright (C) 2014 Virgil Security Inc.
 *
 * This file is part of extension to PolarSSL (http://www.polarssl.org)
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
 * Implementation is based on the standard ISO 18033-2.
 */

#include "polarssl/config.h"

#if defined(POLARSSL_ECIES_C)

#include "polarssl/ecies.h"

#include "polarssl/pk.h"
#include "polarssl/cipher.h"
#include "polarssl/ecdh.h"
#include "polarssl/md.h"
#include "polarssl/kdf1.h"

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#include <stdlib.h>
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

#ifdef POLARSSL_ECIES_DEBUG
#include <stdio.h>
#endif /* POLARSSL_ECIES_DEBUG */

#define ECIES_CHECK_RESULT(result) if((result) < 0) goto exit;

#define ECIES_OCTET_SIZE 8
#define ECIES_SIZE_TO_OCTETS(size) ((size + 7) / ECIES_OCTET_SIZE)

#define ECIES_HMAC_SIZE 256
#define ECIES_HMAC_LEN ECIES_SIZE_TO_OCTETS(ECIES_HMAC_SIZE)

#define ECIES_ENC_SIZE 256
#define ECIES_ENC_LEN ECIES_SIZE_TO_OCTETS(ECIES_ENC_SIZE)

#define ECIES_IV_SIZE 128
#define ECIES_IV_LEN ECIES_SIZE_TO_OCTETS(ECIES_IV_SIZE)

#define ECIES_KDF_LEN (ECIES_HMAC_LEN + ECIES_ENC_LEN + ECIES_IV_LEN)

#define ECIES_CIPHER_PADDING POLARSSL_PADDING_PKCS7
#define ECIES_CIPHER_MODE POLARSSL_CIPHER_AES_256_CBC

#define ECIES_STR(s) #s
#define ECIES_XSTR(s) ECIES_STR(s)

#define ECIES_MD_SHA_INFO_FROM_SIZE(size) md_info_from_string("SHA"ECIES_XSTR(size))

typedef union {
    struct {
        unsigned char hmac[ECIES_HMAC_LEN];
        unsigned char enc[ECIES_ENC_LEN];
        unsigned char iv[ECIES_IV_LEN];
    } key;
    unsigned char data[ECIES_KDF_LEN];
} ecies_kdf_value_t;

typedef struct {
    unsigned char data[ECIES_HMAC_LEN];
} ecies_hmac_t;

typedef struct {
    uint32_t version; // Not used at this implementation.
    uint32_t pub_key_pos;
    uint32_t pub_key_len;
    uint32_t hmac_pos;
    uint32_t hmac_len;
    uint32_t enc_pos;
    uint32_t enc_len;
    uint32_t reserved; // Not used at this implementation.
} ecies_encrypt_message_header_t;

static void reverse_bytes(void *start, int size) {
    unsigned char *lo = start;
    unsigned char *hi = start + size - 1;
    unsigned char swap;
    while (lo < hi) {
        swap = *lo;
        *lo++ = *hi;
        *hi-- = swap;
    }
}

static int ecies_write_uint32(uint32_t val, unsigned char **p, const unsigned char *end)
{
    int len = sizeof(val);
    const int one_const = 1;
    const int is_bigendian = (*(char*)&one_const) == 0;

    if (end - *p < len) {
        return POLARSSL_ERR_ECIES_OUTPUT_TOO_SMALL;
    }

    memcpy (*p, (const unsigned char *)&val, len);
    if (is_bigendian) {
        reverse_bytes(*p, len);
    }
    *p += len;
    return len;
}

static int ecies_read_uint32(uint32_t *val, const unsigned char **p, const unsigned char *end)
{
    int len = 0;
    const int one_const = 1;
    const int is_bigendian = (*(char*)&one_const) == 0;

    if (val == NULL) {
        return POLARSSL_ERR_ECIES_BAD_INPUT_DATA;
    }

    len = sizeof(*val);
    memcpy (val, *p, len);
    if (is_bigendian) {
        reverse_bytes(val, len);
    }
    *p += len;

    return len;
}

static int ecies_write_encrypt_header(const ecies_encrypt_message_header_t *header,
        unsigned char *start, const unsigned char *end)
{
    int result = 0;
    unsigned char *p = start;
    if (end - start < sizeof(ecies_encrypt_message_header_t)) {
        return POLARSSL_ERR_ECIES_OUTPUT_TOO_SMALL;
    }
    ECIES_CHECK_RESULT(result = ecies_write_uint32(header->version, &p, end));
    ECIES_CHECK_RESULT(result = ecies_write_uint32(header->pub_key_pos, &p, end));
    ECIES_CHECK_RESULT(result = ecies_write_uint32(header->pub_key_len, &p, end));
    ECIES_CHECK_RESULT(result = ecies_write_uint32(header->hmac_pos, &p, end));
    ECIES_CHECK_RESULT(result = ecies_write_uint32(header->hmac_len, &p, end));
    ECIES_CHECK_RESULT(result = ecies_write_uint32(header->enc_pos, &p, end));
    ECIES_CHECK_RESULT(result = ecies_write_uint32(header->enc_len, &p, end));
    ECIES_CHECK_RESULT(result = ecies_write_uint32(header->reserved, &p, end));
exit:
    return result;
}

static int ecies_read_encrypt_header(ecies_encrypt_message_header_t *header,
        const unsigned char *start, const unsigned char *end)
{
    int result = 0;
    const unsigned char *p = start;
    if (end - start < sizeof(ecies_encrypt_message_header_t)) {
        return POLARSSL_ERR_ECIES_MALFORMED_DATA;
    }
    ECIES_CHECK_RESULT(result = ecies_read_uint32(&(header->version), &p, end));
    ECIES_CHECK_RESULT(result = ecies_read_uint32(&(header->pub_key_pos), &p, end));
    ECIES_CHECK_RESULT(result = ecies_read_uint32(&(header->pub_key_len), &p, end));
    ECIES_CHECK_RESULT(result = ecies_read_uint32(&(header->hmac_pos), &p, end));
    ECIES_CHECK_RESULT(result = ecies_read_uint32(&(header->hmac_len), &p, end));
    ECIES_CHECK_RESULT(result = ecies_read_uint32(&(header->enc_pos), &p, end));
    ECIES_CHECK_RESULT(result = ecies_read_uint32(&(header->reserved), &p, end));
exit:
    return result;
}

static int ecies_ka(ecp_keypair *public, const ecp_keypair *private, mpi *shared,
        int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    if (public == NULL || private == NULL || shared == NULL) {
        return POLARSSL_ERR_ECIES_BAD_INPUT_DATA;
    }
    if (public->grp.id != private->grp.id) {
        return POLARSSL_ERR_ECIES_BAD_INPUT_DATA;
    }
    return ecdh_compute_shared(&public->grp, shared, &public->Q, &private->d, f_rng, p_rng);
}

static int ecies_kdf(const unsigned char *input, size_t ilen, unsigned char *output, size_t olen)
{
    return kdf1(input, ilen, output, olen);
}

static int ecies_hmac(const unsigned char *input, size_t ilen,
        const unsigned char *key, size_t keylen, ecies_hmac_t *hmac)
{
    const md_info_t *md_info = NULL;

    memset(hmac->data, 0, ECIES_HMAC_LEN);

    md_info = ECIES_MD_SHA_INFO_FROM_SIZE(ECIES_HMAC_SIZE);

    return md_hmac(md_info, key, keylen, input, ilen, hmac->data);
}

int ecies_write_public_key(ecp_keypair *key, unsigned char *output, size_t olen)
{
    int result = 0;
    pk_context pk;

    if (key == NULL || output == NULL) {
        return POLARSSL_ERR_ECIES_BAD_INPUT_DATA;
    }

    pk_init(&pk);
    pk.pk_info = pk_info_from_type(POLARSSL_PK_ECKEY);
    pk.pk_ctx = key;
    result = pk_write_pubkey_der(&pk, output, olen);
    ECIES_CHECK_RESULT(result);
    memcpy(output, output + olen - result, result);
exit:
    pk.pk_ctx = NULL;
    pk_free(&pk);
    return result;
}

int ecies_read_public_key(const unsigned char *input, size_t ilen, ecp_keypair **key)
{
    int result = 0;
    pk_context pk;

    if (input == NULL ||  key == NULL || *key != NULL) {
        return POLARSSL_ERR_ECIES_BAD_INPUT_DATA;
    }

    pk_init(&pk);
    result = pk_parse_public_key(&pk, input, ilen);
    ECIES_CHECK_RESULT(result);
exit:
    if (result == 0 && pk.pk_ctx != NULL) {
        if (pk_can_do(&pk, POLARSSL_PK_ECKEY)) {
            *key = pk.pk_ctx; // SHOULD be released in client code.
        } else {
            pk_free(&pk);
            result = POLARSSL_ERR_ECIES_MALFORMED_DATA;
        }
    }
    return result;
}

#ifdef POLARSSL_ECIES_DEBUG
static void ecies_print_buf(const char *title, const unsigned char *buf, size_t buf_len)
{
    size_t i = 0;
    fprintf(stdout, "%s\n", title);
    for(i = 0; i < buf_len; ++i) {
        fprintf(stdout, "%02X%s", buf[i], ( i + 1 ) % 16 == 0 ? "\r\n" : " " );
    }

}
#endif /* POLARSSL_ECIES_DEBUG */

int ecies_encrypt(ecp_keypair *key, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    // Define counters.
    int result = 0;
    size_t offset = 0;
    size_t chunk_len = 0;
    size_t osize_left = 0;
    // Define keys and hmac data.
    ecp_keypair ephemeral_key;
    mpi shared_key;
    unsigned char * shared_key_binary = NULL;
    size_t shared_key_binary_len = 0;
    ecies_kdf_value_t kdf_value;
    ecies_hmac_t hmac_value;
    // Define cipher data.
    cipher_context_t cipher_ctx;
    size_t cipher_block_size = 0;
    size_t cipher_outlen = 0;
    unsigned char * cipher_buffer = NULL;
    // Encrypted message
    ecies_encrypt_message_header_t encrypt_header;
    unsigned char *encrypt_data = NULL;

    if (key == NULL || input == NULL || output == NULL || olen == NULL) {
        return POLARSSL_ERR_ECIES_BAD_INPUT_DATA;
    }

    if (osize < sizeof(ecies_encrypt_message_header_t)) {
        return POLARSSL_ERR_ECIES_OUTPUT_TOO_SMALL;
    }

    // Init structures.
    encrypt_data = output + sizeof(encrypt_header);
    osize_left = osize - sizeof(encrypt_header);
    *olen = 0;
    mpi_init(&shared_key);
    ecp_keypair_init(&ephemeral_key);
    cipher_init(&cipher_ctx);
    result = cipher_init_ctx(&cipher_ctx, cipher_info_from_type(ECIES_CIPHER_MODE));
    ECIES_CHECK_RESULT(result);
    memset(&hmac_value, 0, sizeof(hmac_value));
    memset(&kdf_value, 0, sizeof(kdf_value));
    memset(&encrypt_header, 0, sizeof(encrypt_header));
    shared_key_binary_len = ECIES_SIZE_TO_OCTETS(key->grp.pbits);

    // 1. Generate ephemeral keypair.
    result = ecp_gen_key(key->grp.id, &ephemeral_key, f_rng, p_rng);
    ECIES_CHECK_RESULT(result);
    // 2. Write ephemeral public key to crypto message
    encrypt_header.pub_key_pos = 0;
    result = ecies_write_public_key(&ephemeral_key, encrypt_data + encrypt_header.pub_key_pos, osize_left);
    ECIES_CHECK_RESULT(result);
    encrypt_header.pub_key_len = result;
    osize_left -= result;
    // 3. Compute shared secret key.
    result = ecies_ka(key, &ephemeral_key, &shared_key, f_rng, p_rng);
    ECIES_CHECK_RESULT(result);
    shared_key_binary = polarssl_malloc(shared_key_binary_len);
    memset(shared_key_binary, 0, shared_key_binary_len);
    result = mpi_write_binary(&shared_key, shared_key_binary, shared_key_binary_len);
    ECIES_CHECK_RESULT(result);
    // 4. Derive keys (encryption key and hmac key).
    result = ecies_kdf(shared_key_binary, shared_key_binary_len, kdf_value.data, ECIES_KDF_LEN);
    ECIES_CHECK_RESULT(result);
    // 5. Encrypt given message.
    result = cipher_setkey(&cipher_ctx, kdf_value.key.enc, ECIES_ENC_SIZE, POLARSSL_ENCRYPT);
    ECIES_CHECK_RESULT(result);
    result = cipher_set_padding_mode(&cipher_ctx, ECIES_CIPHER_PADDING);
    ECIES_CHECK_RESULT(result);
    result = cipher_set_iv(&cipher_ctx, kdf_value.key.iv, ECIES_IV_LEN);
    ECIES_CHECK_RESULT(result);
    result = cipher_reset(&cipher_ctx);
    ECIES_CHECK_RESULT(result);
    cipher_block_size = cipher_get_block_size(&cipher_ctx);
    cipher_buffer = polarssl_malloc(2 * cipher_block_size);
    encrypt_header.enc_pos = encrypt_header.pub_key_pos + encrypt_header.pub_key_len;
    encrypt_header.enc_len = 0;
    for (offset = 0; offset < ilen; offset += cipher_get_block_size(&cipher_ctx)) {
        chunk_len = (ilen - offset > cipher_get_block_size(&cipher_ctx)) ?
                cipher_get_block_size(&cipher_ctx) : (size_t)(ilen - offset);
        cipher_outlen = 0;
        cipher_update(&cipher_ctx, input + offset, chunk_len, cipher_buffer, &cipher_outlen);
        if (osize_left < cipher_outlen) {
            result = POLARSSL_ERR_ECIES_OUTPUT_TOO_SMALL;
        }
        ECIES_CHECK_RESULT(result);
        memcpy(encrypt_data + encrypt_header.enc_pos + encrypt_header.enc_len,
                cipher_buffer, cipher_outlen);
        encrypt_header.enc_len += cipher_outlen;
        osize_left -= cipher_outlen;
    }
    result = cipher_finish(&cipher_ctx, cipher_buffer, &cipher_outlen);
    ECIES_CHECK_RESULT(result);
    if (osize_left < cipher_outlen) {
        result = POLARSSL_ERR_ECIES_OUTPUT_TOO_SMALL;
    }
    ECIES_CHECK_RESULT(result);
    memcpy(encrypt_data + encrypt_header.enc_pos + encrypt_header.enc_len, cipher_buffer, cipher_outlen);
    encrypt_header.enc_len += cipher_outlen;
    osize_left -= cipher_outlen;
    // 5. Get HMAC for encrypted message.
    result = ecies_hmac(encrypt_data + encrypt_header.enc_pos, encrypt_header.enc_len,
            kdf_value.key.hmac, ECIES_HMAC_LEN, &hmac_value);
    ECIES_CHECK_RESULT(result);
    encrypt_header.hmac_pos = encrypt_header.enc_pos + encrypt_header.enc_len;
    encrypt_header.hmac_len = ECIES_HMAC_LEN;
    if (osize_left < ECIES_HMAC_LEN) {
        result = POLARSSL_ERR_ECIES_OUTPUT_TOO_SMALL;
    }
    ECIES_CHECK_RESULT(result);
    memcpy(encrypt_data + encrypt_header.hmac_pos, hmac_value.data, ECIES_HMAC_LEN);
    osize_left -= ECIES_HMAC_LEN;
    // 6. Write encryption header.
    result = ecies_write_encrypt_header(&encrypt_header, output, output + osize);
    ECIES_CHECK_RESULT(result);


exit:
    if (cipher_buffer != NULL) {
        polarssl_free(cipher_buffer);
    }
    cipher_free(&cipher_ctx);
    ecp_keypair_free(&ephemeral_key);
    mpi_free(&shared_key);
    if (shared_key_binary) {
        polarssl_free(shared_key_binary);
    }
    *olen = osize - osize_left;
    return result;
}


int ecies_decrypt(ecp_keypair *key, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    // Define counters.
    int result = 0;
    size_t ioffset = 0;
    size_t ooffset = 0;
    size_t chunk_len = 0;
    size_t osize_left = 0;
    // Define keys and hmac data.
    ecp_keypair *ephemeral_key = NULL;
    mpi shared_key;
    unsigned char *shared_key_binary = NULL;
    size_t shared_key_binary_len = 0;
    ecies_kdf_value_t kdf_value;
    ecies_hmac_t hmac_value;
    // Define cipher data.
    cipher_context_t cipher_ctx;
    size_t cipher_block_size = 0;
    size_t cipher_outlen = 0;
    unsigned char * cipher_buffer = NULL;
    // Encrypted message
    ecies_encrypt_message_header_t *encrypt_header = NULL;
    const unsigned char *encrypt_data = NULL;

    if (key == NULL || input == NULL || ilen < sizeof(ecies_encrypt_message_header_t) ||
            output == NULL || olen == NULL) {
        return POLARSSL_ERR_ECIES_BAD_INPUT_DATA;
    }

    // Init structures.
    mpi_init(&shared_key);
    ecp_keypair_init(ephemeral_key);
    memset(&hmac_value, 0, sizeof(hmac_value));
    memset(&kdf_value, 0, sizeof(kdf_value));
    encrypt_header = (ecies_encrypt_message_header_t *)input;
    encrypt_data = input + sizeof(ecies_encrypt_message_header_t);
    osize_left = osize;
    *olen = 0;
    shared_key_binary_len = ECIES_SIZE_TO_OCTETS(key->grp.pbits);

    // 1. Get ephemeral public key from encrypted message.
    result = ecies_read_public_key(encrypt_data + encrypt_header->pub_key_pos, encrypt_header->pub_key_len,
            &ephemeral_key);
    ECIES_CHECK_RESULT(result);
    // 2. Compute shared secret key.
    result = ecies_ka(ephemeral_key, key, &shared_key, f_rng, p_rng);
    ECIES_CHECK_RESULT(result);
    shared_key_binary = polarssl_malloc(ECIES_SIZE_TO_OCTETS(key->grp.pbits));
    memset(shared_key_binary, 0, shared_key_binary_len);
    result = mpi_write_binary(&shared_key, shared_key_binary, shared_key_binary_len);
    ECIES_CHECK_RESULT(result);
    // 3. Derive keys (encryption key and hmac key).
    result = ecies_kdf(shared_key_binary, shared_key_binary_len, kdf_value.data, ECIES_KDF_LEN);
    ECIES_CHECK_RESULT(result);
    // 4. Get HMAC for encrypted message.
    result = ecies_hmac(encrypt_data + encrypt_header->enc_pos, encrypt_header->enc_len,
            kdf_value.key.hmac, ECIES_HMAC_LEN, &hmac_value);
    ECIES_CHECK_RESULT(result);
    // 5. Compare computed HMAC with original.
    if (encrypt_header->hmac_len == ECIES_HMAC_LEN) {
        result = memcmp(encrypt_data + encrypt_header->hmac_pos, hmac_value.data, ECIES_HMAC_LEN);
        if (result != 0) {
            result = POLARSSL_ERR_ECIES_MALFORMED_DATA;
        }
    } else {
        result = POLARSSL_ERR_ECIES_MALFORMED_DATA;
    }
    ECIES_CHECK_RESULT(result);
    // 6. Decrypt given message.
    cipher_init(&cipher_ctx);
    result = cipher_init_ctx(&cipher_ctx, cipher_info_from_type(ECIES_CIPHER_MODE));
    ECIES_CHECK_RESULT(result);
    result = cipher_setkey(&cipher_ctx, kdf_value.key.enc, ECIES_ENC_SIZE, POLARSSL_DECRYPT);
    ECIES_CHECK_RESULT(result);
    result = cipher_set_padding_mode(&cipher_ctx, ECIES_CIPHER_PADDING);
    ECIES_CHECK_RESULT(result);
    result = cipher_set_iv(&cipher_ctx, kdf_value.key.iv, ECIES_IV_LEN);
    ECIES_CHECK_RESULT(result);
    result = cipher_reset(&cipher_ctx);
    ECIES_CHECK_RESULT(result);
    cipher_block_size = cipher_get_block_size(&cipher_ctx);
    cipher_buffer = polarssl_malloc(2 * cipher_block_size);
    for (ioffset = 0, ooffset = 0; ioffset < encrypt_header->enc_len; ioffset += cipher_get_block_size(&cipher_ctx)) {
        chunk_len = (encrypt_header->enc_len - ioffset > cipher_get_block_size(&cipher_ctx)) ?
                cipher_get_block_size(&cipher_ctx) : (size_t)(encrypt_header->enc_len - ioffset);
        cipher_outlen = 0;
        cipher_update(&cipher_ctx, encrypt_data + encrypt_header->enc_pos + ioffset, chunk_len, cipher_buffer,
                &cipher_outlen);
        if (osize_left < cipher_outlen) {
            result = POLARSSL_ERR_ECIES_OUTPUT_TOO_SMALL;
        }
        ECIES_CHECK_RESULT(result);
        memcpy(output + ooffset, cipher_buffer, cipher_outlen);
        ooffset += cipher_outlen;
        osize_left -= cipher_outlen;
    }
    result = cipher_finish(&cipher_ctx, cipher_buffer, &cipher_outlen);
    ECIES_CHECK_RESULT(result);
    if (osize_left < cipher_outlen) {
        result = POLARSSL_ERR_ECIES_OUTPUT_TOO_SMALL;
    }
    ECIES_CHECK_RESULT(result);
    memcpy(output + ooffset, cipher_buffer, cipher_outlen);
    ooffset += cipher_outlen;
    osize_left -= cipher_outlen;

exit:
    if (cipher_buffer != NULL) {
        polarssl_free(cipher_buffer);
    }
    cipher_free(&cipher_ctx);
    if (ephemeral_key != NULL) {
        ecp_keypair_free(ephemeral_key);
    }
    if (shared_key_binary) {
        polarssl_free(shared_key_binary);
    }
    mpi_free(&shared_key);
    *olen = osize - osize_left;
    return result;
}


#endif /* defined(POLARSSL_ECIES_C) */
