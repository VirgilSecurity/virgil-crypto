#
# Copyright (C) 2015-2016 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

# Input:
#     PHP_MODULE_FILE_NAME - PHP file name of the module under test.

set (TEST_FILES
    VirgilHash_MD5_Test.php
    VirgilHash_SHA256_Test.php
    VirgilHash_SHA512_Test.php
    VirgilCipher_Test.php
    VirgilStreamCipher_Test.php
    VirgilChunkCipher_Test.php
    VirgilStreamSigner_Test.php
    VirgilSigner_Test.php
    VirgilVersion_Test.php
    VirgilCustomParams_Test.php
    VirgilPBKDF_Test.php

    StringSource.php
    StringSink.php
)

if (VIRGIL_CRYPTO_FEATURE_LOW_LEVEL_WRAP)
    list (APPEND TEST_FILES
        VirgilSymmetricCipher_Test.php
        VirgilAsymmetricCipher_EC_Test.php
        VirgilAsymmetricCipher_RSA_Test.php
        VirgilAsn1Reader_Test.php
        VirgilAsn1Writer_Test.php
        VirgilRandom_Test.php
        VirgilPBE_Test.php
        VirgilKDF_Test.php
    )
endif (VIRGIL_CRYPTO_FEATURE_LOW_LEVEL_WRAP)

add_subdirectory (data)

file (GLOB STALE_TEST_FILES "${CMAKE_CURRENT_BINARY_DIR}/*.php")
if (STALE_TEST_FILES)
    file (REMOVE ${STALE_TEST_FILES})
endif ()

foreach (TEST_FILE ${TEST_FILES})
    configure_file (
        ${CMAKE_CURRENT_SOURCE_DIR}/${TEST_FILE}.in
        ${CMAKE_CURRENT_BINARY_DIR}/${TEST_FILE}
        @ONLY
    )
    list (APPEND PHP_ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${TEST_FILE}")
endforeach (TEST_FILE)

find_host_program (PHP_MODULE php)
find_host_program (PHPUNIT_MODULE phpunit)

if (PHP_MODULE AND PHPUNIT_MODULE)
    add_test (
        NAME ${PHP_MODULE_FILE_NAME}
        COMMAND ${PHP_MODULE} -d extension=../virgil_crypto_php.so -d safe_mode=Off ${PHPUNIT_MODULE} --include-path .. .
    )
endif (PHP_MODULE AND PHPUNIT_MODULE)
