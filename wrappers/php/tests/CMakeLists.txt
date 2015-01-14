#
# Copyright (C) 2014 Virgil Security Inc.
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

set (TEST_FILE_LIST
    VirgilHash_MD5_Test.php
    VirgilHash_SHA256_Test.php
    VirgilHash_SHA512_Test.php
    VirgilSymmetricCipher_AES256_CBC_Test.php
    VirgilAsymmetricCipher_EC_Test.php
    VirgilAsymmetricCipher_RSA_Test.php
    VirgilCipher_Test.php
    VirgilStreamCipher_Test.php
    VirgilChunkCipher_Test.php
    VirgilStreamSigner_Test.php
    VirgilSigner_Test.php
    VirgilAsn1Reader_Test.php
    VirgilAsn1Writer_Test.php
    VirgilJsonDataMarshaller_Test.php
    VirgilAsn1DataMarshaller_Test.php
    VirgilRandom_Test.php
    VirgilPBE_Test.php
    VirgilVersion_Test.php

    StringSource.php
    StringSink.php
)

add_subdirectory (data)

foreach (TEST_FILE ${TEST_FILE_LIST})
    configure_file (
        ${CMAKE_CURRENT_SOURCE_DIR}/${TEST_FILE}.in
        ${CMAKE_CURRENT_BINARY_DIR}/${TEST_FILE}
        @ONLY
    )
endforeach (TEST_FILE)

find_program (PHP_MODULE php)
find_program (PHPUNIT_MODULE phpunit)

if (PHP_MODULE AND PHPUNIT_MODULE)
    add_test (
        NAME ${PHP_MODULE_FILE_NAME}
        COMMAND ${PHP_MODULE} -n -d extension_dir=.. -d safe_mode=Off ${PHPUNIT_MODULE} --include-path .. .
    )
endif (PHP_MODULE AND PHPUNIT_MODULE)
