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

#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/VirgilCipher.h>
using virgil::service::VirgilCipher;

int print_usage(std::ostream& out, const char *programName) {
    out << "Usage: " << programName;
    out << " <owner_enc_key> <owner_private_key> <owner_private_key_pwd> <friend_public_key> <friend_enc_key>\n";
    out << "    <owner_enc_key>         - [in]  owner's encryption key file" << std::endl;
    out << "    <owner_private_key>     - [in]  owner's private key" << std::endl;
    out << "    <owner_private_key_pwd> - [in]  owner's private key password" << std::endl;
    out << "    <friend_public_key>     - [in]  friend's public key file" << std::endl;
    out << "    <friend_enc_key>        - [out] friend's encryption key file" << std::endl;
    return -1;
}

int main(int argc, char **argv) {
    // Parse arguments.
    const char *programName = argv[0];
    unsigned currArgPos = 0;

    // Check arguments num.
    if (argc < 5) {
        return print_usage(std::cerr, programName);
    }

    // Parse argument: owner_enc_key
    ++currArgPos;
    std::ifstream ownerEncryptionKeyFile(argv[currArgPos], std::ios::in);
    if (!ownerEncryptionKeyFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }
    VirgilByteArray ownerEncryptionKey;
    std::copy(std::istreambuf_iterator<char>(ownerEncryptionKeyFile), std::istreambuf_iterator<char>(),
            std::back_inserter(ownerEncryptionKey));
    ownerEncryptionKeyFile.close();

    // Parse argument: owner_private_key
    ++currArgPos;
    std::ifstream ownerPrivateKeyFile(argv[currArgPos], std::ios::in);
    if (!ownerPrivateKeyFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }
    VirgilByteArray ownerPrivateKey;
    std::copy(std::istreambuf_iterator<char>(ownerPrivateKeyFile), std::istreambuf_iterator<char>(),
            std::back_inserter(ownerPrivateKey));
    ownerPrivateKeyFile.close();

    // Parse argument: owner_private_key_pwd
    ++currArgPos;
    VirgilByteArray ownerPrivateKeyPassword = VIRGIL_BYTE_ARRAY_FROM_STD_STRING(std::string(argv[currArgPos]));

    // Parse argument: friend_public_key
    ++currArgPos;
    std::ifstream friendPublicKeyFile(argv[currArgPos], std::ios::in);
    if (!friendPublicKeyFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }
    VirgilByteArray friendPublicKey;
    std::copy(std::istreambuf_iterator<char>(friendPublicKeyFile), std::istreambuf_iterator<char>(),
            std::back_inserter(friendPublicKey));
    friendPublicKeyFile.close();

    // Parse argument: friend_enc_key
    ++currArgPos;
    std::ofstream friendEncryptionKeyFile(argv[currArgPos], std::ios::out | std::ios::binary);
    if (!friendEncryptionKeyFile.is_open()) {
        std::cerr << "Unable to open file: " <<  argv[currArgPos] << std::endl;
        return print_usage(std::cerr, programName);
    }

    // Create cipher.
    VirgilCipher cipher;

    // Reencrypt encryption key (share encryption key).
    VirgilByteArray friendEncryptionKey =
            cipher.reencryptKey(ownerEncryptionKey, friendPublicKey, ownerPrivateKey, ownerPrivateKeyPassword);

    // Write friend encryption key to file.
    std::copy(friendEncryptionKey.begin(), friendEncryptionKey.end(),
            std::ostreambuf_iterator<char>(friendEncryptionKeyFile));

    return 0;
}
