#!/bin/bash
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

# Returns absolute path of given object
function abspath {
    pushd . $> /dev/null
    if [ -d "$1" ]; then
        cd "$1"
    else
        cd "`dirname \"$1\"`"
    fi
    echo `pwd -P`
    popd $> /dev/null
}

# Check arguments
if [ -z $1 ]; then
    echo "Directory with CLI is not specified. Please pass it as first argument."
    exit 1
fi

if [ ! -d $1 ]; then
    echo "CLI does not exist at path: $1"
    exit 1
fi

# Define CLI commands
cli_dir=$(abspath $1)
if [ -f "$cli_dir/virgil" ]; then
    keygen_cmd="$cli_dir/virgil keygen"
    key2pub_cmd="$cli_dir/virgil key2pub"
    pub2cert_cmd="$cli_dir/virgil pub2cert"
    certinfo_cmd="$cli_dir/virgil certinfo"
    encrypt_cmd="$cli_dir/virgil encrypt"
    decrypt_cmd="$cli_dir/virgil decrypt"
    sign_cmd="$cli_dir/virgil sign"
    verify_cmd="$cli_dir/virgil verify"
else
    keygen_cmd="$cli_dir/virgilkeygen"
    key2pub_cmd="$cli_dir/virgilkey2pub"
    pub2cert_cmd="$cli_dir/virgilpub2cert"
    certinfo_cmd="$cli_dir/virgilcertinfo"
    encrypt_cmd="$cli_dir/virgilencrypt"
    decrypt_cmd="$cli_dir/virgildecrypt"
    sign_cmd="$cli_dir/virgilsign"
    verify_cmd="$cli_dir/virgilverify"
fi

function test {
    # Generate elliptic curve private key
    if [ "$1" == "ec" ]; then
        eval "$keygen_cmd" --ec bp512r1 -o private.pem --pwd password --format pem || exit 1
    elif [ "$1" == "rsa" ]; then
        eval "$keygen_cmd" --rsa 2048 -o private.pem --pwd password --format pem || exit 1
    else
        echo "Invalid parameter to function test: $1, available parameters - ec | rsa."
    fi

    # Extract public key
    eval "$key2pub_cmd" -i private.pem --pwd password -o public.pem || exit 1

    # Create certificate from the public key
    eval "$pub2cert_cmd" -i public.pem -o cert.der --format der \
            --account-id "ACC-123" --certificate-id "CERT-123"  || exit 1

    # Verify certificate
    if [[ $(eval "$certinfo_cmd" -i cert.der --account-id) != "ACC-123" ]]; then
        echo "Certificate account id is not equal to initial."; exit 1
    fi

    if [[ $(eval "$certinfo_cmd" -i cert.der --certificate-id) != "CERT-123"  ]]; then
        echo "Certificate id is not equal to initial."; exit 1
    fi

    if [[ $(eval "$certinfo_cmd" -i cert.der -p) != $(cat public.pem) ]]; then
        echo "Certificate public key is not equal to initial."; exit 1
    fi

    # Test encryption / decryption
    test_string="test string"

    ## -- with embedded content info
    ###       encrypt
    echo $test_string | eval "$encrypt_cmd" cert.der recipient_password > data.enc || exit 1
    ###       decrypt with key
    decrypted_data=`eval "$decrypt_cmd" --key private.pem --pwd password --recipient cert.der < data.enc` || exit 1
    if [ "$test_string" != "$decrypted_data" ]; then
        echo "Decrypted data ($decrypted_data) is not equal to initial data ($test_string)."; exit 1
    fi
    ###       decrypt with password
    decrypted_data=`eval "$decrypt_cmd" --recipient recipient_password < data.enc` || exit 1
    if [ "$test_string" != "$decrypted_data" ]; then
        echo "Decrypted data ($decrypted_data) is not equal to initial data ($test_string)."; exit 1
    fi

    ## -- with content info stored in separate file
    ###       encrypt
    echo $test_string | eval "$encrypt_cmd" --content-info content.dat recipient_password cert.der > data.enc || exit 1
    ###       decrypt with key
    decrypted_data=`eval "$decrypt_cmd" --key private.pem --pwd password \
            --content-info content.dat --recipient cert.der < data.enc` || exit 1
    if [ "$test_string" != "$decrypted_data" ]; then
        echo "Decrypted data ($decrypted_data) is not equal to initial data ($test_string)."; exit 1
    fi
    ###       decrypt with password
    decrypted_data=`eval "$decrypt_cmd" --recipient recipient_password --content-info content.dat < data.enc` || exit 1
    if [ "$test_string" != "$decrypted_data" ]; then
        echo "Decrypted data ($decrypted_data) is not equal to initial data ($test_string)."; exit 1
    fi

    # Test sign / verify
    echo "Data to be signed" > data.dat
    ## -- sign
    eval "$sign_cmd" -i data.dat -o sign.der --format der --certificate cert.der --key private.pem --pwd password\
            || exit 1
    ## -- verify
    verify_result=`eval "$verify_cmd" -i data.dat --sign sign.der --certificate cert.der || exit 1`
    if [ "$verify_result" == "failure" ]; then
        echo "Verification failed."; exit 1
    fi
}

# Create working directory
work_dir=`mktemp -d -t virgil`
if [ ! -d $work_dir ]; then
    echo "Can not create working directory."; exit 1
fi

# Go to working directory
pushd "$work_dir" &> /dev/null

# Perform test
test ec
test rsa

# Go to initial directory
popd $> /dev/null

# Remove working directory
rm -fr "$work_dir"
