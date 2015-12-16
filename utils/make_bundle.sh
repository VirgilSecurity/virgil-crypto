#!/bin/bash
#
# Copyright (C) 2015 Virgil Security Inc.
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
# This script accept next parameters: <bundle_name> <in_dir> <out_dir>, where
#     bundle_name - name of the target bundle;
#     in_dir      - path to the installed crypto library witn 'include' and 'lib' directories inside;
#     out_dir     - path to the output bundle
#
# Example: ./make_bundle.sh VirgilCrypto /path/to/source /path/to/destination
#

function show_usage {
    if [ ! -z "$1" ]; then
        echo $1
    fi
    echo "Usage: ${BASH_SOURCE[0]} <bundle_name> <in_dir> <out_dir>"
    echo "     bundle_name - name of the target bundle;"
    echo "     in_dir      - path to the installed crypto library witn 'include' and 'lib' directories inside;"
    echo "     out_dir     - path to the output bundle"
    exit 1
}

# Define name of the framework
if [ ! -z "$1" ]; then
    FRAMEWORK_NAME="$1"
else
    show_usage "Error. Bundle name is not defined."
fi

# Define install directory for framework
if [ ! -z "$2" ]; then
    INDIR="$2"
else
    show_usage "Error. Input directory is not defined."
fi

# Define working directory for framework
if [ ! -z "$3" ]; then
    OUTDIR="$3"
else
    show_usage "Error. Output directory is not defined."
fi

HEADERS_DIR="$INDIR/include"

LIBMBEDTLS="libmbedtls.a"
LIBVIRGIL="libvirgil_crypto.a"

# Create working dir
mkdir -p "$OUTDIR"

# Find all archs of library ARM mbedTLS
LIBMBEDTLS_LIBS=`find $INDIR -name $LIBMBEDTLS | tr '\n' ' '`

# Find all archs of library Virgil Crypto
LIBVIRGIL_LIBS=`find $INDIR -name $LIBVIRGIL | tr '\n' ' '`

xcrun lipo -create ${LIBMBEDTLS_LIBS} -output "$OUTDIR/$LIBMBEDTLS"
xcrun lipo -create ${LIBVIRGIL_LIBS} -output "$OUTDIR/$LIBVIRGIL"
# Merge several static libraries in one static library which will actually be framework
xcrun libtool -static -o "$OUTDIR/$FRAMEWORK_NAME" "$OUTDIR/$LIBMBEDTLS" "$OUTDIR/$LIBVIRGIL"

FRAMEWORK_FULL_NAME="$FRAMEWORK_NAME.framework"
# Compose framework directory structure
mkdir -p "$OUTDIR/$FRAMEWORK_FULL_NAME/Versions/A"
mkdir -p "$OUTDIR/$FRAMEWORK_FULL_NAME/Versions/A/Headers"

# Link the "Current" version to "A"
ln -sf A "$OUTDIR/$FRAMEWORK_FULL_NAME/Versions/Current"
ln -sf Versions/Current/Headers "$OUTDIR/$FRAMEWORK_FULL_NAME/Headers"
ln -sf "Versions/Current/$FRAMEWORK_NAME" "$OUTDIR/$FRAMEWORK_FULL_NAME/$FRAMEWORK_NAME"

# Locate all files to correspondent places
cp -f "$OUTDIR/$FRAMEWORK_NAME" "$OUTDIR/$FRAMEWORK_FULL_NAME/Versions/A/"
cp -Rf "$HEADERS_DIR/" "$OUTDIR/$FRAMEWORK_FULL_NAME/Versions/A/Headers/"

rm -f "$OUTDIR/$LIBMBEDTLS"
rm -f "$OUTDIR/$LIBVIRGIL"
rm -f "$OUTDIR/$FRAMEWORK_NAME"

# cd "$OUTDIR" && tar -czvf "$FRAMEWORK_FULL_NAME.tar.gz" "$FRAMEWORK_FULL_NAME/"
