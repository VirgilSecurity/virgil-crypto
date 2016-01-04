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
# This script attempts to build all targets
#

pushd `dirname $0` > /dev/null

# Native
./build.sh cpp .. ../build/cpp ../install/cpp &
./build.sh php .. ../build/php ../install/php &
./build.sh python .. ../build/python ../install/python &
./build.sh ruby .. ../build/ruby ../install/ruby &
./build.sh java .. ../build/java ../install/java &
./build.sh net .. ../build/net ../install/net &
./build.sh nodejs .. ../build/nodejs ../install/nodejs &

# Crossplatform
./build.sh asmjs .. ../build/asmjs ../install/asmjs &
./build.sh java_android .. ../build/java_android ../install/java_android &
./build.sh net_android .. ../build/net_android ../install/net_android &
./build.sh as3 .. ../build/as3 ../install/as3 &
./build.sh pnacl .. ../build/pnacl ../install/pnacl &

# Apple
if [ "`uname -s`" == "Darwin" ];then
    ./build.sh osx .. ../build/osx ../install/osx &
    ./build.sh ios .. ../build/ios ../install/ios &
    ./build.sh applewatchos .. ../build/applewatchos ../install/applewatchos &
    ./build.sh appletvos .. ../build/appletvos ../install/appletvos &
    ./build.sh net_ios .. ../build/net_ios ../install/net_ios &
    ./build.sh net_applewatchos .. ../build/net_applewatchos ../install/net_applewatchos &
    ./build.sh net_appletvos .. ../build/net_appletvos ../install/net_appletvos &
fi

wait

popd > /dev/null

echo "Done"
