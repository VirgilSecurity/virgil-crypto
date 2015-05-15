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

set -ev

sudo apt-get update -qq
sudo apt-get install -y python-yaml

if [ "${PLATFORM_NAME}" == "CPP" ]; then
    sudo apt-get install -y libcurl4-openssl-dev
fi

if [ "${PLATFORM_NAME}" != "CPP" ] && [ "${PLATFORM_EMBEDDED}" != "ON" ]; then
    # Install SWIG
    wget http://downloads.sourceforge.net/swig/swig-3.0.5.tar.gz -O /tmp/swig-3.0.5.tar.gz
    tar -xvf /tmp/swig-3.0.5.tar.gz --directory /tmp > /dev/null
    cd /tmp/swig-3.0.5 && ./configure --prefix=/usr && make && sudo make install
fi

if [ "${PLATFORM_NAME}" == "PHP" ]; then
    # Install PHP runtime
    sudo apt-get install -y php5
    # Install PHP developer libs
    sudo apt-get install -y php5-dev
    # Install PHPUnit
    wget https://phar.phpunit.de/phpunit.phar -O /tmp/phpunit.phar
    sudo chmod +x /tmp/phpunit.phar
    sudo mv -f /tmp/phpunit.phar /usr/bin/phpunit
fi
