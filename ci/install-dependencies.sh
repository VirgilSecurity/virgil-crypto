#!/bin/bash
#
# Copyright (C) 2015-2018 Virgil Security Inc.
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
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#

set -e

######################################## Inspect OS & ENV
lsb_release -a

LANG_VERSION_MAJOR=$(echo ${LANG_VERSION} | cut -d. -f1)
LANG_VERSION_MINOR=$(echo ${LANG_VERSION} | cut -d. -f2)
LANG_VERSION_PATCH=$(echo ${LANG_VERSION} | cut -d. -f3)

######################################## Update lists of packages
travis_retry sudo apt-get -qq update

######################################## Utils
travis_retry sudo apt-get install -y -qq software-properties-common

######################################## Doxygen
travis_retry sudo apt-get install -y --force-yes -qq doxygen

######################################## Compilers
if [[ "${CC}" == "gcc-5" ]]; then
    travis_retry sudo apt-add-repository -y ppa:ubuntu-toolchain-r/test
    travis_retry sudo apt-get -qq update
    travis_retry sudo apt-get install -y -qq gcc-5 g++-5
elif [[ "${CC}" == "gcc-6" ]]; then
    travis_retry sudo apt-add-repository -y ppa:ubuntu-toolchain-r/test
    travis_retry sudo apt-get -qq update
    travis_retry sudo apt-get install -y -qq gcc-6 g++-6
elif [[ "${CC}" == "clang-3.6" ]]; then
    travis_retry sudo apt-add-repository "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.6 main"
    travis_retry sudo apt-get -qq update
    travis_retry sudo apt-get install -y --force-yes -qq clang-3.6 clang++-3.6
fi

######################################## CMake
if [ -d "cmake-${CMAKE_VERSION}" ] && [ "$(ls -A "cmake-${CMAKE_VERSION}")" ]; then
    echo "Use cached CMake version ${CMAKE_VERSION} ..."
    cd cmake-${CMAKE_VERSION}
else
    echo "Download & Build CMake version ${CMAKE_VERSION} ..."
    travis_retry wget https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}.tar.gz
    tar xvfz cmake-${CMAKE_VERSION}.tar.gz
    cd cmake-${CMAKE_VERSION}
    ./bootstrap
    make -j4 >/dev/null
fi

sudo make install >/dev/null

cd -

######################################## SWIG
if [ -d "swig-${SWIG_VERSION}" ] && [ "$(ls -A "swig-${SWIG_VERSION}")" ]; then
    echo "Use cached SWIG version ${SWIG_VERSION} ..."
    cd swig-${SWIG_VERSION}
else
    echo "Download & Build SWIG version ${SWIG_VERSION} ..."
    travis_retry wget http://downloads.sourceforge.net/swig/swig-${SWIG_VERSION}.tar.gz
    tar -xzf swig-${SWIG_VERSION}.tar.gz
    cd swig-${SWIG_VERSION}
    ./configure >/dev/null
    make -j4 >/dev/null
fi

sudo make install >/dev/null

cd -

####################################### PHP & PHPUnit
if [[ "${LANG}" == "php" ]]; then
    PHP_VERSION=${LANG_VERSION_MAJOR}.${LANG_VERSION_MINOR}
    PHP_VERSION_MAJOR=${LANG_VERSION_MAJOR}

    if [[ ${PHP_VERSION_MAJOR} -ge 7 ]]; then
        PHPUNIT_VERSION=6.2
    else
        PHPUNIT_VERSION=5.7
    fi
    ######################################## PHP
    echo "Install PHP version ${PHP_VERSION} ..."
    travis_retry sudo apt-add-repository -y ppa:ondrej/php
    travis_retry sudo apt-get -qq update
    travis_retry sudo apt-get install -y -qq php${PHP_VERSION}
    travis_retry sudo apt-get install -y -qq php${PHP_VERSION}-cli
    travis_retry sudo apt-get install -y -qq php${PHP_VERSION}-dev
    travis_retry sudo apt-get install -y -qq php${PHP_VERSION}-mbstring
    ######################################## PHPUnit
    echo "Install PHPUnit version ${PHPUNIT_VERSION} ..."
    travis_retry wget https://phar.phpunit.de/phpunit-${PHPUNIT_VERSION}.phar
    chmod +x phpunit-${PHPUNIT_VERSION}.phar
    sudo mv phpunit-${PHPUNIT_VERSION}.phar /usr/bin/phpunit
fi

set +e
