#!/usr/bin/python
#
# Copyright(C) 2015-2018 Virgil Security Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#    (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#    (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#    (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#

import os
import urllib
import json
import re
from distutils.version import LooseVersion

urllib.urlretrieve("https://nodejs.org/download/release/index.json", "index.json")

with open('index.json', 'r') as f:
    nodejs_index = json.load(f)

with open('checksum.txt', 'w') as checksum_file:

    for nodejs in nodejs_index:
        version = nodejs['version']

        if(LooseVersion(version) < LooseVersion("v4.0.0")):
            continue

        print("Loading checksum of version: %s" % version)
        urllib.urlretrieve("https://nodejs.org/download/release/%s/SHASUMS256.txt" % version, "SHASUMS256.txt")

        with open('SHASUMS256.txt', 'r') as f:
            lines = f.readlines()

            for line in lines:
                if re.search(r"(headers\.tar\.gz|node\.lib)", line):
                    checksum_file.write('{:8}  {}'.format(version, line))

            checksum_file.flush()


if os.path.exists('index.json'):
    os.remove('index.json')

if os.path.exists('SHASUMS256.txt'):
    os.remove('SHASUMS256.txt')
