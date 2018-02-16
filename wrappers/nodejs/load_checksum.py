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

import json
import sys

from distutils.version import LooseVersion

PYTHON_VERSION = sys.version_info[0]
if PYTHON_VERSION == 3:
    import urllib.request as urllib2
    from urllib.error import HTTPError
else:
    import urllib2
    from urllib2 import HTTPError as HTTPError


def get_data_from_url(url):
    try:
        return urllib2.urlopen(url).read()
    except HTTPError as e:
        print("Cant get data from {url} error: {error}".format(url=url, error=e))


if __name__ == '__main__':
    nodejs_releases_url = "https://nodejs.org/download/release"
    raw_nodejs_versions = get_data_from_url(nodejs_releases_url + "/index.json")
    if not raw_nodejs_versions:
        sys.exit(1)
    nodejs_versions = [x['version'] for x in json.loads(raw_nodejs_versions)]
    result_checksums = list()

    for version in nodejs_versions:

        if LooseVersion(version) < LooseVersion("v4.0.0"):
            print("Skip checksums for stale version: {}".format(version))
            continue

        print("Loading checksums for version: {}".format(version))
        file_checksums = get_data_from_url(nodejs_releases_url + "/{}/SHASUMS256.txt".format(version))
        if not file_checksums:
            sys.exit(1)
        for line in file_checksums.decode().split("\n"):
            if line.endswith("headers.tar.gz") or line.endswith("node.lib"):
                result_checksums.append("{:8} {}".format(version, line))

    open('checksum.txt', 'w').write("\n".join(result_checksums))

