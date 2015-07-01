#! /usr/bin/python

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

import os
import fileinput
import re
import sys

def get_known_namespaces():
    """ Return dictionary of known namespaces in the wrapped Crypto Library.
    """
    return {
        "virgil.crypto" : "Virgil.Crypto",
        "virgil.crypto.foundation" : "Virgil.Crypto.Foundation",
        "virgil.crypto.foundation.asn1" : "Virgil.Crypto.Foundation.Asn1",
        "virgil.crypto.foundation.cms" : "Virgil.Crypto.Foundation.Cms"
    }

def uppercase_namespaces(files, namespaces):
    """ Travel thru given files and change old namespaces to the new one.
    """
    for src in files:
        for line in fileinput.input(src, inplace=True):
            for (namespaceOld, namespaceNew) in namespaces.items():
                pattern = re.compile(re.escape(namespaceOld), re.IGNORECASE)
                line = re.sub(pattern, namespaceNew, line)
            sys.stdout.write(line)

def aux_source_directory(srcDir):
    """ Return list of source files found in the given directory.
    """
    sources = []
    for (dirpath, dirnames, filenames) in os.walk(srcDir):
        for filename in filenames:
            if filename.endswith('.cs'):
                sources.append(os.path.join(dirpath, filename))
    return sources

def main(argv=None):
    if argv is None:
        argv = sys.argv

    srcDir = argv[1]
    if (not os.path.isdir(srcDir)):
        return "C# Source files not found at: " + srcDir

    return uppercase_namespaces(aux_source_directory(srcDir), get_known_namespaces())

if __name__ == "__main__":
    sys.exit(main(sys.argv))
