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
import yaml

import argparse

def parseArguments():
    parser = argparse.ArgumentParser(description=
        "Use this utility to patch MbedTLS library add extended it functionality.");
    parser.add_argument("-i", "--input-dir", dest="inputDir", help="library directoty", required=True)
    parser.add_argument("-d", "--config-defines", dest="configDefines",
            help="configuration file full name for defines", required=True)
    parser.add_argument("-p", "--config-platform-defines", dest="configPlatformDefines", action='append',
            help="configuration file full name for platfrom dependent defines", required=False)
    return parser.parse_args()

def regexForEnabledDefine(define):
    return r'^[\s]*(#define[\s]+' + define + r')[\s]+'

def regexForDisabledDefine(define):
    return r'^[\s]*//[\s]*(#define[\s]+' + define + r')[\s+]'

def disableDefines(defines, filePath):
    if not defines:
        return;
    for line in fileinput.input(filePath, inplace=True):
        for define in defines:
            pattern = regexForEnabledDefine(define)
            if re.match(pattern, line):
                line = re.sub(pattern, r'//\1', line)
                break;
        sys.stdout.write(line)

def enableDefines(defines, filePath):
    if not defines:
        return;
    for line in fileinput.input(filePath, inplace=True):
        for define in defines:
            pattern = regexForDisabledDefine(define)
            if re.match(pattern, line):
                line = re.sub(pattern, r'\1', line)
                break;
        sys.stdout.write(line)

def addDefines(defines, filePath, insertAfterRegex):
    if not defines:
        return;
    newDefinesWasAdded = False
    for line in fileinput.input(filePath, inplace=True):
        sys.stdout.write(line)
        if not newDefinesWasAdded and re.match(insertAfterRegex, line):
            sys.stdout.write("\n")
            sys.stdout.write("/* START custom defines section */\n" )
            for define in defines:
                sys.stdout.write(define + "\n" )
            sys.stdout.write("/* END custom defines section */\n" )
            newDefinesWasAdded = True

def main(argv=None):
    if argv is None:
        argv = sys.argv

    args = parseArguments()
    # Define paths
    libraryDir = os.path.abspath(os.path.normpath(args.inputDir))
    configFilePath = os.path.join(libraryDir, "include/mbedtls/config.h")
    checkConfigFilePath = os.path.join(libraryDir, "include/mbedtls/check_config.h")
    # Apply common defines
    commonDefines = yaml.load(open(args.configDefines));
    disableDefines(commonDefines.get("disable", []), configFilePath);
    enableDefines(commonDefines.get("enable", []), configFilePath);
    addDefines(commonDefines.get("new", []), configFilePath,
            regexForEnabledDefine("MBEDTLS_CONFIG_H"));
    addDefines(commonDefines.get("check", []), checkConfigFilePath,
            regexForEnabledDefine("MBEDTLS_CHECK_CONFIG_H"));
    # Apply platform specific defines
    if args.configPlatformDefines:
        for configPlatformDefineFile in args.configPlatformDefines:
            configPlatformDefines = yaml.load(open(configPlatformDefineFile));
            disableDefines(configPlatformDefines.get("disable", []), configFilePath);
            enableDefines(configPlatformDefines.get("enable", []), configFilePath);
            addDefines(configPlatformDefines.get("new", []), configFilePath,
                    regexForEnabledDefine("MBEDTLS_CONFIG_H"));
            addDefines(configPlatformDefines.get("check", []), checkConfigFilePath,
                    regexForEnabledDefine("MBEDTLS_CHECK_CONFIG_H"));

if __name__ == "__main__":
    sys.exit(main(sys.argv))
