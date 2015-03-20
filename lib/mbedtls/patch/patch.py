#! /usr/bin/python

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

import os
import fileinput
import re
import collections

import sys
import yaml

import argparse

def recursiveMerge(dest, src):
    """Provide recursive merge of two containers"""
    if isinstance(dest, dict) and isinstance(src, dict):
        recursiveMergeDict(dest, src)
    elif isinstance(dest, set) and isinstance(src, set):
        dest |= src
    elif isinstance(dest, list) and isinstance(src, list):
        dest += src
    else:
        raise Exception("dest and src has unsupported or different types:" +
                " dest(" + dest.__class__.__name__ + "), src(" + src.__class__.__name__ + ").\n" +
                "Supported types: dict, set, list.");
    return dest

def recursiveMergeDict(dest, src):
    """Provide recursive merge of two dictionaries."""
    if not isinstance(dest, dict) or not isinstance(src, dict):
        raise Exception("'dest' or 'src' is not of 'dict' type")
    for key in src:
        if key in dest and all(isinstance(x, collections.Container) for x in (dest[key], src[key])):
            recursiveMerge(dest[key], src[key])
        elif src[key] != None:
            dest[key] = src[key]
    return dest

def parseArguments():
    """Parse given arguments
    """
    parser = argparse.ArgumentParser(description=
        "Use this utility to patch PolarSSL library add extended it functionality.");
    parser.add_argument("-i", "--input-dir", dest="inputDir", help="library directoty", required=True)
    parser.add_argument("-d", "--config-defines", dest="configDefines",
            help="configuration file full name for defines", required=True)
    parser.add_argument("-p", "--config-platform-defines", dest="configPlatformDefines",
            help="configuration file full name for platfrom dependent defines", required=False)
    return parser.parse_args()

def patchConfigFile(settings, configFilePath):
    """Patch PolarSSL config.h file
    """
    # Comment macros from the settings list
    commentMacrosSet = settings["comment_macros"]
    if commentMacrosSet:
        for line in fileinput.input(configFilePath, inplace=True):
            for commentMacros in commentMacrosSet:
                pattern = r'^[\s]*(#define[\s]+' + commentMacros + ')'
                if re.match(pattern, line):
                    line = re.sub(pattern, r'//\1', line)
                    break;
            sys.stdout.write(line)
    # Uncomment macros from the settings list
    uncommentMacrosSet = settings["uncomment_macros"]
    if uncommentMacrosSet:
        for line in fileinput.input(configFilePath, inplace=True):
            for uncommentMacros in uncommentMacrosSet:
                pattern = r'^[\s]*//[\s]*(#define[\s]+' + uncommentMacros + ')'
                if re.match(pattern, line):
                    line = re.sub(pattern, r'\1', line)
                    break;
            sys.stdout.write(line)

    customMacroses = settings["new_macros"];
    if customMacroses:
        addMacrosAfterRe = settings["add_new_macros_after_regex"]
        macrosesWadAdded = False
        for line in fileinput.input(configFilePath, inplace=True):
            sys.stdout.write(line)
            if not macrosesWadAdded and re.match(addMacrosAfterRe, line):
                if len(customMacroses) > 0:
                    sys.stdout.write("\n")
                if len(customMacroses) > 0:
                    sys.stdout.write("/* START custom macroses section */\n" )
                for customMacros in customMacroses:
                    sys.stdout.write(customMacros + "\n" )
                if len(customMacroses) > 0:
                    sys.stdout.write("/* END custom macroses section */\n\n" )
                macrosesWadAdded = True

def patchCheckConfigFile(settings, configFilePath):
    """Patch PolarSSL check_config.h file
    """
    customMacroses = settings["check_macros"];
    if customMacroses:
        addMacrosAfterRe = settings["add_check_macros_after_regex"]
        macrosesWadAdded = False
        for line in fileinput.input(configFilePath, inplace=True):
            sys.stdout.write(line)
            if not macrosesWadAdded and re.match(addMacrosAfterRe, line):
                if len(customMacroses) > 0:
                    sys.stdout.write("\n")
                if len(customMacroses) > 0:
                    sys.stdout.write("/* START custom macroses section */\n" )
                for customMacros in customMacroses:
                    sys.stdout.write(customMacros + "\n" )
                if len(customMacroses) > 0:
                    sys.stdout.write("/* END custom macroses section */\n\n" )
                macrosesWadAdded = True

def main(argv=None):
    if argv is None:
        argv = sys.argv

    args = parseArguments()

    currentDir = os.path.dirname(os.path.abspath(__file__))

    configDefines = yaml.load(open(args.configDefines));
    if args.configPlatformDefines:
        configPlatformDefines = yaml.load(open(args.configPlatformDefines));
        recursiveMerge(configDefines, configPlatformDefines)

    libraryDir = os.path.abspath(os.path.normpath(args.inputDir))
    configFilePath = os.path.join(libraryDir, "include/polarssl/config.h")
    checkConfigFilePath = os.path.join(libraryDir, "include/polarssl/check_config.h")

    patchConfigFile(configDefines, configFilePath)
    patchCheckConfigFile(configDefines, checkConfigFilePath)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
