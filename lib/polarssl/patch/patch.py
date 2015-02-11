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
import shutil
import subprocess
import tarfile
import tempfile
import contextlib

@contextlib.contextmanager
def cd(path):
    """Context manager for changing the current working directory"""
    newPath = path
    try:
        savedPath = os.getcwd()
        os.chdir(newPath)
        yield
    finally:
        os.chdir(savedPath)

@contextlib.contextmanager
def makeTempDir(prefix='.tmp'):
    """A context manager for creating and then deleting a temporary directory."""
    tmpdir = tempfile.mkdtemp(prefix=prefix)
    try:
        yield tmpdir
    finally:
        shutil.rmtree(tmpdir)

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
    parser.add_argument("-s", "--config-sources", dest="configSources",
            help="configuration file full name for sources", required=True)
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

def addNewHeaders(settings, srcDir, dstDir):
    """Add new header files to destination folder
    """
    for header in settings["new_headers"]:
        shutil.copy(os.path.join(srcDir, header), dstDir)

def addNewSources(settings, srcDir, dstDir):
    """Add new source files to destination folder
    """
    for header in settings["new_sources"]:
        shutil.copy(os.path.join(srcDir, header), dstDir)

def insertObjectsToFile(filePath, insertedObjects, insertedPositionRegEx, additionalEndlineDelimeter):
    with open (filePath, "r") as editedFile:
        editedFileContent = editedFile.read()

    insertedObjectsFiltered = set()
    for insertedObjectCandidate in insertedObjects:
        if not re.search(r"\s+%s\s+" % (insertedObjectCandidate), editedFileContent):
            insertedObjectsFiltered.add(insertedObjectCandidate)
        else:
            print "WARNING. Inserted object is ommited: %s" % (insertedObjectCandidate)

    objectsWadAdded = False
    for line in fileinput.input(filePath, inplace=True):
        sys.stdout.write(line)
        if not objectsWadAdded and re.match(insertedPositionRegEx, line):
            if len(insertedObjectsFiltered) > 0:
                sys.stdout.write("\t")
            for insertedObject in insertedObjectsFiltered:
                sys.stdout.write(insertedObject + " ")
            if len(insertedObjectsFiltered) > 0:
                sys.stdout.write(additionalEndlineDelimeter + "\n")
            objectsWadAdded = True

def addNewObjectsToMakeBuildPhase(settings, makeFilePath):
    """Patch library\Makefile file
    """
    insertedObjects = settings["makefile_objects"]["objects"]
    insertedPositionRegEx = settings["makefile_objects"]["add_after_regex"]
    additionalEndlineDelimeter = settings["makefile_objects"]["additional_endline_delimeter"]
    insertObjectsToFile(makeFilePath, insertedObjects, insertedPositionRegEx, additionalEndlineDelimeter)

def addNewObjectsToCMakeBuildPhase(settings, makeFilePath):
    """Patch library\CMakeLists.txt file
    """
    insertedObjects = settings["cmakelists_objects"]["objects"]
    insertedPositionRegEx = settings["cmakelists_objects"]["add_after_regex"]
    additionalEndlineDelimeter = settings["cmakelists_objects"]["additional_endline_delimeter"]
    insertObjectsToFile(makeFilePath, insertedObjects, insertedPositionRegEx, additionalEndlineDelimeter)

def applySvnPatches(settings, patchFilesDir, polarsslRootDir):
    """Apply svn patches to cuurent working copy
    """

    with makeTempDir() as tmpDir:

        patchFileNameList = settings["svn_patch_files"]

        for patchFileName in patchFileNameList:
            patchFilePath = os.path.join(patchFilesDir, patchFileName)
            convertedPatchFilePath = os.path.join(tmpDir, patchFileName)

            # Convert endlines to the platform specific
            with open(patchFilePath, 'U') as infile:
                patchFileContent = infile.read()
            with open(convertedPatchFilePath, 'w') as outfile:
                outfile.write(patchFileContent)

            # Patch file
            with cd(polarsslRootDir):
                subprocess.call(["patch", "--force", "--forward", "--strip=0", "--input=" + convertedPatchFilePath])


def main(argv=None):
    if argv is None:
        argv = sys.argv

    args = parseArguments()

    currentDir = os.path.dirname(os.path.abspath(__file__))
    srcDir = os.path.join(currentDir, "src")
    diffDir = os.path.join(currentDir, "diff")

    configDefines = yaml.load(open(args.configDefines));
    if args.configPlatformDefines:
        configPlatformDefines = yaml.load(open(args.configPlatformDefines));
        recursiveMerge(configDefines, configPlatformDefines)

    configSources = yaml.load(open(args.configSources));

    libraryDir = os.path.abspath(os.path.normpath(args.inputDir))
    configFilePath = os.path.join(libraryDir, "include/polarssl/config.h")
    checkConfigFilePath = os.path.join(libraryDir, "include/polarssl/check_config.h")
    libraryMakeFilePath = os.path.join(libraryDir, "library/Makefile")
    libraryCMakeFilePath = os.path.join(libraryDir, "library/CMakeLists.txt")
    libraryIncludeDir = os.path.join(libraryDir, "include/polarssl")
    librarySourceDir = os.path.join(libraryDir, "library")


    patchConfigFile(configDefines, configFilePath)
    patchCheckConfigFile(configDefines, checkConfigFilePath)

    addNewHeaders(configSources, srcDir, libraryIncludeDir)
    addNewSources(configSources, srcDir, librarySourceDir)
    addNewObjectsToMakeBuildPhase(configSources, libraryMakeFilePath)
    addNewObjectsToCMakeBuildPhase(configSources, libraryCMakeFilePath)

    applySvnPatches(configSources, diffDir, libraryDir)

if __name__ == "__main__":
    sys.exit(main(sys.argv))

