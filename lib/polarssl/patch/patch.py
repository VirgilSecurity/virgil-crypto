#! /usr/bin/python

import os
import fileinput
import re

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

def parseArguments():
    """Parse given arguments
    """
    parser = argparse.ArgumentParser(description=
        "Use this utility to patch PolarSSL library add extended it functionality.");
    parser.add_argument("-i", "--input", dest="input", help="input directoty", required=True)
    parser.add_argument("-c", "--config-name", dest="configFileName", help="configuration file name", required=True)
    return parser.parse_args()

def patchConfigFile(settings, configFilePath):
    """Patch PolarSSL config.h file
    """
    # Comment macros from the settings list
    commentMacrosSet = settings["config_file"]["comment_macros"]
    for line in fileinput.input(configFilePath, inplace=True):
        for commentMacros in commentMacrosSet:
            pattern = r'^[\s]*(#define[\s]+' + commentMacros + ')'
            if re.match(pattern, line):
                line = re.sub(pattern, r'//\1', line)
                break;
        sys.stdout.write(line)
    # Uncomment macros from the settings list
    uncommentMacrosSet = settings["config_file"]["uncomment_macros"]
    for line in fileinput.input(configFilePath, inplace=True):
        for uncommentMacros in uncommentMacrosSet:
            pattern = r'^[\s]*//[\s]*(#define[\s]+' + uncommentMacros + ')'
            if re.match(pattern, line):
                line = re.sub(pattern, r'\1', line)
                break;
        sys.stdout.write(line)

    customMacroses = settings["config_file"]["new_macros"];
    addMacrosAfterRe = settings["config_file"]["add_new_macros_after_regex"]
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
    customMacroses = settings["config_file"]["check_macros"];
    addMacrosAfterRe = settings["config_file"]["add_check_macros_after_regex"]
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
    for header in settings["library_new_headers"]:
        shutil.copy(os.path.join(srcDir, header), dstDir)

def addNewSources(settings, srcDir, dstDir):
    """Add new source files to destination folder
    """
    for header in settings["library_new_sources"]:
        shutil.copy(os.path.join(srcDir, header), dstDir)

def insertObjectsToFile(filePath, insertedObjects, insertedPositionRegEx, additionalEndlineDelimeter):
    with open (filePath, "r") as editedFile:
        editedFileContent = editedFile.read()

    insertedObjectsFiltered = set()
    for insertedObjectCandidate in insertedObjects:
        if not insertedObjectCandidate in editedFileContent:
            insertedObjectsFiltered.add(insertedObjectCandidate)

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
    insertedObjects = settings["library_makefile_objects"]["objects"]
    insertedPositionRegEx = settings["library_makefile_objects"]["add_after_regex"]
    additionalEndlineDelimeter = settings["library_makefile_objects"]["additional_endline_delimeter"]
    insertObjectsToFile(makeFilePath, insertedObjects, insertedPositionRegEx, additionalEndlineDelimeter)

def addNewObjectsToCMakeBuildPhase(settings, makeFilePath):
    """Patch library\CMakeLists.txt file
    """
    insertedObjects = settings["library_cmakelists_objects"]["objects"]
    insertedPositionRegEx = settings["library_cmakelists_objects"]["add_after_regex"]
    additionalEndlineDelimeter = settings["library_cmakelists_objects"]["additional_endline_delimeter"]
    insertObjectsToFile(makeFilePath, insertedObjects, insertedPositionRegEx, additionalEndlineDelimeter)

def applySvnPatches(settings, patchFilesDir, polarsslRootDir):
    """Apply svn patches to cuurent working copy
    """

    with makeTempDir() as tmpDir:

        patchFileNameList = settings["library_svn_patch_files"]

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
    libraryDir = os.path.abspath(os.path.normpath(args.input))
    configFileName = args.configFileName

    currentDir = os.path.dirname(os.path.abspath(__file__))
    patchFilesDir = currentDir

    settings = yaml.load(open(os.path.join(patchFilesDir, configFileName)));

    configFilePath = os.path.join(libraryDir, "include/polarssl/config.h")
    checkConfigFilePath = os.path.join(libraryDir, "include/polarssl/check_config.h")
    libraryMakeFilePath = os.path.join(libraryDir, "library/Makefile")
    libraryCMakeFilePath = os.path.join(libraryDir, "library/CMakeLists.txt")
    libraryIncludeDir = os.path.join(libraryDir, "include/polarssl")
    librarySourceDir = os.path.join(libraryDir, "library")

    patchConfigFile(settings, configFilePath)
    patchCheckConfigFile(settings, checkConfigFilePath)
    addNewHeaders(settings, patchFilesDir, libraryIncludeDir)
    addNewSources(settings, patchFilesDir, librarySourceDir)
    addNewObjectsToMakeBuildPhase(settings, libraryMakeFilePath)
    addNewObjectsToCMakeBuildPhase(settings, libraryCMakeFilePath)
    applySvnPatches(settings, patchFilesDir, libraryDir)

if __name__ == "__main__":
    sys.exit(main(sys.argv))

