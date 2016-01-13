:: Copyright (C) 2015 Virgil Security Inc.
::
:: Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
::
:: All rights reserved.
::
:: Redistribution and use in source and binary forms, with or without
:: modification, are permitted provided that the following conditions are
:: met:
::
::     (1) Redistributions of source code must retain the above copyright
::     notice, this list of conditions and the following disclaimer.
::
::     (2) Redistributions in binary form must reproduce the above copyright
::     notice, this list of conditions and the following disclaimer in
::     the documentation and/or other materials provided with the
::     distribution.
::
::     (3) Neither the name of the copyright holder nor the names of its
::     contributors may be used to endorse or promote products derived from
::     this software without specific prior written permission.
::
:: THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
:: IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
:: WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
:: DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
:: INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
:: (INCLUDING, BUT NOT LIMITED TO, PROCUremENT OF SUBSTITUTE GOODS OR
:: SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
:: HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
:: STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
:: IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
:: POSSIBILITY OF SUCH DAMAGE.

:: This script helps to build Virgil Security Crypto library under Windows OS with MSVC toolchain.

@echo off
setlocal

:: Prepare environment variables
if defined MSVC_ROOT call :remove_quotes MSVC_ROOT
if defined JAVA_HOME call :remove_quotes JAVA_HOME

:: Check environment prerequisite
if "%MSVC_ROOT%" == "" goto error_not_msvc_root
if not exist "%MSVC_ROOT%\VC\vcvarsall.bat" goto :error_vcvarsall_not_found

:: Define script global variables
set CURRENT_DIR=%CD%
set SCRIPT_DIR=%~dp0

:: Parse input parameters
if not "%1" == "" (
    set TARGET=%1
) else (
    set TARGET=cpp
)
call :show_info TARGET: %TARGET%

set "TARGET_NAME=%TARGET:-="^&REM #%
set "TARGET_VERSION=%TARGET:*-=%"
if "%TARGET_NAME%" == "%TARGET_VERSION%" set TARGET_VERSION=

call :show_info TARGET_NAME: %TARGET_NAME%
if not "%TARGET_VERSION%" == "" call :show_info TARGET_VERSION: %TARGET_VERSION%

if not "%2" == "" (
    call :abspath SRC_DIR=%2
) else (
    set SRC_DIR=%CURRENT_DIR%
)
call :show_info SRC_DIR: %SRC_DIR%

if not "%3" == "" (
    mkdir %3 2>nul || REM Ignore error during creation
    call :abspath BUILD_DIR=%3
) else (
    set BUILD_DIR=%CURRENT_DIR%\build\%TARGET%
)
call :show_info BUILD_DIR: %BUILD_DIR%

if not "%4" == "" (
    mkdir %4 2>nul || REM Ignore error during creation
    call :abspath INSTALL_DIR=%4
) else (
    set INSTALL_DIR=%CURRENT_DIR%\install\%TARGET%
    mkdir %INSTALL_DIR% 2>nul || REM Ignore error during creation
)
call :show_info INSTALL_DIR: %INSTALL_DIR%

:: Configure common CMake parameters
set CMAKE_ARGS=-DCMAKE_BUILD_TYPE=Release -G"NMake Makefiles"

:: Prepare build and install directories
mkdir %BUILD_DIR% %INSTALL_DIR% 2>nul
call :clean_dirs %BUILD_DIR% %INSTALL_DIR%
cd "%BUILD_DIR%"

:: Route target build
if "%TARGET_NAME%" == "cpp" goto cpp
if "%TARGET_NAME%" == "java" goto java
if "%TARGET_NAME%" == "net" goto net
if "%TARGET_NAME%" == "nodejs" goto nodejs

:: No supported target was found
goto error_target_not_supported

:cpp
goto native
goto :eof

:java
if "%JAVA_HOME%" == "" goto error_not_java_home
goto native
goto :eof

:nodejs
if not "%TARGET_VERSION%" == "" (
    set CMAKE_ARGS=%CMAKE_ARGS% -DLANG_VERSION=%TARGET_VERSION%
)
goto native
goto :eof

:net
:: Build x86 architecture
setlocal
    set PLATFORM_ARCH=x86
    call :clean_dirs %BUILD_DIR%
    call :configure_%PLATFORM_ARCH%
    set CMAKE_ARGS=%CMAKE_ARGS% -DPLATFORM_ARCH=%PLATFORM_ARCH% -DCMAKE_INSTALL_PREFIX="%INSTALL_DIR%"
    cmake %CMAKE_ARGS% -DLANG=%TARGET_NAME% "%SRC_DIR%" || goto end
    nmake && nmake install || goto end
endlocal
:: Build x64 architecture
setlocal
    set PLATFORM_ARCH=x64
    call :clean_dirs %BUILD_DIR%
    call :configure_%PLATFORM_ARCH%
    set CMAKE_ARGS=%CMAKE_ARGS% -DPLATFORM_ARCH=%PLATFORM_ARCH% -DCMAKE_INSTALL_PREFIX="%INSTALL_DIR%"
    cmake %CMAKE_ARGS% -DLANG=%TARGET_NAME% "%SRC_DIR%" || goto end
    nmake && nmake install || goto end
endlocal
:: Make .NET specific file organization
xcopy /y/q "%SRC_DIR%\VERSION" "%INSTALL_DIR%" >nul
set /p ARCHIVE_NAME=<lib_name.txt
call :archive_artifacts %INSTALL_DIR% %ARCHIVE_NAME%
goto :eof

:native
:: Build x86 architecture
setlocal
    set PLATFORM_ARCH=x86
    set INSTALL_DIR=%INSTALL_DIR%\%PLATFORM_ARCH%
    call :clean_dirs %BUILD_DIR%
    call :configure_%PLATFORM_ARCH%
    set CMAKE_ARGS=%CMAKE_ARGS% -DPLATFORM_ARCH=%PLATFORM_ARCH% -DCMAKE_INSTALL_PREFIX="%INSTALL_DIR%"
    cmake %CMAKE_ARGS% -DLANG=%TARGET_NAME% "%SRC_DIR%" || goto end
    nmake && nmake install || goto end
    xcopy /y/q "%SRC_DIR%\VERSION" "%INSTALL_DIR%" >nul
    set /p ARCHIVE_NAME=<lib_name_full.txt
    call :archive_artifacts %INSTALL_DIR% %ARCHIVE_NAME%
endlocal
:: Build x64 architecture
setlocal
    set PLATFORM_ARCH=x64
    set INSTALL_DIR=%INSTALL_DIR%\%PLATFORM_ARCH%
    call :clean_dirs %BUILD_DIR%
    call :configure_%PLATFORM_ARCH%
    set CMAKE_ARGS=%CMAKE_ARGS% -DPLATFORM_ARCH=%PLATFORM_ARCH% -DCMAKE_INSTALL_PREFIX="%INSTALL_DIR%"
    cmake %CMAKE_ARGS% -DLANG=%TARGET_NAME% "%SRC_DIR%" || goto end
    nmake && nmake install || goto end
    xcopy /y/q "%SRC_DIR%\VERSION" "%INSTALL_DIR%" >nul
    set /p ARCHIVE_NAME=<lib_name_full.txt
    call :archive_artifacts %INSTALL_DIR% %ARCHIVE_NAME%
endlocal
goto :eof

:: usage: call :archive_artifacts <src_dir> <archive_name>
:archive_artifacts
call :pack_and_zip %1 %2
goto :eof

:: Utility functions
:abspath
pushd %2
set %1=%CD%
popd
goto :eof

:remove_quotes
for /f "delims=" %%A in ('echo %%%1%%') do set %1=%%~A
goto :eof

:show_info
echo [INFO] %*
goto :eof

:show_warning
echo [WARNING] %*
goto :eof

:show_error
echo [ERROR] %*
goto :eof

:configure_x86
call "%MSVC_ROOT%\VC\vcvarsall.bat" x86
goto :eof

:configure_x64
call "%MSVC_ROOT%\VC\vcvarsall.bat" x64
goto :eof

:: Remove content of the given directories.
:: usage: call :clean_dirs <path_to_dir> ...
:clean_dirs
for %%x in (%*) do (
    if exist "%%~x" (
        pushd %%~x
        for /F "delims=" %%i in ('dir /b') do (rmdir /s/q "%%i" 2>nul || del /s/q "%%i" >nul)
        popd
    )
)
goto :eof

:: Move content of the given directory to the dir and zip it.
:: usage: call :pack_and_zip <src_dir> <dir_name>
:pack_and_zip
pushd %1
for /F "delims=" %%i in ('dir /b') do (
    if not exist "%2" mkdir "%2"
    move /y "%%i" "%2" > nul
)
CScript "%SCRIPT_DIR%\zip.vbs" "%2" "%2.zip" >nul && rmdir /s/q "%2"
popd
goto :eof

:: Errors
:error_not_msvc_root
echo MSVC_ROOT environment variable is not defined
echo Please set environment variable MSVC_ROOT to point 'Microsoft Visual Studio' install directory.
goto :eof

:error_not_java_home
echo JAVA_HOME environment variable is not defined
echo Please set environment variable JAVA_HOME to point JDK install directory.
goto :eof

:error_vcvarsall_not_found
echo Can not found vcvarsall.bat under %MSVC_ROOT%\VC directory.
goto :eof

:error_target_not_supported
call :show_error Target with name '%TARGET_NAME%' is not supported.
goto :eof

:end
if %errorlevel% neq 0 exit /b %errorlevel%
goto :eof
