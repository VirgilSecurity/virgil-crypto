/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Define type map for size_t
%apply unsigned int { size_t };

// Ignore C++ operators
%ignore operator=;
%ignore operator==;

// Language specific includes
#if defined(SWIGPHP)
    %include "php/common.i"
#endif

#if defined(SWIGCSHARP)
    %include "csharp/common.i"
#endif

#if defined(SWIGJAVA)
    %include "java/common.i"
#endif

#if defined(SWIGGO)
    %include "go/common.i"
#endif

// Define VirgilByteArray typemap if was not defined yet
#ifndef SWIG_VIRGIL_BYTE_ARRAY
#define SWIG_VIRGIL_BYTE_ARRAY
%include <std_vector.i>
namespace std {
    %template(VirgilByteArray) vector<unsigned char>;
};
#endif

// Exception handling
%insert("header") %{
#include <virgil/crypto/VirgilCryptoException.h>
%}

%insert("header") %{
#include <sstream>
#include <exception>
static std::string backtrace_message(const std::exception& exception, int level = 0) {
    std::ostringstream sstr;
    sstr << exception.what();
    try {
        std::rethrow_if_nested(exception);
    } catch(const std::exception& nested) {
        sstr << "\n" << backtrace_message(nested, level);
    } catch(...) {}
    return sstr.str();
}
%}

// This code should be commited until SWIG issue "https://github.com/swig/swig/issues/627" is fixed
// #ifdef SWIGPHP
// %feature("director:except") {
//     if ($error == FAILURE) {
//         throw Swig::DirectorMethodException();
//     }
// }
// #endif
%exception {
    try {
        $action
    }
#ifdef SWIGPHP
    catch (Swig::DirectorException &e) {
        SWIG_exception(SWIG_SystemError, e.what());
    }
#endif
#ifdef SWIGJAVA
    catch (const std::exception& exception) {
        jclass clazz = jenv->FindClass("java/lang/Exception");
        jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
        return $null;
    }
    catch (...) {
        jclass clazz = jenv->FindClass("java/lang/Exception");
        jenv->ThrowNew(clazz, "Unknown exception");
        return $null;
    }
#else
    catch (const std::exception& exception) {
        SWIG_exception(SWIG_RuntimeError, backtrace_message(exception).c_str());
    }
    catch (...) {
        SWIG_exception(SWIG_UnknownError, "Unknown exception");
    }
#endif
}
