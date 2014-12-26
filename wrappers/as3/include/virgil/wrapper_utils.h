/**
 * Copyright (C) 2014 Virgil Security Inc.
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

#ifndef VIRGIL_WRAPPER_UTILS_H
#define VIRGIL_WRAPPER_UTILS_H

#include <AS3/AS3.h>
#include <AS3/AS3++.h>

#include <stdexcept>

#define VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(virgilByteArray, actionScriptByteArray) \
do { \
    inline_as3( \
        "var "#actionScriptByteArray":ByteArray = new ByteArray();\n" \
    ); \
    if (!virgilByteArray.empty()) { \
        inline_as3( \
            "com.adobe.flascc.CModule.readBytes(%0, %1, "#actionScriptByteArray");\n" \
            ""#actionScriptByteArray".position = 0;\n" \
            : : "r"(virgilByteArray.data()), "r"(virgilByteArray.size()) \
        ); \
    } \
} while (0)

#define AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(actionScriptByteArray, virgilByteArray) \
do { \
    size_t actionScriptByteArray##Size = 0; \
    inline_as3( \
        "%0 = "#actionScriptByteArray".length;\n" \
        :"=r"(actionScriptByteArray##Size) \
    ); \
    if (actionScriptByteArray##Size > 0) { \
        virgilByteArray.resize(actionScriptByteArray##Size); \
        inline_as3( \
            "var currPos:uint = "#actionScriptByteArray".position;\n" \
            ""#actionScriptByteArray".position = 0;\n" \
            "com.adobe.flascc.CModule.writeBytes(%0, %1, "#actionScriptByteArray");\n" \
            ""#actionScriptByteArray".position = currPos;\n" \
            : : "r"(virgilByteArray.data()), "r"(virgilByteArray.size()) \
        ); \
    } else { \
        virgilByteArray.clear(); \
    } \
} while (0)

#define AS3_STRING_TO_STD_STRING(actionScriptString, stdString) \
do { \
    char *c_str_ = NULL; \
    AS3_MallocString(c_str_, actionScriptString); \
    stdString = AS3::sz2stringAndFree(c_str_); \
} while(0)

#define STD_STRING_TO_AS3_STRING(stdString, actionScriptString) \
do { \
    const std::string& stdStringRef = stdString; \
    AS3_DeclareVar(actionScriptString, String); \
    AS3_CopyCStringToVar(actionScriptString, const_cast<char* >(stdStringRef.data()), stdStringRef.size()); \
} while(0)

#define AS3_THROW_EXCEPTION(cMessage) \
do { \
    STD_STRING_TO_AS3_STRING(std::string(cMessage), asErrorMessage); \
    inline_as3("throw new Error(asErrorMessage);"); \
} while (0)

#define AS3_VAR_IS_DEFINED(asVar, cResult) inline_as3("%0 = "#asVar" != null;\n" : "=r"(cResult))

#define WRAPPER_THROWABLE_SECTION_START \
    try {
#define WRAPPER_THROWABLE_SECTION_END \
    } catch (const std::exception& exception) { \
        AS3_THROW_EXCEPTION(exception.what()); \
    } catch (...) { \
        AS3_THROW_EXCEPTION("Undefined exception was occured."); \
    }

#define GEN_CONSTRUCTOR(className, package) \
__attribute__(( \
    annotate("as3sig:public function _wrap_new_"#className"():int"), \
    annotate("as3package:"#package) \
)) \
void _wrap_new_##className() { \
    className *self_ = new className(); \
    AS3_DeclareVar(asresult, int); \
    AS3_CopyScalarToVar(asresult, self_); \
    AS3_ReturnAS3Var(asresult); \
}

#define GEN_THROWABLE_CONSTRUCTOR(className, package) \
__attribute__(( \
    annotate("as3sig:public function _wrap_new_"#className"():int"), \
    annotate("as3package:"#package) \
)) \
void _wrap_new_##className() { \
WRAPPER_THROWABLE_SECTION_START \
    className *self_ = new className(); \
    AS3_DeclareVar(asresult, int); \
    AS3_CopyScalarToVar(asresult, self_); \
    AS3_ReturnAS3Var(asresult); \
WRAPPER_THROWABLE_SECTION_END \
}

#define GEN_DESTRUCTOR(className, package) \
__attribute__(( \
    annotate("as3sig:public function _wrap_delete_"#className"(self):void"), \
    annotate("as3package:"#package) \
)) \
void _wrap_delete_##className() { \
    className *self_ = (className *)0; \
    AS3_GetScalarFromVar(self_, self); \
    delete self_; \
    AS3_ReturnAS3Var(undefined); \
}

#endif /* VIRGIL_WRAPPER_UTILS_H */

