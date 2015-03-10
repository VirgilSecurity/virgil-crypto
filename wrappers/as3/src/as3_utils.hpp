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

#ifndef AS3_UTILS_HPP
#define AS3_UTILS_HPP

#include <AS3/AS3.h>
#include <AS3/AS3++.h>

#include <stdexcept>

#define kPackage "com.virgilsecurity.wrapper"

#define AS3_VAR_IS_DEFINED(asVar, cResult) inline_as3("%0 = "#asVar" != null;\n" : "=r"(cResult))

#define AS3_DECL_FUNC(funcName, paramsAndReturnValue) \
__attribute__(( \
    annotate("as3import:flash.utils.ByteArray"), \
    annotate("as3sig:public function "#funcName""paramsAndReturnValue), \
    annotate("as3package:"kPackage) \
)) \
void funcName()

#define AS3_RETURN_VOID() AS3_ReturnAS3Var(undefined)

#define AS3_RETURN_C_PTR(cVar) \
do { \
    AS3_DeclareVar(asVar, int); \
    AS3_CopyScalarToVar(asVar, cVar); \
    AS3_ReturnAS3Var(asVar); \
} while (0)

#define AS3_RETURN_C_SCALAR(cVar, asScalarType) \
do { \
    AS3_DeclareVar(asVar, asScalarType); \
    AS3_CopyScalarToVar(asVar, cVar); \
    AS3_ReturnAS3Var(asVar); \
} while (0)

#define AS3_RETURN_C_BOOL(cVar) AS3_RETURN_C_SCALAR(cVar, Boolean)
#define AS3_RETURN_C_INT(cVar) AS3_RETURN_C_SCALAR(cVar, int)
#define AS3_RETURN_C_UINT(cVar) AS3_RETURN_C_SCALAR(cVar, uint)
#define AS3_RETURN_C_ENUM(cVar) AS3_RETURN_C_SCALAR(cVar, uint)

#define AS3_TO_C_PTR(className, asVar, cVar) \
    className *cVar = (className *)0; \
    AS3_GetScalarFromVar(cVar, asVar)

#define AS3_TO_C_VAR(asVar, cVar) \
    AS3::local::var cVar; \
    AS3_GetVarxxFromVar(cVar, asVar);

#define AS3_TO_C_SCALAR(asVar, cVar, cScalarType) \
    cScalarType cVar = (cScalarType)0; \
    AS3_GetScalarFromVar(cVar, asVar)

#define AS3_TO_C_BOOL(asVar, cVar) AS3_TO_C_SCALAR(asVar, cVar, bool)
#define AS3_TO_C_UINT(asVar, cVar) AS3_TO_C_SCALAR(asVar, cVar, size_t)
#define AS3_TO_C_INT(asVar, cVar) AS3_TO_C_SCALAR(asVar, cVar, int)
#define AS3_TO_C_ENUM(enumType, asVar, cVar) AS3_TO_C_SCALAR(asVar, cVar, enumType)

#define AS3_FROM_C_BYTE_ARRAY(cByteArray, asByteArray) \
do { \
    inline_as3( \
        "var "#asByteArray":ByteArray = new ByteArray();\n" \
    ); \
    if (!cByteArray.empty()) { \
        inline_as3( \
            "com.adobe.flascc.CModule.readBytes(%0, %1, "#asByteArray");\n" \
            ""#asByteArray".position = 0;\n" \
            : : "r"(cByteArray.data()), "r"(cByteArray.size()) \
        ); \
    } \
} while (0)

#define AS3_TO_C_BYTE_ARRAY_NO_DECL(asByteArray, cByteArray) \
do { \
    size_t asByteArray##Size = 0; \
    inline_as3( \
        "%0 = "#asByteArray".length;\n" \
        :"=r"(asByteArray##Size) \
    ); \
    if (asByteArray##Size > 0) { \
        cByteArray.resize(asByteArray##Size); \
        inline_as3( \
            "var currPos:uint = "#asByteArray".position;\n" \
            ""#asByteArray".position = 0;\n" \
            "com.adobe.flascc.CModule.writeBytes(%0, %1, "#asByteArray");\n" \
            ""#asByteArray".position = currPos;\n" \
            : : "r"(cByteArray.data()), "r"(cByteArray.size()) \
        ); \
    } else { \
        cByteArray.clear(); \
    } \
} while (0)

#define AS3_TO_C_BYTE_ARRAY(asByteArray, cByteArray) \
    VirgilByteArray cByteArray; \
    AS3_TO_C_BYTE_ARRAY_NO_DECL(asByteArray, cByteArray)

#define AS3_TO_C_BYTE_ARRAY_OPT(asByteArray, cByteArray) \
VirgilByteArray cByteArray; \
do { \
    bool cByteArrayDefined = false; \
    AS3_VAR_IS_DEFINED(asByteArray, cByteArrayDefined); \
    if (cByteArrayDefined) { \
        AS3_TO_C_BYTE_ARRAY_NO_DECL(asByteArray, cByteArray); \
    } \
} while (0)

#define AS3_RETURN_C_BYTE_ARRAY(cVar) \
do { \
    AS3_FROM_C_BYTE_ARRAY(cVar, asVar); \
    AS3_ReturnAS3Var(asVar); \
} while (0)

#define AS3_TO_STD_STRING(asString, stdString) \
std::string stdString; \
do { \
    char *c_str_ = NULL; \
    AS3_MallocString(c_str_, asString); \
    stdString = AS3::sz2stringAndFree(c_str_); \
} while(0)

#define AS3_FROM_STD_STRING(stdString, asString) \
do { \
    const std::string& stdStringRef = stdString; \
    AS3_DeclareVar(asString, String); \
    AS3_CopyCStringToVar(asString, const_cast<char* >(stdStringRef.data()), stdStringRef.size()); \
} while(0)

#define AS3_RETURN_STD_STRING(stdVar) \
do { \
    AS3_FROM_STD_STRING(stdVar, asVar); \
    AS3_ReturnAS3Var(asVar); \
} while (0)

#define AS3_THROW_EXCEPTION(cMessage) \
do { \
    AS3_FROM_STD_STRING(std::string(cMessage), asErrorMessage); \
    inline_as3("throw new Error(asErrorMessage);"); \
} while (0)

#define AS3_THROWABLE_SECTION_START \
    try {
#define AS3_THROWABLE_SECTION_END \
    } catch (const std::exception& exception) { \
        AS3_THROW_EXCEPTION(exception.what()); \
    } catch (...) { \
        AS3_THROW_EXCEPTION("Undefined exception was occured."); \
    }

#define AS3_IMPL_CONSTRUCTOR(className) \
AS3_DECL_FUNC(_wrap_new_##className, "():int") { \
    className *cSelf = new className(); \
    AS3_RETURN_C_PTR(cSelf); \
}

#define AS3_DECL_THROWABLE_CONSTRUCTOR(className) \
AS3_DECL_FUNC(_wrap_new_##className, "():int") { \
    AS3_THROWABLE_SECTION_START \
        className *cSelf = new className(); \
        AS3_RETURN_C_PTR(cSelf); \
    AS3_THROWABLE_SECTION_END \
}

#define AS3_IMPL_DESTRUCTOR(className) \
AS3_DECL_FUNC(_wrap_delete_##className, "(asSelf):void") { \
    AS3_TO_C_PTR(className, asSelf, cSelf); \
    delete cSelf; \
    AS3_RETURN_VOID(); \
}


#endif /* AS3_UTILS_HPP */

