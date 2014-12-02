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
    for (size_t pos = 0; pos < virgilByteArray.size(); ++pos) { \
        unsigned char value = virgilByteArray.at(pos); \
        inline_as3( \
            ""#actionScriptByteArray".writeByte(%0);\n" \
            ::"r"(value) \
        ); \
    } \
    inline_as3( \
        ""#actionScriptByteArray".position = 0;\n" \
    ); \
} while (0)

#define AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(actionScriptByteArray, virgilByteArray) \
do { \
    size_t actionScriptByteArray##Size = 0; \
    size_t actionScriptByteArray##Position = 0; \
    inline_as3( \
        "%0 = "#actionScriptByteArray".length;\n" \
        "%1 = "#actionScriptByteArray".position;\n" \
        ""#actionScriptByteArray".position = 0;\n" \
        :"=r"(actionScriptByteArray##Size), "=r"(actionScriptByteArray##Position) \
    ); \
    for (size_t pos = 0; pos < actionScriptByteArray##Size; ++pos) { \
        int value = 0; \
        inline_as3( \
            "%0 = "#actionScriptByteArray".readByte();\n" \
            :"=r"(value) \
        ); \
        virgilByteArray.push_back((unsigned char)value); \
    } \
    inline_as3( \
        ""#actionScriptByteArray".position = %0;\n" \
        ::"r"(actionScriptByteArray##Position) \
    ); \
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

