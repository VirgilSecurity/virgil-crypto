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

cmake_minimum_required (VERSION 2.8 FATAL_ERROR)

project (${WRAPPED_LIB_NAME}_javascript)

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set (JS_INSTALL_DIR js)
set (JS_MODULE_NAME ${PROJECT_NAME})
set (SWIG_MODULE_NAME ${JS_MODULE_NAME})

find_package (SWIG REQUIRED)
include (${SWIG_USE_FILE})

set (CMAKE_SWIG_FLAGS "")

set (SWIG_WRAP_LOW_LEVEL_API YES)
set (SWIG_WRAP_COPY_CONSTRUCTOR YES)
set (WRAPPER_INTERFACE_FILE "${CMAKE_CURRENT_BINARY_DIR}/wrapper.i")
configure_file (
    "${wrappers_SOURCE_DIR}/swig/wrapper.i.in"
    "${WRAPPER_INTERFACE_FILE}"
)

set_property (SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY CPLUSPLUS ON)
set_property (
    SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY SWIG_FLAGS "-ignoremissing" "-node"
)

# Generate SWIG wrapper
macro (SWIG_GENERATE_MODULE name language)
  SWIG_MODULE_INITIALIZE (${name} ${language})
  set (swig_dot_i_sources)
  set (swig_other_sources)
  foreach (it ${ARGN})
    if (${it} MATCHES ".*\\.i$")
      set (swig_dot_i_sources ${swig_dot_i_sources} "${it}")
    else ()
      set (swig_other_sources ${swig_other_sources} "${it}")
    endif ()
  endforeach ()

  set(swig_generated_sources)
  foreach(it ${swig_dot_i_sources})
    SWIG_ADD_SOURCE_TO_MODULE(${name} swig_generated_source ${it})
    set(swig_generated_sources ${swig_generated_sources} "${swig_generated_source}")
  endforeach()
  get_directory_property(swig_extra_clean_files ADDITIONAL_MAKE_CLEAN_FILES)
  set_directory_properties(PROPERTIES
    ADDITIONAL_MAKE_CLEAN_FILES "${swig_extra_clean_files};${swig_generated_sources}")
endmacro ()

swig_generate_module (${JS_MODULE_NAME} javascript ${WRAPPER_INTERFACE_FILE})

# Confugure GYP file
function (LIST_TO_JSON_ARRAY list json_array)
    set (result "[")
    foreach (element ${list})
        if (${element} MATCHES '^"[.]*$"' OR ${element} MATCHES "^'[.]*$'")
            set (result "${result}${element},")
        else ()
            set (result "${result}\"${element}\",")
        endif ()
    endforeach ()
    set (result "${result}]")
    set (${json_array} ${result} PARENT_SCOPE)
endfunction (LIST_TO_JSON_ARRAY)

# Define includes for JS node
set (JS_INCLUDES "${${WRAPPED_LIB_NAME}_SOURCE_DIR}/include")
list_to_json_array (${JS_INCLUDES} JS_INCLUDES_JSON_ARRAY)

# Define libraries for JS node
set (JS_LIBRARIES_JSON_ARRAY "['-L${EXTERNAL_LIBS_DIR}','-lmbedtls','-l${WRAPPED_LIB_NAME}']")

# Configure node-gyp build file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/binding.gyp.in
    ${CMAKE_CURRENT_BINARY_DIR}/binding.gyp
    @ONLY
)

# Build JS wrapper
find_program (NODE_GYP "node-gyp")

add_custom_target (JS_NODE ALL
        COMMAND ${NODE_GYP} "configure" "build" "--verbose"
        DEPENDS ${swig_generated_sources}
        COMMENT "Build nodejs module."
    )

install (PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/build/Release/${JS_MODULE_NAME}.node"
        DESTINATION "${JS_INSTALL_DIR}/${INSTALL_LIB_DIR_NAME}")
