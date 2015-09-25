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

# Dependecy to https://github.com/nlohmann/json

# Configure external project
if (NOT TARGET project_json)
    ExternalProject_Add (project_json
        GIT_REPOSITORY "https://github.com/nlohmann/json.git"
        PREFIX "${CMAKE_CURRENT_BINARY_DIR}/ext/json"
        CMAKE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND ""
        TEST_COMMAND ""
    )
endif ()

# Configure output
ExternalProject_Get_Property (project_json PREFIX)
set (JSON_INCLUDE_DIRS "${PREFIX}/src/project_json/src")

# Workaround of http://public.kitware.com/Bug/view.php?id=14495
file (MAKE_DIRECTORY ${JSON_INCLUDE_DIRS})

# Make target
if (NOT TARGET json)
    add_library (json INTERFACE IMPORTED)
    set_target_properties (json PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${JSON_INCLUDE_DIRS}
    )
    add_dependencies (json project_json)
endif ()
