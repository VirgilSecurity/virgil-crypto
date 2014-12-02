#
# Copyright (C) 2014 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

#
# @brief Defines pointer size for current compiler.
# @return pointer size in bytes thru @param 'pointer_size'
#
function (check_pointer_size pointer_size)

file (WRITE
    ${CMAKE_BINARY_DIR}/CMakeTmp/check_pointer_size.cxx
    "int main() { void *ptr = 0; return sizeof(ptr); }"
)

try_run (
    RUN_RESULT
    COMPILE_RESULT
    ${CMAKE_BINARY_DIR}
    ${CMAKE_BINARY_DIR}/CMakeTmp/check_pointer_size.cxx
    OUTPUT_VARIABLE OUTPUT
)

if (COMPILE_RESULT AND RUN_RESULT GREATER 0)
    set (${pointer_size} ${RUN_RESULT} PARENT_SCOPE)
else ()
    unset (${pointer_size} PARENT_SCOPE)
endif ()

endfunction (check_pointer_size)
