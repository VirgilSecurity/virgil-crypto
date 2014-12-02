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
# This module can be used as part of the build process to copy files from given directory and all it's subdirectories
#     to the single destination directory.
#
# @example:
#     add_custom_command (TARGET ${tgt} POST_BUILD
#              COMMAND ${CMAKE_COMMAND}
#              ARGS
#                      -DSRC_DIR:PATH=${PATH_TO_SOURCE_DIR}
#                      -DDST_DIR:PATH=${PATH_TO_SOURCE_DESTINATION_DIR}
#                      -DGLOBBING_EXPRESSION:STRING="*.cxx"
#                      -P "${FULL_PATH_TO_THIS_FILE}"
#          )
#

if (NOT SRC_DIR)
    message (FATAL_ERROR "Source directory is not defined. Please define variable SRC_DIR.")
endif ()

if (NOT IS_DIRECTORY ${SRC_DIR})
    message (FATAL_ERROR "Given source directory does not exists: " ${SRC_DIR})
endif ()

if (NOT DST_DIR)
    message (FATAL_ERROR "Destination directory is not defined. Please define variable DST_DIR.")
endif ()

if (NOT GLOBBING_EXPRESSION)
    message (FATAL_ERROR "Globbing expression is not defined. "
            "Please define variable GLOBBING_EXPRESSION to be used as template for coping process.")
endif ()

file (GLOB_RECURSE sources ${SRC_DIR} ${GLOBBING_EXPRESSION})
file (COPY ${sources} DESTINATION ${DST_DIR})
