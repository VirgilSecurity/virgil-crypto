#!/usr/bin/perl
#
# Copyright (C) 2015-2018 Virgil Security Inc.
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
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#

# Usage: patch_embind.pl path_to_original_embind.h path_to_patched_embind.h

use strict;
use warnings;

open(my $in_file, '<', $ARGV[0]) or die "Could not open file '$ARGV[0]' $!";
open(my $out_file, '>', $ARGV[1]) or die "Could not open file '$ARGV[1]' $!";

my $INITIAL = "Initial";
my $INVOKE_DECL_DETECTED = "InvokeDeclDetected";
my $INVOKE_BODY_DETECTED = "InvokeBodyDetected";
my $INVOKE_BODY_PROCESSING = "InvokeBodyProcessing";

my $state = $INITIAL;
my $spaces = "";
my $tab = "    ";

my $exception_handle = <<"END_MESSAGE";
#include <sstream>
#include <stdexcept>
#include <exception>

namespace emscripten { namespace internal {
    extern "C" {
        void _virgil_throw_error(const char* message) __attribute__((noreturn));
    }

    void _virgil_handle_exception(const std::exception& exception) __attribute__((noreturn));

    std::string backtrace_message(const std::exception& exception, int level = 0) {
        std::ostringstream sstr;
        sstr << exception.what();
        try {
            std::rethrow_if_nested(exception);
        } catch(const std::exception& nested) {
            sstr << "\\n" << backtrace_message(nested, level);
        } catch(...) {}
        return sstr.str();
    }

    void _virgil_handle_exception(const std::exception& exception) {
        _virgil_throw_error(backtrace_message(exception).c_str());
    }
}}
END_MESSAGE

while (my $line = <$in_file>) {
    my $patched_line = $line;

    if ($line =~ /#include\s+<emscripten\/wire\.h>/) {
        $patched_line = $line."\n".$exception_handle;
    } elsif ($state eq $INITIAL) {
        if ($line =~ /static.+invoke\s*\(/) {
            $state = $INVOKE_DECL_DETECTED;
        }
    } elsif ($state eq $INVOKE_DECL_DETECTED) {
        if ($line =~ /^(\s+)\)\s+{/) {
            $state = $INVOKE_BODY_DETECTED;
            $spaces = $1;
        }
    } elsif ($state eq $INVOKE_BODY_DETECTED) {
        $state = $INVOKE_BODY_PROCESSING;
        $patched_line = $spaces.$tab."try {\n".$tab.$line;
    } elsif ($state eq $INVOKE_BODY_PROCESSING) {
        if ($line =~ /$spaces}/) {
            $state = $INITIAL;
            $patched_line = $spaces.$tab."} catch (const std::exception& ex) {\n";
            $patched_line .= $spaces.$tab.$tab."_virgil_handle_exception(ex);\n";
            $patched_line .= $spaces.$tab."}\n".$line;
        } else {
            $patched_line = $tab.$line;
        }
    }
    $out_file->print($patched_line);
}

close($in_file);
close($out_file);
