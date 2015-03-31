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

// C# runtime
#ifdef SWIGWIN
%pragma(csharp) imclasscode=%{
    #region "C# Select architecture dependent folder to load library from"
    protected class VirgilLibLoader
    {
        [System.Runtime.InteropServices.DllImport("kernel32",
                CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        [return: global::System.Runtime.InteropServices.MarshalAs(
                System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool SetDllDirectory(string path);

        static VirgilLibLoader()
        {
            ConfigureWinDllPath(DefineDllPath());
        }

        private static string DefineDllPath()
        {
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            var uri = new System.UriBuilder(assembly.CodeBase);
            var unescapePath = System.Uri.UnescapeDataString(uri.Path + uri.Fragment);
            var directory = System.IO.Path.GetDirectoryName(unescapePath);
            if (directory == null)
            {
                throw new System.IO.DirectoryNotFoundException("VirgilLibLoader: " +
                        "Can not define parent directory of the assembly: " +
                        assembly.FullName + ". At location: " + unescapePath + ".");
            }
            return System.IO.Path.Combine(directory, System.IntPtr.Size == 8 ? "x64" : "x86");
        }

        private static void ConfigureWinDllPath(string path)
        {
            if (!SetDllDirectory(path))
            {
                throw new System.Runtime.InteropServices.ExternalException("Can not add DLL directory: " + path);
            }
        }

    }
    protected static VirgilLibLoader virgilLibLoaderInstance = new VirgilLibLoader();
    #endregion
%}
#endif
