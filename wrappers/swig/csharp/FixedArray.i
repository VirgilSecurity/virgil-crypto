/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

/**
 * @file FixedArray.i
 *
 * @brief Typemaps for std::vector<CTYPE> and const std::vector<CTYPE>&
 *
 * These are mapped to a C# fixed size arrays and are passed around by value.
 * @note CTYPE is build-in type, i.e. unsigned char, int, etc.
 *
 * Example: FIXED_ARRAY(unsigned char, byte),
 *     will map std::vector<unsigned char> to the byte[].
 *
 *
 * To use non-const std::vector<CTYPE> references use the following %apply.
 * %apply const std::vector<CTYPE> & {std::vector<CTYPE> &};
 * Note that they are passed by value.
 *
 * @warning This file conflicts with file "std_vector.i".
 */

%define FIXED_ARRAY(CSTYPE,CTYPE)

// std::vector<CTYPE> typemap
%typemap(ctype)  std::vector<CTYPE> %{void *%}
%typemap(imtype) std::vector<CTYPE> %{System.IntPtr%}
%typemap(cstype) std::vector<CTYPE> %{CSTYPE[]%}

%typemap(in, canthrow=1) std::vector<CTYPE>
%{
    if (!$input) {
        SWIG_CSharpSetPendingExceptionArgument(SWIG_CSharpArgumentNullException, "null CSTYPE[]", 0);
        return $null;
    }
    $1.resize(SWIG_csharp_get_managed_##CSTYPE##_array_size($input));
    SWIG_csharp_copy_to_unmanaged_##CSTYPE##_array($input, $1.data(), $1.size());
%}

%typemap(out) std::vector<CTYPE>
%{
    $result = SWIG_csharp_create_managed_##CSTYPE##_array($1.data(), $1.size());
%}

%typemap(csin,
    pre= "    System.Runtime.InteropServices.GCHandle handle$csinput = "
                  "System.Runtime.InteropServices.GCHandle.Alloc($csinput,"
                  "System.Runtime.InteropServices.GCHandleType.Pinned);",
    post="      handle$csinput.Free();"
    ) std::vector<CTYPE> "System.Runtime.InteropServices.GCHandle.ToIntPtr(handle$csinput)"

%typemap(csout, excode=SWIGEXCODE) std::vector<CTYPE>  {
    System.IntPtr csArrayPtr = $imcall;$excode
    if (csArrayPtr == System.IntPtr.Zero) {
        return new CSTYPE[0];
    }
    System.Runtime.InteropServices.GCHandle handle =
            System.Runtime.InteropServices.GCHandle.FromIntPtr(csArrayPtr);
    CSTYPE[] csArray = (handle.Target as CSTYPE[]);
    handle.Free();
    return csArray;
}

%typemap(directorin) std::vector<CTYPE>
%{
    $input = SWIG_csharp_create_managed_##CSTYPE##_array($1.data(), $1.size());
%}

%typemap(directorout, canthrow=1) std::vector<CTYPE>
%{
    if (!$input) {
        SWIG_CSharpSetPendingExceptionArgument(SWIG_CSharpArgumentNullException, "null CSTYPE[]", 0);
        return $null;
    }
    $result.resize(SWIG_csharp_get_managed_##CSTYPE##_array_size($input));
    SWIG_csharp_copy_to_unmanaged_##CSTYPE##_array($input, $result.data(), $result.size());
%}

%typemap(csdirectorin,
         pre= "    System.Runtime.InteropServices.GCHandle handle$iminput = \n"
              "        System.Runtime.InteropServices.GCHandle.FromIntPtr($iminput);"
         ) std::vector<CTYPE> "(handle$iminput.Target as CSTYPE[])"

%typemap(csdirectorout) std::vector<CTYPE>
        "System.Runtime.InteropServices.GCHandle.ToIntPtr(\n"
        "      System.Runtime.InteropServices.GCHandle.Alloc($cscall,\n"
        "      System.Runtime.InteropServices.GCHandleType.Weak))"

// const std::vector<CTYPE>& typemap
%typemap(ctype)  const std::vector<CTYPE> & %{void *%}
%typemap(imtype) const std::vector<CTYPE> & %{System.IntPtr%}
%typemap(cstype) const std::vector<CTYPE> & %{CSTYPE[]%}

%typemap(in, canthrow=1) const std::vector<CTYPE> &
%{
    if (!$input) {
        SWIG_CSharpSetPendingExceptionArgument(SWIG_CSharpArgumentNullException, "null CSTYPE[]", 0);
        return $null;
    }
    $*1_ltype $1_arr(SWIG_csharp_get_managed_##CSTYPE##_array_size($input));
    SWIG_csharp_copy_to_unmanaged_##CSTYPE##_array($input, $1_arr.data(), $1_arr.size());
    $1 = &$1_arr;
%}

%typemap(out) const std::vector<CTYPE> &
%{
    $result = SWIG_csharp_create_managed_##CSTYPE##_array($1->data(), $1->size());
%}

%typemap(csin,
    pre= "    System.Runtime.InteropServices.GCHandle handle$csinput = "
                  "System.Runtime.InteropServices.GCHandle.Alloc($csinput,"
                  "System.Runtime.InteropServices.GCHandleType.Pinned);",
    post="      handle$csinput.Free();"
    ) const std::vector<CTYPE> & "System.Runtime.InteropServices.GCHandle.ToIntPtr(handle$csinput)"

%typemap(csout, excode=SWIGEXCODE) const std::vector<CTYPE> &  {
    System.IntPtr csArrayPtr = $imcall;$excode
    if (csArrayPtr == System.IntPtr.Zero) {
        return new CSTYPE[0];
    }
    System.Runtime.InteropServices.GCHandle handle = System.Runtime.InteropServices.GCHandle.FromIntPtr(csArrayPtr);
    CSTYPE[] array = (handle.Target as CSTYPE[]);
    handle.Free();
    return array;
}

%typemap(directorin) const std::vector<CTYPE> &
%{
    $input = SWIG_csharp_create_managed_##CSTYPE##_array($1.data(), $1.size());
%}

%typemap(directorout, canthrow=1) const std::vector<CTYPE> &
%{
    if (!$input) {
        SWIG_CSharpSetPendingExceptionArgument(SWIG_CSharpArgumentNullException, "null CSTYPE[]", 0);
        return $null;
    }
    static $*1_ltype $1_arr;
    $1_arr.resize(SWIG_csharp_get_managed_##CSTYPE##_array_size($input));
    SWIG_csharp_copy_to_unmanaged_##CSTYPE##_array($input, $1_arr.data(), $1_arr.size());
    $1 = &$1_arr;
%}

%typemap(csdirectorin,
         pre= "    System.Runtime.InteropServices.GCHandle handle$iminput = \n"
              "        System.Runtime.InteropServices.GCHandle.FromIntPtr($iminput);"
         ) const std::vector<CTYPE> & "(handle$iminput.Target as CSTYPE[])"

%typemap(csdirectorout) const std::vector<CTYPE> &
        "System.Runtime.InteropServices.GCHandle.ToIntPtr(\n"
        "      System.Runtime.InteropServices.GCHandle.Alloc($cscall,\n"
        "      System.Runtime.InteropServices.GCHandleType.Weak))"

// common std::vector<CTYPE> and const std::vector<CTYPE> & typemap
%typemap(csvarin, excode=SWIGEXCODE2) std::vector<CTYPE>, const std::vector<CTYPE> & %{
    set {
        System.Runtime.InteropServices.GCHandle handle$csinput = System.Runtime.InteropServices.GCHandle.Alloc(
                $csinput, System.Runtime.InteropServices.GCHandleType.Pinned);
        try {
            $imcall;$excode
        } finally {
            handle$csinput.Free();
        }
    }
%}

%typemap(csvarout, excode=SWIGEXCODE2) std::vector<CTYPE>, const std::vector<CTYPE> & %{
    get {
        System.IntPtr csArrayPtr = $imcall;$excode;
        if (csArrayPtr == System.IntPtr.Zero) {
            return new CSTYPE[0];
        }
        System.Runtime.InteropServices.GCHandle handle =
                System.Runtime.InteropServices.GCHandle.FromIntPtr(csArrayPtr);
        CSTYPE[] csArray = (handle.Target as CSTYPE[]);
        handle.Free();
        return csArray;
    }
%}

// C++ runtime
%insert(runtime) %{
/**
 * @name C++ ArrayHelper callbacks
 * @note Array value type: CTYPE
 */
///@{
/**
 * Create managed CSTYPE array from unmanaged CTYPE array.
 * @return pointer to the managed CSTYPE array: CSTYPE[].
 */
typedef void * (SWIGSTDCALL* SWIG_CSharp_CreateManaged_##CSTYPE##_ArrayCallback)(const CTYPE *, const int);
static SWIG_CSharp_CreateManaged_##CSTYPE##_ArrayCallback SWIG_csharp_create_managed_##CSTYPE##_array = NULL;
/**
 * Return size of the managed CSTYPE array.
 */
typedef int (SWIGSTDCALL* SWIG_CSharp_GetManaged_##CSTYPE##_ArraySizeCallback)(void *);
static SWIG_CSharp_GetManaged_##CSTYPE##_ArraySizeCallback SWIG_csharp_get_managed_##CSTYPE##_array_size = NULL;
/**
 * Copy managed CSTYPE array to the unmanaged CTYPE array.
 */
typedef int (SWIGSTDCALL* SWIG_CSharp_CopyToUnmanaged_##CSTYPE##_ArrayCallback)(void *, CTYPE *, int);
static SWIG_CSharp_CopyToUnmanaged_##CSTYPE##_ArrayCallback SWIG_csharp_copy_to_unmanaged_##CSTYPE##_array = NULL;

#ifdef __cplusplus
extern "C" {
#endif
SWIGEXPORT void SWIGSTDCALL SWIG_CSharp_RegisterCreateManaged_##CSTYPE##_ArrayCallback_$module(
        SWIG_CSharp_CreateManaged_##CSTYPE##_ArrayCallback callback) {
    SWIG_csharp_create_managed_##CSTYPE##_array = callback;
}
SWIGEXPORT void SWIGSTDCALL SWIG_CSharp_RegisterGetManaged_##CSTYPE##_ArraySizeCallback_$module(
        SWIG_CSharp_GetManaged_##CSTYPE##_ArraySizeCallback callback) {
    SWIG_csharp_get_managed_##CSTYPE##_array_size = callback;
}
SWIGEXPORT void SWIGSTDCALL SWIG_CSharp_RegisterCopyToUnmanaged_##CSTYPE##_ArrayCallback_$module(
        SWIG_CSharp_CopyToUnmanaged_##CSTYPE##_ArrayCallback callback) {
    SWIG_csharp_copy_to_unmanaged_##CSTYPE##_array = callback;
}
#ifdef __cplusplus
}
#endif
///@}
%}

// C# runtime
%pragma(csharp) imclasscode=%{
    #region "C# ArrayHelper delegates, array value type: CSTYPE"
    protected class SWIG_##CSTYPE##_ArrayHelper
    {
        #region "Delegate: Translate unmanaged C++ array to managed C# array"
        public delegate System.IntPtr CreateManaged_##CSTYPE##_ArrayDelegate(
                System.IntPtr cppArrayPtr, int cppArraySize);
        static CreateManaged_##CSTYPE##_ArrayDelegate createManaged_##CSTYPE##_ArrayDelegate =
                new CreateManaged_##CSTYPE##_ArrayDelegate(CreateManaged_##CSTYPE##_Array);

        [global::System.Runtime.InteropServices.DllImport("$dllimport",
                EntryPoint="SWIG_CSharp_RegisterCreateManaged_"+#CSTYPE+"_ArrayCallback_$module")]
        public static extern void SWIG_CSharp_RegisterCreateManaged_##CSTYPE##_ArrayCallback_$module(
                    CreateManaged_##CSTYPE##_ArrayDelegate createManaged_##CSTYPE##_ArrayDelegate);

        static System.IntPtr CreateManaged_##CSTYPE##_Array(System.IntPtr cppArrayPtr, int cppArraySize)
        {
            CSTYPE[] arraybuffer = new CSTYPE[cppArraySize];
            if (arraybuffer != null && cppArrayPtr != System.IntPtr.Zero) {
                System.Runtime.InteropServices.Marshal.Copy(cppArrayPtr, arraybuffer, 0, cppArraySize);
                System.Runtime.InteropServices.GCHandle handle = System.Runtime.InteropServices.GCHandle.Alloc(
                      arraybuffer, System.Runtime.InteropServices.GCHandleType.Pinned);
                return System.Runtime.InteropServices.GCHandle.ToIntPtr(handle);
            } else {
                return System.IntPtr.Zero;
            }
        }
        #endregion

        #region "Delegate: Define managed C# array size"
        public delegate int GetManaged_##CSTYPE##_ArraySizeDelegate(System.IntPtr csArray);
        static GetManaged_##CSTYPE##_ArraySizeDelegate getManaged_##CSTYPE##_ArraySizeDelegate =
                new GetManaged_##CSTYPE##_ArraySizeDelegate(GetManaged_##CSTYPE##_ArraySize);

        [global::System.Runtime.InteropServices.DllImport("$dllimport",
                    EntryPoint="SWIG_CSharp_RegisterGetManaged_"+#CSTYPE+"_ArraySizeCallback_$module")]
        public static extern void SWIG_CSharp_RegisterGetManaged_##CSTYPE##_ArraySizeCallback_$module(
                    GetManaged_##CSTYPE##_ArraySizeDelegate getManaged_##CSTYPE##_ArraySizeDelegate);

        static int GetManaged_##CSTYPE##_ArraySize(System.IntPtr csArray)
        {
            System.Runtime.InteropServices.GCHandle handle =
                    System.Runtime.InteropServices.GCHandle.FromIntPtr(csArray);
            return (handle.Target as CSTYPE[]).Length;
        }
        #endregion

        #region "Delegate: Copy managed C# array to unmanaged C++ array"
        public delegate void CopyToUnmanaged_##CSTYPE##_ArrayDelegate(
                System.IntPtr csArray, System.IntPtr cppArrayPtr, int cppArraySize);
        static CopyToUnmanaged_##CSTYPE##_ArrayDelegate copyToUnmanaged_##CSTYPE##_ArrayDelegate =
                new CopyToUnmanaged_##CSTYPE##_ArrayDelegate(CopyToUnmanaged_##CSTYPE##_Array);

        [global::System.Runtime.InteropServices.DllImport("$dllimport",
                EntryPoint="SWIG_CSharp_RegisterCopyToUnmanaged_"+#CSTYPE+"_ArrayCallback_$module")]
        public static extern void SWIG_CSharp_RegisterCopyToUnmanaged_##CSTYPE##_ArrayCallback_$module(
                CopyToUnmanaged_##CSTYPE##_ArrayDelegate copyToUnmanaged_##CSTYPE##_ArrayDelegate);

        static void CopyToUnmanaged_##CSTYPE##_Array(System.IntPtr csArrayPtr,
                System.IntPtr cppArrayPtr, int cppArraySize)
        {
            System.Runtime.InteropServices.GCHandle handle =
                    System.Runtime.InteropServices.GCHandle.FromIntPtr(csArrayPtr);
            CSTYPE[] csArray = (handle.Target as CSTYPE[]);
            if (csArray.Length > 0) {
                System.Runtime.InteropServices.Marshal.Copy(csArray, 0, cppArrayPtr, cppArraySize);
            }
        }
        #endregion

        #region "Register all C# delegates as C++ callbacks"
        static SWIG_##CSTYPE##_ArrayHelper()
        {
            SWIG_CSharp_RegisterCreateManaged_##CSTYPE##_ArrayCallback_$module(
                    createManaged_##CSTYPE##_ArrayDelegate);
            SWIG_CSharp_RegisterGetManaged_##CSTYPE##_ArraySizeCallback_$module(
                    getManaged_##CSTYPE##_ArraySizeDelegate);
            SWIG_CSharp_RegisterCopyToUnmanaged_##CSTYPE##_ArrayCallback_$module(
                    copyToUnmanaged_##CSTYPE##_ArrayDelegate);
        }
        #endregion
    }
    static protected SWIG_##CSTYPE##_ArrayHelper CSTYPE##ArrayHelper = new SWIG_##CSTYPE##_ArrayHelper();
    #endregion
%}

%enddef
