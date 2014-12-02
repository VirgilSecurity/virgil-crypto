package com.virgilsecurity {
    import flash.utils.ByteArray;

    public class ConvertionUtils {

        static public function asciiStringToArray(string : String) : ByteArray {
            var result : ByteArray = new ByteArray ();
            result.writeMultiByte(string, "iso-8859-1");
            result.position = 0;
            return result;
        }

        static public function arrayToAsciiString(array : ByteArray) : String {
            var pos : int = array.position;
            array.position = 0;
            try {
                var result : String = array.readMultiByte(array.length, "iso-8859-1");
            } finally {
                array.position = pos;
            }
            return  result;
        }

        static public function utfStringToArray(string : String) : ByteArray {
            var result : ByteArray = new ByteArray ();
            result.writeUTFBytes(string);
            result.position = 0;
            return result;
        }

        static public function arrayToUTFString(array : ByteArray) : String {
            var pos : int = array.position;
            array.position = 0;
            try {
                var result : String = array.readUTFBytes(array.length);
            } finally {
                array.position = pos;
            }
            return result;;
        }
    }
}
