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

 package com.virgilsecurity.demo {

    import flash.utils.setTimeout;
    import flash.utils.ByteArray;
    import flash.display.Loader;
    import flash.events.Event;
    import flash.events.IOErrorEvent;
    import flash.events.ProgressEvent;
    import flash.net.FileFilter;
    import flash.filesystem.File;
    import flash.filesystem.FileMode;
    import flash.filesystem.FileStream;

    import spark.components.Application;
    import spark.components.Label;
    import spark.components.Button;
    import spark.components.RadioButton;
    import spark.components.RadioButtonGroup;
    import spark.components.TextArea;
    import spark.components.Group;

    import flash.utils.getTimer;

    import com.virgilsecurity.*;
    import com.virgilsecurity.wrapper.CModule;

    public class EncryptAppController extends Application {
        /* UI elemnets */
        [Bindable] public var selectInputFileButton:Button;
        [Bindable] public var selectOutputFileButton:Button;
        [Bindable] public var selectKeyFileButton:Button;
        [Bindable] public var processFileButton:Button;
        [Bindable] public var debugArea:TextArea;
        [Bindable] public var blockerView:Group;
        [Bindable] public var blockerViewLabel:Label;
        [Bindable] public var encryptionOptionsGroup:RadioButtonGroup;
        [Bindable] public var encryptionOptionEncrypt:RadioButton;
        [Bindable] public var encryptionOptionDecrypt:RadioButton;
        /* File loading variables */
        private static const FILE_TYPES:Array = [new FileFilter("Any file", "*")];
        private var inFileStream:FileStream;
        private var encryptionKeyFileStream:FileStream;
        private var outFileStream:FileStream;
        /* State variables */
        private var isLastOperationWasEncryptd:Boolean = false;
        /* Code profiling */
        private var timerFileProcessStart:uint = 0;
        private var timerFileProcessEnd:uint = 0;
        /* Hardcoded asymmetric keys */
        private static const PLAIN_TEXT:String = "This string will be encrypted.";
        private static const EC_PUBLIC_KEY:String =
                "-----BEGIN PUBLIC KEY-----\n" +
                "MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEa+CTMPBSOFoeZQIPiUOc84r2\n" +
                "BsdPwOzDshzW/JDeY85E8HC+cVF/9K+vdsoeyYP3yGpTwA53hZIKueUh+QAF53C9\n" +
                "X6uaP98Jiu8RMZNplo9p4BZpCwP90A2rxRSatEFHOOtw3FCCmHqzsxpEQCEwnd47\n" +
                "BOP7sd6Nwy37YlX95RM=\n" +
                "-----END PUBLIC KEY-----\n";
        private static const EC_PRIVATE_KEY:String =
                "-----BEGIN EC PRIVATE KEY-----\n" +
                "MIHaAgEBBEBKFx+SNvhRVb0HpyEBceoVoU4AKZLrx9jdxRdQAS9tC/CQdAmB2t0h\n" +
                "XsMEbtg5DVmwh29GzuLkyTh9VQYxAP/roAsGCSskAwMCCAEBDaGBhQOBggAEa+CT\n" +
                "MPBSOFoeZQIPiUOc84r2BsdPwOzDshzW/JDeY85E8HC+cVF/9K+vdsoeyYP3yGpT\n" +
                "wA53hZIKueUh+QAF53C9X6uaP98Jiu8RMZNplo9p4BZpCwP90A2rxRSatEFHOOtw\n" +
                "3FCCmHqzsxpEQCEwnd47BOP7sd6Nwy37YlX95RM=\n" +
                "-----END EC PRIVATE KEY-----\n";
        private static const RSA_PUBLIC_KEY:String =
                "-----BEGIN PUBLIC KEY-----\n" +
                "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMk/B8TlOOwNnxpOBGUo0bW9HbNuiaro\n" +
                "K+GG5ZcLA9AnA2Fwkx8hFozP0hQp97kbA/RS96/NdbreSjVqltlotc0CAwEAAQ==\n" +
                "-----END PUBLIC KEY-----\n";
        private static const RSA_PRIVATE_KEY:String =
                "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIBOQIBAAJBAMk/B8TlOOwNnxpOBGUo0bW9HbNuiaroK+GG5ZcLA9AnA2Fwkx8h\n" +
                "FozP0hQp97kbA/RS96/NdbreSjVqltlotc0CAwEAAQJAYML8olAwoVcfU8+FT3pj\n" +
                "8sU+faK9cL53MtXgmFJEgBUWlg0aGq67an8vgReCdIK6F3500f6Yf9LhjkoZ4ZBl\n" +
                "QQIhAPvyiVFhizURqzZHn4cQtKR2bgGJsARdvlg6KKHP/XXRAiEAzHu3uJ1mIFHH\n" +
                "MGMrpKC4mcnyvM4UEETIINUA+pabMz0CIGeJQA0FfOOOI0HnJROoNdPwJzzSjFb+\n" +
                "/x3aqJ/2jT5BAiBTLEtpY1Rj9v9/VgctelY776G1XFla2K9Sc3FnfBT6vQIgJlqb\n" +
                "tFCwQZczpa/OtOqYKHHpFevnLEVWrlHvCRgJeJU=\n" +
                "-----END RSA PRIVATE KEY-----\n";

        /* UI action handlers */
        public function creationCompleate():void {
            CModule.startAsync();
        }

        public function onSelectInputFile(event:Event):void {
            if (encryptionOptionsGroup.selection == encryptionOptionEncrypt) {
                requestFileToBeProcessed("Choose file for encryption");
            } else if (encryptionOptionsGroup.selection == encryptionOptionDecrypt) {
                requestFileToBeProcessed("Choose file for decryption");
            }
        }

        public function onSelectOutputFile(event:Event):void {
            if (encryptionOptionsGroup.selection == encryptionOptionEncrypt) {
                requestOutputFile("Save encrypted file as...");
            } else if (encryptionOptionsGroup.selection == encryptionOptionDecrypt) {
                requestOutputFile("Save decrypted file as...");
            }
        }

        public function onSelectKeyFile(event:Event):void {
            requestEncryptionKeyFile();
        }

        public function onProcessFile(event:Event):void {
            if (encryptionOptionsGroup.selection == encryptionOptionEncrypt) {
                invokeAfterDelay(processFileEncryption, "Encryption, please wait.");
            } else if (encryptionOptionsGroup.selection == encryptionOptionDecrypt) {
                invokeAfterDelay(processFileDecryption, "Decryption, please wait.");
            }
        }

        public function onClearDebugOutput(event:Event):void {
            debugArea.text = "";
        }

        public function onEncryptEnabled(event:Event):void {
            updateControlPanel();
        }

        public function onDecryptEnabled(event:Event):void {
            updateControlPanel();
        }

        /* Block view control */
        public function blockUI(message:String = null):void {
            blockerView.visible = true;
            if (message) {
                blockerViewLabel.text = message;
            } else {
                blockerViewLabel.text = "Processing...";
            }
        }

        public function unblockUI():void {
            blockerView.visible = false;
        }

        /* File loading process handlers*/
        private function requestFileToBeProcessed(title:String):void {
            // create the inFileStream instance
            var inFile:File = new File();
            // listen for when they select a file
            inFile.addEventListener(Event.SELECT, fileForProcessingIsSelected);
            // listen for when then cancel out of the browse dialog
            inFile.addEventListener(Event.CANCEL, fileForProcessingIsCanceled);
            // open a native browse dialog that filters for text files
            inFile.browseForOpen(title, FILE_TYPES);
        }

        private function fileForProcessingIsSelected(event:Event):void {
            outDebugMessage("Selected file: " + event.target.nativePath);

            var inFile:File = event.target as File;
            inFileStream = new FileStream();
            inFileStream.open(inFile, FileMode.READ);
            updateControlPanel();
        }

        private function fileForProcessingIsCanceled(event:Event):void {
            outDebugMessage("File selection is canceled.");
        }

        private function requestEncryptionKeyFile():void {
            // create the inFileStream instance
            var file:File = new File();
            // listen for when they select a file
            file.addEventListener(Event.SELECT, encryptionKeyFileIsSelected);
            // listen for when then cancel out of the browse dialog
            file.addEventListener(Event.CANCEL, encryptionKeyFileIsCanceled);
            // open a native browse dialog that filters for text files
            if (encryptionOptionsGroup.selection == encryptionOptionEncrypt) {
                file.browseForSave("Save encryption key file");
            } else if (encryptionOptionsGroup.selection == encryptionOptionDecrypt) {
                file.browseForOpen("Choose encryption key file", FILE_TYPES);
            }
        }

        private function encryptionKeyFileIsSelected(event:Event):void {
            outDebugMessage("Selected file: " + event.target.nativePath);

            var file:File = event.target as File;
            encryptionKeyFileStream = new FileStream();
            if (encryptionOptionsGroup.selection == encryptionOptionEncrypt) {
                encryptionKeyFileStream.open(file, FileMode.WRITE);
            } else if (encryptionOptionsGroup.selection == encryptionOptionDecrypt) {
                encryptionKeyFileStream.open(file, FileMode.READ);
            }
            updateControlPanel();
        }

        private function encryptionKeyFileIsCanceled(event:Event):void {
            outDebugMessage("File selection is canceled.");
        }

        /* File saving process handlers */
        private function requestOutputFile(title:String):void {
            // create the outFileStream instance
            var outDir:File = File.documentsDirectory;
            try {
                // listen for when they select a file
                outDir.addEventListener(Event.SELECT, outputFileIsSelected);
                // listen for when then cancel out of the browse dialog
                outDir.addEventListener(Event.CANCEL, outputFileIsCanceled);
                // open a native browse dialog to save the content of the file
                outDir.browseForSave(title);
            } catch (error:Error) {
                outDebugMessage("Failed to save file: " + error.message);
            }
        }

        private function outputFileIsSelected(event:Event):void {
            var newFile:File = event.target as File;
            outDebugMessage("Destination file was selected: " + newFile.nativePath);
            outFileStream = new FileStream();
            outFileStream.open(newFile, FileMode.WRITE);
            updateControlPanel();
        }

        private function outputFileIsCanceled(event:Event):void {
            outDebugMessage("File selection is canceled.");
        }

        /* UI configuration */
        private function updateControlPanel():void {
            selectInputFileButton.enabled = true;
            selectKeyFileButton.enabled = true;
            selectOutputFileButton.enabled = true;
            if (inFileStream != null && outFileStream != null && encryptionKeyFileStream != null) {
                processFileButton.enabled = true;
            }
        }

        /* File processing */
        private function processFileEncryption():void {
            timerFileProcessStart = getTimer();

            var cipher:VirgilChunkCipher = VirgilChunkCipher.create();

            var dataChunk:ByteArray = new ByteArray();
            const encryptionChunkSize:uint = cipher.adjustEncryptionChunkSize(1024 * 1024);

            var encryptionKey:ByteArray = cipher.startEncryption(stringToBytes(EC_PUBLIC_KEY));
            encryptionKeyFileStream.writeBytes(encryptionKey);
            while (inFileStream.bytesAvailable > 0) {
                dataChunk.clear();
                inFileStream.readBytes(dataChunk, 0, Math.min(encryptionChunkSize, inFileStream.bytesAvailable));
                outFileStream.writeBytes(cipher.process(dataChunk));
            }
            cipher.finalize();
            cipher.destroy();
            timerFileProcessEnd = getTimer();
            unblockUI();
            outDebugMessage("File is processed in: " + (timerFileProcessEnd - timerFileProcessStart) + " ms.");
        }

        private function processFileDecryption():void {
            timerFileProcessStart = getTimer();

            var cipher:VirgilChunkCipher = VirgilChunkCipher.create();

            var dataChunk:ByteArray = new ByteArray();
            const encryptionChunkSize:uint = cipher.adjustEncryptionChunkSize(1024 * 1024);
            const decryptionChunkSize:uint = cipher.adjustEncryptionChunkSize(encryptionChunkSize);

            var encryptionKey:ByteArray = new ByteArray();
            encryptionKeyFileStream.readBytes(encryptionKey);
            encryptionKey.position = 0;

            cipher.startDecryption(encryptionKey, stringToBytes(EC_PRIVATE_KEY));
            while (inFileStream.bytesAvailable > 0) {
                dataChunk.clear();
                inFileStream.readBytes(dataChunk, 0, Math.min(encryptionChunkSize, inFileStream.bytesAvailable));
                outFileStream.writeBytes(cipher.process(dataChunk));
            }
            cipher.finalize();
            cipher.destroy();
            timerFileProcessEnd = getTimer();
            unblockUI();
            outDebugMessage("File is processed in: " + (timerFileProcessEnd - timerFileProcessStart) + " ms.");
        }

        /* Debug console */
        private function outDebugMessage(message:String):void {
            debugArea.text += message + "\n";
            autoscroll(debugArea);
        }

        private function autoscroll(textArea:TextArea):void {
            setTimeout(function():void {
                textArea.scroller.verticalScrollBar.value = textArea.scroller.verticalScrollBar.maximum;
            }, 100);
        }

        /* Async calls implementation*/
        private function invokeAfterDelay(func:Function, blockMessage:String = null, delay:uint = 20):void {
            if (blockMessage) {
                blockUI(blockMessage);
            }
            setTimeout(func, delay);
        }

        /* ByteArray helpers */
        private static function clone(source:Object):* {
            var myBA:ByteArray = new ByteArray();
            myBA.writeObject(source);
            myBA.position = 0;
            return(myBA.readObject());
        }

        static private function stringToBytes(string:String):ByteArray {
            var result:ByteArray = new ByteArray ();
            result.writeMultiByte(string, "iso-8859-1");
            result.position = 0;
            return result;
        }

        static private function stringFromBytes(array:ByteArray):String {
            var pos:int = array.position;
            array.position = 0;
            try {
                var result:String = array.readMultiByte(array.length, "iso-8859-1");
            } finally {
                array.position = pos;
            }
            return  result;
        }

    }
}
