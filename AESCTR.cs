using System;
using System.IO;
using AESImplementationSpace;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;

namespace AESWithCTRSpace
{
    class AESWithCTR
    {
        private String path;
        private int actionMode;
        private byte[] IV;
        private byte[] counter;
        private AES3481 aes;

        public const int DECRYPT = 0;
        public const int ENCRYPT = 1;

        private const int BLOCK_SIZE = 16;

        public AESWithCTR(string path, string key, string initVector)
        {
            // if(keyIV == null)
            //     keyIV = new Dictionary<string, string>();
            this.path = path;
            this.IV = new byte[BLOCK_SIZE];
            byte[] iv = new byte[BLOCK_SIZE];

            byte[] convertedIV = Encoding.UTF8.GetBytes(initVector);
            byte[] convertedKey = Encoding.UTF8.GetBytes(key);
            int keySize = convertedKey.Length;
            if(keySize <= 16)
                keySize = 16;
            else if(keySize <= 24)
                keySize = 24;
            else if (keySize <= 32)
                keySize = 32;
            else
                Console.WriteLine("AES Key cannot be more than 32-byte long.");



            byte[] completeKey = new byte[keySize];
            Array.Copy(convertedKey, 0, completeKey, keySize - convertedKey.Length, convertedKey.Length);
            Array.Copy(convertedIV, 0, iv, BLOCK_SIZE - convertedIV.Length, convertedIV.Length);

            setIV(iv);
            this.aes = new AES3481(keySize);
            aes.setKey(completeKey);
        }

        public void setAction(int action)
        {
            this.actionMode = action;
        }

        public void setIV(byte[] iv)
        {
            // if (iv.Length != BLOCK_SIZE)
            //     Console.WriteLine("Invalid length of Initial Vector");
            // else
            Array.Copy(iv, 0, this.IV, BLOCK_SIZE - iv.Length, iv.Length);
        }

        private byte[] XORByteArray16(byte[] a, byte[] b)
        {
            byte[] result = new byte[16];

            for(int i = 0; i < BLOCK_SIZE; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
        }

        private byte[] getUniqueNounceCounter(byte[] iv, byte[] counter)
        {
           return XORByteArray16(iv, counter);
        }

        private void incrementCounter(int index)
        {
            if(index == 0)
                counter[index] += 1;

            if(counter[index] == 0xff)
            {
                counter[index] = 0x0;
                incrementCounter(index - 1);
            }
            else
                counter[index] += 1;

        }

        // Reference: https://docs.microsoft.com/en-us/dotnet/api/system.io.directory.getfiles?view=netcore-3.1
        // Process all files in the directory passed in, recurse on any directories
        // that are found, and process the files they contain.
        private void ProcessDirectory(string targetDirectory)
        {
            // Process the list of files found in the directory.
            string [] fileEntries = Directory.GetFiles(targetDirectory);
            foreach(string fileName in fileEntries)
                ProcessFile(fileName);

            // Recurse into subdirectories of this directory.
            string [] subdirectoryEntries = Directory.GetDirectories(targetDirectory);
            foreach(string subdirectory in subdirectoryEntries)
                ProcessDirectory(subdirectory);
        }

        // Insert logic for processing found files here.
        private void ProcessFile(string path)
        {
            // Doing encryption or decryption here
            // Console.WriteLine("Processed file '{0}'.", path);

            byte blockFillValue = 0x0f;

            this.counter = new byte[BLOCK_SIZE];
            for(int i = 0; i < BLOCK_SIZE; i++)
                counter[i] = 0x00;
            byte[] content = File.ReadAllBytes(path);
            byte[] processContent = new byte[content.Length];
            int pointer = 0;
            while (pointer + BLOCK_SIZE <= content.Length - 1)
            {
                byte[] block = new byte[BLOCK_SIZE];
                bool AESfailed = false;
                for(int i = 0; i < BLOCK_SIZE && pointer < content.Length; i++)
                {
                    block[i] = content[pointer];
                    pointer ++;
                }

                byte[] randomCounter = getUniqueNounceCounter(IV, counter);
                incrementCounter(BLOCK_SIZE - 1);
                byte[] aesText = new byte[BLOCK_SIZE];

                if(this.actionMode == ENCRYPT || this.actionMode == DECRYPT)
                {
                    aes.encrypt(randomCounter);
                    aesText = aes.getCipherTextiInBytes();
                }
                else
                {
                    AESfailed = true;
                    Console.WriteLine("AES Failed");
                }
                if(!AESfailed)
                    Array.Copy(XORByteArray16(aesText, block), 0, processContent, pointer - BLOCK_SIZE, BLOCK_SIZE);
            }

            // Check if it's the end of the content (the remainder of content {content.Length mod 16})
            if (pointer < content.Length)
            {
                byte[] tempText = new byte[content.Length + BLOCK_SIZE - (content.Length - pointer)];
                Array.Copy(processContent, tempText, processContent.Length);
                byte[] block = new byte[BLOCK_SIZE];
                bool AESfailed = false;
                // int numOfByteLeft = content.Length - pointer;
                for(int i = 0; i < BLOCK_SIZE; i++)
                {
                    if(pointer + i < content.Length)
                        block[i] = content[pointer + i];
                    else
                        block[i] = blockFillValue;
                    // pointer ++;
                }

                byte[] randomCounter = getUniqueNounceCounter(IV, counter);
                incrementCounter(BLOCK_SIZE - 1);

                byte[] aesText = new byte[BLOCK_SIZE];

                if(this.actionMode == ENCRYPT || this.actionMode == DECRYPT)
                {
                    aes.encrypt(randomCounter);
                    aesText = aes.getCipherTextiInBytes();
                }
                else
                {
                    AESfailed = true;
                    Console.WriteLine("AES Failed");
                }

                // Console.WriteLine(tempText.Length);
                // Console.WriteLine(pointer);

                if(!AESfailed)
                    Array.Copy(XORByteArray16(aesText, block), 0, tempText, pointer, BLOCK_SIZE);
                processContent = new byte[tempText.Length];
                Array.Copy(tempText, processContent, tempText.Length);
            }


            // Only for Decryption
            if(this.actionMode == DECRYPT)
            {
                int p = processContent.Length - 1;
                Boolean checkMark = processContent[p] == blockFillValue;
                for(int i = processContent.Length - 2; i >= 0 && checkMark; i--)
                {
                    if(processContent[i] == blockFillValue)
                    {
                        p = p - 1;
                    }
                    else
                    {
                        checkMark = false;
                    }
                }
                int reducedLength = processContent.Length - (processContent.Length - 1 - p + 1);

                byte[] tempContent = new byte[reducedLength];
                if(reducedLength < processContent.Length)
                {
                    Array.Copy(processContent, tempContent, reducedLength);
                    processContent = new byte[reducedLength];
                    Array.Copy(tempContent, processContent, reducedLength);
                }
            }

            File.WriteAllBytes(path, processContent);
        }

        public void StartCrypto()
        {
            // ProcessDirectory(this.FolderFullPath);
            ProcessFile(this.path);
            // Console.WriteLine("Finish Cryto Operation !!");
        }
    }
}
