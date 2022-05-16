using System;
using System.Text;
using System.IO;

namespace vsCodeDotNet
{
    class Rc4
    {
        private static int sizeOfSArray = 256;
        private Byte[] S = new Byte[sizeOfSArray];
        private Byte[] T = new Byte[sizeOfSArray];

        //key-scheduling algorithm
        //S-box-Generator
        private void KSA(String key){
            int i = 0;
            int j = 0;

            //initalize S & K Array
            for (i=0;i<sizeOfSArray;i++){
                S[i] = (byte)i;
                T[i] = (byte)key[i % key.Length];
            }

            //Initial Permutation Of S
            for (i=0;i<sizeOfSArray;i++){
                //Console.WriteLine(asciiOfChar + " = " + T[i]]);
                j = (j + S[i] + T[i]) % sizeOfSArray;

                //swap index i value and index j value
                int temp = S[i];
                S[i] = S[j];
                S[j] = (byte)temp;
            }
        }

        //pseudo-random generation algorithm produces keystream
        //stream generation
        private byte[] PRGA(int inputLength){
            int i= 0;
            int j = 0;
            int c = 0;
            int t = 0;

            byte[] k = new byte[inputLength];
            for(c=0; c < inputLength; c++){
                i = (i + 1) % sizeOfSArray;
                j = (j + S[i]) % sizeOfSArray;

                 //swap index i value and index j value
                int temp = S[i];
                S[i] = S[j];
                S[j] = (byte)temp;

                t = (S[i] + S[j]) % sizeOfSArray;
                k[c] = S[t];
            }
            return k;
        }

        //to get cipherText xor keystream and plainText
        public byte[] RC4Encrypt(byte[] plainText, String key){
            KSA(key);
            byte[] k = PRGA(plainText.Length);
            //converted plaintext into ascii
            int asciiOfPlainText;
            int resultOfXOR;

            byte[] a = new byte[plainText.Length];

            //converts plaintext character to ascii then xors for each char to get ciphertext 1 by 1
            for (int i = 0; i < plainText.Length; i++){
                asciiOfPlainText = (byte)plainText[i];
                //xor the ascii value
                resultOfXOR = k[i] ^ asciiOfPlainText;
                a[i] = (byte)resultOfXOR;
            }
            return a;
        }

        //to get plainText xor keystream and cipherText
        public byte[] RC4Decrypt(byte[] cipherText, String key){
            KSA(key);
            byte[] k = PRGA(cipherText.Length);
            //converted plaintext into ascii
            int asciiOfCipherText;
            int resultOfXOR;
            byte[] s = new byte[cipherText.Length];

            //converts cipher character to ascii then xors for each char to get each plaintext char 1 by 1
            for (int i = 0; i < cipherText.Length; i++){
                asciiOfCipherText = (byte)cipherText[i];
                //xor the ascii values
                resultOfXOR = k[i] ^ asciiOfCipherText;
                s[i] = (byte)resultOfXOR;
            }
            //add XOR between k and plainText
            return s;
        }

        //public static void Main(string[] args)
        //{
            // Rc4 t = new Rc4();
            // string testPlainText = "NO ONE CAN SAVE FROM DEATH";
            // string testKey = "THIS IS THE GOOD KEY";

            // // Program t = new Program();

            // byte[] a =  Encoding.ASCII.GetBytes(testPlainText);

            // a = t.RC4Encrypt(a, testKey);
            // Console.WriteLine(a);

            // // a = t.RC4Decrypt(a, testKey);
            // // Console.WriteLine(plainText);

            // //used to encrypt text file with rc4
            // string txt = "TestFile.txt";
            // // byte[] text = File.ReadAllBytes(txt);
            // // text = t.RC4Encrypt(text, "81516513ThisMy45511Key");
            // // File.WriteAllBytes(txt, text);

            // //used to decrypt text file with rc4
            // byte[] text = File.ReadAllBytes(txt);
            // text = t.RC4Decrypt(text, "81516513ThisMy45511Key");

            // File.WriteAllBytes(txt, text);
        //}
    }
}
