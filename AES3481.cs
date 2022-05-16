using System;

namespace AESImplementationSpace
{
    class AES3481
    {
        private byte[] Sbox, InverseSbox, ProcessText, Key, RCj;
        private byte[] PlainText, CipherText;
        private byte[] ExpandedKey;
        private const int BOX_SIZE = 256, TEXT_SIZE = 16;
        private int round;

        public AES3481(int keySize)
        {
            this.Sbox = new byte[BOX_SIZE];
            this.InverseSbox = new byte[BOX_SIZE];
            this.ProcessText = new byte[TEXT_SIZE];
            this.Key = new byte[keySize];

            // if (keySize != key.Length)
            //     throw new Exception("The key does not have the length of keySize");
            // else
            //     Array.Copy(key, Key, keySize);

            if (!(keySize == 16 || keySize == 24 || keySize == 32))
                throw new Exception("Key size must be 16, 24, or 32 bytes.");
            
            // RoundKey = new byte[16];

            int ExpandedKeySize = keySize == 16 ? 176 : (keySize == 24 ? 208 : (keySize == 32 ? 240 : 0));

            this.ExpandedKey = new byte[ExpandedKeySize];
            
            this.round = 0;

            this.PlainText = new byte[TEXT_SIZE];
            this.CipherText = new byte[TEXT_SIZE];

            setNumOfRound(keySize);
            this.RCj = new byte[this.round];
            initializeSboxAndInverseSbox();
            initializeRCj();
            proceedKeyExpansion();
        }

        /* 
            Helper Methods:
            ROTL8           : Sbox, InverseSbox initialization
            RotByte         :
            setNumOfRound   :
            GMul            :
            
        */
        private byte ROTL8(byte x, byte shift) 
        { 
            return  (byte) (x << shift | x >> (8 - shift));
        }

        private void RotBytes(byte[] word)
        {
            byte temp = word[0];
            for (int i = 0; i < word.Length - 1; i++){
                word[i] = word[i + 1];
            }
            word[word.Length - 1] = temp;
        }

        private byte GMul(byte a, byte b) 
        { // Galois Field (256) Multiplication of two Bytes
            byte p = 0;

            for (int counter = 0; counter < 8; counter++) {
                if ((b & 1) != 0) {
                    p ^= a;
                }

                bool hi_bit_set = (a & 0x80) != 0;
                a <<= 1;
                if (hi_bit_set) {
                    a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
                }
                b >>= 1;
            }

            return p;
        }

        private void setNumOfRound(int KeySize)
        {
            this.round = KeySize == 16 ? 10 : (KeySize == 24 ? 12 : (KeySize == 32 ? 14: 0)); 
        }

        // End of Helper Methods

        // Set up 

        public void setKey(byte[] key)
        {
            if (Key.Length != key.Length)
                throw new Exception("The key does not have the length of keySize");
            else
                Array.Copy(key, Key, Key.Length);
        }

        private void initializeSboxAndInverseSbox()
        {
            // From Wikipedia https://en.wikipedia.org/wiki/Rijndael_S-box
            byte p, q;
            p = 1;
            q = 1;

            /* loop invariant: p * q == 1 in the Galois field */
            do {
                /* multiply p by 3 */
                p  = (byte)(p ^ (p << 1) ^ ((p & 0x80) != 0x0 ? 0x1B : 0));

                /* divide q by 3 (equals multiplication by 0xf6) */
                q ^= (byte)(q << 1);
		        q ^= (byte)(q << 2);
		        q ^= (byte)(q << 4);
		        q ^= (byte)((q & 0x80) != 0x0 ? 0x09 : 0);

                /* compute the affine transformation */
                byte xformed = (byte)(q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4));

                Sbox[p] = (byte)(xformed ^ 0x63);

            } while(p != 1);
            
            /* 0 is a special case since it has no inverse */
            Sbox[0] = 0x63;

            /* Initialize the InverseSbox based on Sbox */
            for (int i = 0; i < 256; i ++)
            {
                InverseSbox[Sbox[i]] = (byte)i; 
            }
        }

        private void initializeRCj()
        {
            RCj[0] = 0x01;
            for (int i = 1; i < RCj.Length; i++)
                RCj[i] = GMul(0x02, RCj[i - 1]);
        }

        private void proceedKeyExpansion()
        {
            for (int i = 0; i < 16; i++)
            {
                ExpandedKey[i] = Key[i];
            }

            for (int i = 16; i < 176; i += 4)
            {
                if(i % 16 == 0)
                {
                    byte[] PreviousWord = new byte[4];
                    PreviousWord[0] = ExpandedKey[i - 4];
                    PreviousWord[1] = ExpandedKey[i - 3];
                    PreviousWord[2] = ExpandedKey[i - 2];
                    PreviousWord[3] = ExpandedKey[i - 1];
                    RotBytes(PreviousWord);
                    SubByte(PreviousWord);

                    //XOR with RCj[round]
                    PreviousWord[0] ^= RCj[i / 16 - 1];
                    PreviousWord[1] ^= 0x0;
                    PreviousWord[2] ^= 0x0;
                    PreviousWord[3] ^= 0x0;

                    //XOR with w[i - 4] and update ExpandedKey
                    for (int j = 0; j < PreviousWord.Length; j++)
                    {
                        PreviousWord[j] ^= ExpandedKey[i - 16 + j];
                        ExpandedKey[i + j] = PreviousWord[j];
                    }
                }
                else /* If the ith byte is not divided by 4 */
                {
                    /*
                        Example: Calculate w5 from w4 and w1
                        w5 (k20, k21, k22, k23)
                        w4 (k16, k17, k18, k19)
                        w1 (k4, k5, k6, k7) 
                    */
                    for (int k = 0; k < 4; k ++)
                        ExpandedKey[i + k] = (byte)(ExpandedKey[i + k - 4] ^ ExpandedKey[i + k - 16]);  
                }
            }
        }
        /* 
            Main AES Methods
        */
        private void SubByte(byte[] processText)
        {
            for(int i = 0; i < processText.Length; i++)
                processText[i] = Sbox[processText[i]];
        }

        private void InverseSubByte(byte[] processText)
        {
            for (int i = 0; i < processText.Length; i++)
                processText[i] = InverseSbox[processText[i]];
        }

       
        // private void shareShiftRows(byte processText, int[] indices)
        // {
            
        // }

        /*
            processText has 16 bytes
            (*) 1-byte left shift between byte 1, 5, 9, 13
            ($) 2-byte left shift between byte 2, 6, 10, 14 
            (@) 3-byte left shift between byte 3, 7, 11, 15
        */
        private void ShiftRows(byte[] processText)
        {
            // (*)
            byte temp = processText[1];
            for (int i = 1; i <= 9; i += 4)
                processText[i] = processText[i + 4];
            processText[13] = temp;

            // ($)
            temp = processText[2];
            processText[2] = processText[10];
            processText[10] = temp;
            temp = processText[6];
            processText[6] = processText[14];
            processText[14] = temp; 

            // (@)
            temp = processText[15];
            for (int i = 15; i >= 7; i -= 4)
                processText[i] = processText[i - 4];
            processText[3] = temp;
        }

        /*
            processText has 16 bytes
            (*) 1-byte right shift between byte 1, 5, 9, 13
            ($) 2-byte right shift between byte 2, 6, 10, 14
            (@) 3-byte right shift between byte 3, 7, 11, 15
        */
        private void InverseShiftRows(byte[] processText)
        {
            // (*)
            byte temp = processText[13];
            for (int i = 13; i >= 5; i -=4)
                processText[i] = processText[i - 4];
            processText[1] = temp;

            // ($)
             temp = processText[2];
            processText[2] = processText[10];
            processText[10] = temp;
            temp = processText[6];
            processText[6] = processText[14];
            processText[14] = temp;  

            // (@)
            temp = processText[3];
            for (int i = 3; i <= 11; i +=4)
                processText[i] = processText[i + 4];
            processText[15] = temp;
        }

        /* 
            mixColumns for AES are referenced 
            from https://en.wikipedia.org/wiki/Rijndael_MixColumns
        */
        private void MixColumns(byte[] processText)
        {
            byte[] t_Text = new byte[processText.Length];
            Array.Copy(processText, t_Text, processText.Length);
            for (int i = 0; i < 16; i +=4)
            {               
                processText[i]      = (byte)(GMul(0x02, t_Text[i]) ^ GMul(0x03, t_Text[i + 1]) ^ t_Text[i + 2] ^ t_Text[i + 3]);
                processText[i + 1]  = (byte)(t_Text[i] ^ GMul(0x02, t_Text[i + 1]) ^ GMul(0x03, t_Text[i + 2]) ^ t_Text[i + 3]);
                processText[i + 2]  = (byte)(t_Text[i] ^ t_Text[i + 1] ^ GMul(0x02, t_Text[i + 2]) ^ GMul(0x03, t_Text[i + 3])); 
                processText[i + 3]  = (byte)(GMul(0x03, t_Text[i]) ^ t_Text[i + 1] ^ t_Text[i + 2] ^ GMul(0x02, t_Text[i + 3])); 
            }
        }

        private void InverseMixColumns(byte[] processText)
        {
            byte[] t_Text = new byte[processText.Length];
            Array.Copy(processText, t_Text, processText.Length);
            for (int i = 0; i < 16; i+=4)
            {               
                processText[i]      = (byte)(GMul(0x0E, t_Text[i]) ^ GMul(0x0B, t_Text[i + 1]) ^ GMul(0x0D, t_Text[i + 2]) ^ GMul(0x09, t_Text[i + 3]));
                processText[i + 1]  = (byte)(GMul(0x09, t_Text[i]) ^ GMul(0x0E, t_Text[i + 1]) ^ GMul(0x0B, t_Text[i + 2]) ^ GMul(0x0D, t_Text[i + 3]));
                processText[i + 2]  = (byte)(GMul(0x0D, t_Text[i]) ^ GMul(0x09, t_Text[i + 1]) ^ GMul(0x0E, t_Text[i + 2]) ^ GMul(0x0B, t_Text[i + 3])); 
                processText[i + 3]  = (byte)(GMul(0x0B, t_Text[i]) ^ GMul(0x0D, t_Text[i + 1]) ^ GMul(0x09, t_Text[i + 2]) ^ GMul(0x0E, t_Text[i + 3])); 
            }
        }

        private void AddRoundKey(int round, byte[] processText, byte[] ModifyKey, bool isInverse)
        {
            if (!isInverse) // Add key in Encryption
            {
                for (int i = 0; i < processText.Length; i++)
                    processText[i] ^= ModifyKey[round * 16 + i];
            }
            else // Add key in Decryption
            {
                byte[] round_key = new byte[16];
                for (int i = 0; i < round_key.Length; i++)
                    round_key[i] = ModifyKey[round * 16 + i];

                InverseMixColumns(round_key);
                for(int i = 0; i < processText.Length; i++)
                    processText[i] ^= round_key[i];
            }
            
        }

        /*
            The size of the Key are in Byte.
        */
        public void encrypt(byte[] plainText)
        {
            // setNumOfRound(keySize);
            int round_th = 0;
            Array.Copy(plainText, ProcessText, plainText.Length);

            // First round
            AddRoundKey(round_th, ProcessText, ExpandedKey, false);
            // Console.WriteLine("Round {0} AddKey:\n{1}", round_th, MatrixFormat(ProcessText));
            round_th ++;

            // Round 2 to the second last round
            while(round_th <= this.round - 1)
            {
                SubByte(ProcessText);
                // Console.WriteLine("Round {0} SubByte:\n{1}", round_th, MatrixFormat(ProcessText));
                ShiftRows(ProcessText);
                // Console.WriteLine("Round {0} ShiftRow:\n{1}", round_th, MatrixFormat(ProcessText));
                MixColumns(ProcessText);
                // Console.WriteLine("Round {0} MixColumns:\n{1}", round_th, MatrixFormat(ProcessText));
                AddRoundKey(round_th, ProcessText, ExpandedKey, false);
                // Console.WriteLine("Round {0} AddKey:\n{1}", round_th, MatrixFormat(ProcessText));
                round_th ++;
            }

            // Last round (10, 12, 14)
            SubByte(ProcessText);
            ShiftRows(ProcessText);
            AddRoundKey(round_th, ProcessText, ExpandedKey, false);
            // Console.WriteLine("Round {0}:\n{1}", round_th, MatrixFormat(ProcessText));

            Array.Copy(ProcessText, CipherText, TEXT_SIZE);
            Array.Clear(ProcessText, 0, TEXT_SIZE);
        }

        public void decrypt(byte[] cipherText)
        {
            // setNumOfRound(keySize);
            byte[] DecryptExpandedKey = new byte[ExpandedKey.Length];
            
            /* 
                Reverse the ExpandKey accordingly w[0, 3], w[4, 7], ... , w[36, 39], w[40, 43] 
                into w[40, 43], w[36, 39], ... ,w[4, 7], w[0, 3]
            */
            for (int i = 0; i < ExpandedKey.Length; i+=16)
            {
                for (int j = 0; j < 16; j ++)
                {
                    DecryptExpandedKey[i + j] = ExpandedKey[ExpandedKey.Length - 16 - i + j];
                }
            }

            // Console.WriteLine("DecryptExpandedKey:\n{0}", MatrixFormat(DecryptExpandedKey));

            int round_th = 0;
            Array.Copy(cipherText, ProcessText, cipherText.Length);
            // Console.WriteLine("Round {0}:\n{1}", round_th, MatrixFormat(ProcessText));

            
            // First round
            AddRoundKey(round_th, ProcessText, DecryptExpandedKey, false);
            // Console.WriteLine("Round {0}:\n{1}", round_th, MatrixFormat(ProcessText));
            round_th ++;

            // Round 2 to the second last round
            while(round_th <= this.round - 1)
            {
                InverseSubByte(ProcessText);
                InverseShiftRows(ProcessText);
                InverseMixColumns(ProcessText);
                AddRoundKey(round_th, ProcessText, DecryptExpandedKey, true);
                // Console.WriteLine("Round {0}:\n{1}", round_th, MatrixFormat(ProcessText));
                round_th ++;
            }

            // Last round (10, 12, 14)
            InverseSubByte(ProcessText);
            InverseShiftRows(ProcessText);
            AddRoundKey(round_th, ProcessText, DecryptExpandedKey, false);
            // Console.WriteLine("Round {0}:\n{1}", round_th, MatrixFormat(ProcessText));

            Array.Copy(ProcessText, PlainText, TEXT_SIZE);
            Array.Clear(ProcessText, 0, TEXT_SIZE);
        }

        // End of Main AES Methods

        // Retrive Text
        public byte[] getPlainTextiInBytes()
        {
            return this.PlainText;
        }
        
        public byte[] getCipherTextiInBytes()
        {
            return this.CipherText;
        }

        // Testing-Purpose Function
        public byte getSbox(byte b){
            return Sbox[b];
        }

        public byte getInverseSbox(byte b){
            return InverseSbox[b];
        }

        // public String getPlainText()
        // {
        //     String text = "";
        //     foreach(byte b in PlainText)
        //     {
        //         text += b.ToString("x2");
        //     }

        //     return text;
        // }

        public String MatrixFormat(byte[] text)
        {
            String result = "";
            for (int i = 0; i < text.Length; i++)
            {
                result += text[i].ToString("x2") + " ";
                if ((i + 1) % 4 == 0)
                {
                    result += '\n';
                }
            }

            return result;
        }
        // public String getCipherText()
        // {
        //     String text = "";
        //     foreach(byte b in CipherText)
        //     {
        //         text += b.ToString("x2");
        //     }

        //     return text;
        // }

        public String getExpandedKey()
        {
            String text = "";
            for(int i = 0; i < ExpandedKey.Length; i++)
            {
                text += ExpandedKey[i].ToString("x") + ' ';
                if ((i + 1) % 4 == 0)
                    text += '\n';
                if((i + 1) % 16 == 0)
                    text += '\n';
            }
            return text;
        }
    }
}