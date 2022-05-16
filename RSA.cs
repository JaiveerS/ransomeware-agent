using System;
using System.Numerics;
using System.Text;
using System.Collections.Generic;

namespace RSA
{
    class RSAstate
    {

            public BigInteger p;
            public BigInteger q;
            public BigInteger e;
            public BigInteger d;
            public BigInteger n;
            public BigInteger phi;

        // static BigInteger modulInv ( BigInteger a, BigInteger m) {
        //     a = a % m;
        //     for (int i = 1; i < m; i++) {
        //     if ((a * i) % m == 1) {
        //         return i;
        //     }
        // }
        // return 1;

        // }
        public int gcdExtended(BigInteger a, BigInteger b, BigInteger x, BigInteger y) {
                    // Base Case
                    if (a == (BigInteger) 0)
                    {
                        x =  (BigInteger) 0;
                        y = (BigInteger) 1;
                        return (int)b;
                    }

                    // To store results of
                    // recursive call
                    BigInteger x1 = (BigInteger) 1;
                    BigInteger y1 = (BigInteger) 1;

                    int gcd = gcdExtended(b % a, a, x1, y1);

                    // Update x and y using
                    // results of recursive call
                    x = y1 - (b / a) * x1;
                    y = x1;

                    return gcd;
                }
                public  BigInteger getModulInv(BigInteger a, BigInteger b){

                    if(gcdExtended(a,b,1,1) != 1){
                      Console.WriteLine("+++++++++++++++++++++++++++++++++++++++++++++: The primes given are not coprimes of each other ");
                      return -1;
                    }
                    else {

                    BigInteger x1 = (BigInteger) 0;
                    BigInteger x2 = (BigInteger) 1;
                    BigInteger y1 = (BigInteger) 1;
                    BigInteger y2 = (BigInteger) 0;

                    BigInteger q;
                    BigInteger r;
                    BigInteger x;
                    BigInteger y;
                    BigInteger d;
                    while (b >0){
                      q = (BigInteger) Math.Floor((double)a/(double)b);
                      r = a - (q*b);
                      x=x2-(q*x1);
                      y = y2-(q*y1);
                      a = b;
                      b=r;
                      x2=x1;
                      x1=x;
                      y2=y1;
                      y1=y;
                    }
                    x=x2;
                    return x;
                    }

                }

        public byte[] encrypt (byte[] plaintext, BigInteger p1, BigInteger q1, BigInteger e) {
            this.p = p1;
            this.q = q1;
            this.e = e;
            this.n = this.p * this.q;
            this.phi = ((this.p - 1) * (this.q - 1 ));
            this.d = getModulInv(this.e,this.phi);
            BigInteger [] ciphertext = new BigInteger [plaintext.Length];
            for (int i = 0; i < plaintext.Length; i++) {
                BigInteger currentMod = (BigInteger)plaintext[i] % this.n;
                BigInteger res = 1;
                for (int j= (int)this.e; j > 0; j--){
                    res = (res * currentMod) % this.n;
                }
                ciphertext[i] = res;
            }
            // string stringPlainText = "";
            // for (int i  = 0; i < ciphertext.Length; i++) {
            //      //Console.WriteLine ("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&   "+ciphertext[0]+ciphertext[1]+ciphertext[2]+ciphertext[3]+ciphertext[4]);
            //     if (ciphertext[i] < 10 ) {
            //         stringPlainText = stringPlainText +"000" + ciphertext[i].ToString();
            //     }else if (ciphertext[i] < 100 ) {
            //         stringPlainText = stringPlainText +"00" + ciphertext[i].ToString();
            //     }else if (ciphertext[i] < 1000 ) {
            //         stringPlainText = stringPlainText +"0" + ciphertext[i].ToString();
            //     }
            //     else {
            //     stringPlainText = stringPlainText + ciphertext[i].ToString();
            //     }

            // }

            // Encoding utf8 = Encoding.UTF8;

            // byte [] ciphertextString = new byte [ciphertext.Length];
            // ciphertextString = Encoding.ASCII.GetBytes(stringPlainText);
            List<Byte> cipher = new List<byte>();
            int longestPart = ciphertext[0].ToByteArray().Length;
            for (int i = 0; i < ciphertext.Length; i++)
            {
                if (longestPart <= ciphertext[i].ToByteArray().Length)
                {
                    longestPart = ciphertext[i].ToByteArray().Length;
                }
            }

            for (int i = 0; i < ciphertext.Length; i++)
            {
                byte[] converted = ciphertext[i].ToByteArray();
                int cl = converted.Length;
                for (int j = 0; j < longestPart- cl; j ++)
                {
                    cipher.Add((Byte)0);
                }
                for (int k = longestPart - cl; k < longestPart; k++)
                {
                    cipher.Add(converted[k - (longestPart - cl)]);
                }
            }

            cipher.Add((byte)longestPart);
            byte[] result = cipher.ToArray();

            return result;

        }
        public byte[] decrypt (byte[] holderforbytes, BigInteger D, BigInteger N) {
            //Console.WriteLine ("$$$$$$$$$$$$$$$$$$$$$"+holderforbytes[0]+holderforbytes[1]+holderforbytes[2]+holderforbytes[3]+holderforbytes[4]);

            // BigInteger[] ciphertext = new BigInteger[holderforbytes.Length];
            List<BigInteger> ciphertext = new List<BigInteger>();
            // BigInteger ciphertexthold;
            int longestPart = (int)(holderforbytes[holderforbytes.Length - 1]);

            for (int i = 0; i < holderforbytes.Length -1; i += longestPart)
            {
                List<Byte> temp = new List<Byte>();
                Boolean mark = false;
                for (int j = i; j < i + longestPart; j++)
                {
                    if (holderforbytes[j] != (Byte)0)
                        mark = true;
                    if (mark)
                        temp.Add(holderforbytes[j]);
                }
                temp.Add((Byte)00);
                ciphertext.Add(new BigInteger(temp.ToArray()));
            }
            BigInteger[] ciphertext1 = ciphertext.ToArray();


            BigInteger d = D;
            BigInteger n = N;



            byte [] plaintext = new byte [ciphertext1.Length];
            BigInteger [] bigPlainText = new BigInteger[ciphertext1.Length];
            // string stringPlainText="";
            for (int i = 0; i < ciphertext1.Length; i++) {
                BigInteger currentMod  = ciphertext1[i] % n;
                BigInteger res = 1;
                for (int j = (int)d; j > 0; j--) {
                    res = (res * currentMod) % n;
                }
                bigPlainText[i] = res;
            }

            // for (int i = 0; i < bigPlainText.Length; i++) {

            //     if (bigPlainText[i] < 10 ) {
            //         stringPlainText = stringPlainText +"0" + bigPlainText[i].ToString();

            //     }
            //     else {
            //     stringPlainText = stringPlainText + bigPlainText[i].ToString();
            //     }
            //  //Console.WriteLine (stringPlainText);
            // }
            //Console.WriteLine(stringPlainText);


            // Encoding utf8 = Encoding.UTF8;
            // plaintext = Encoding.ASCII.GetBytes(stringPlainText);
            List<Byte> plaintext1 = new List<Byte>();
            for (int i = 0; i < bigPlainText.Length; i ++)
            {
                byte[] temp = bigPlainText[i].ToByteArray();
                for (int j = 0; j < temp.Length; j++)
                {
                    plaintext1.Add(temp[j]);
                }
            }
            byte[] plaintext2 = plaintext1.ToArray();

            return plaintext2;
        }

        public BigInteger getTheD(){
          return this.d;
        }
        public BigInteger getTheN(){
          return this.n;
        }


    //     static void Main(string[] args)
    //     {
    //    byte [] tester = {02,15,24,09,23,4,16,8,9};
    //    BigInteger [] tester2 = encrypt(tester,71,53);
    //     for (int i =0; i < tester2.Length; i++) {
    //         Console.WriteLine(tester2[i]);
    //     }
    //     Console.WriteLine("===================");
    //     byte [] tester3 = decrypt(tester2,.d,.n);
    //     for (int i =0; i < tester3.Length; i++) {
    //         Console.WriteLine(tester3[i]);
    //     }
    //     Console.WriteLine("TESTING p + q\n" + .p +"\n" + .q);
    //     }
    }
}
