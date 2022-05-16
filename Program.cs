using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Numerics;

using vsCodeDotNet;//Rc4 file
using AESWithCTRSpace; //AES file 1
using AESImplementationSpace;//AES file 2
using ECCoremod; // ECC file
using RSA;

namespace myXor
{
    class Program
    {

        private static String autokeyFileLocation = "\\autopasswords.txt";
        private static String ranIVgen = "";
        private static String ranPasswordgen = "";
        private static BigInteger RSAp = 0;
        private static BigInteger RSAq = 0;
        private static BigInteger RSAd = 0;
        private static BigInteger RSAn = 0;
        private static BigInteger RSAe = 0;
        private static int autoDecryptCounter = 0;
        private static String[] autoDecryptLine;
        private static String autoDecryptString = "";
        private static String[] autoDecryptLineAES;
        private static String currentDir = "";
        private static String srcKey = "";
        private static String srcAlgo = "";
        private static String srcFileFolder = "";
        private static String srcFile = "";
        private static String srcFolder = "";
        private static String srcAction = "";
        private static String srcType = "";
        private static String srcIV = "";
        private static int  choiceLoopOut = 0;
        private static String choiceAuto = "auto";
        private static String choiceSym = "sym";
        private static String choiceAsym = "asym";
        private static String choiceAlgoXOR = "XOR";
        private static String choiceAlgoAES = "AES";
        private static String choiceAlgoRC4 = "RC4";
        private static String choiceAlgoRSA = "RSA";
        private static String choiceAlgoECC = "ECC";
        private static String choiceEncrypt = "encrypt";
        private static String choiceDecrypt = "decrypt";
        private static String choiceFolder = "Folder";
        private static String choiceFile = "File";
        static void Main(string[] args)
        {

          Console.WriteLine("Encryption v02 \n \n");



          do{ // Input type (sym or asym):
            Console.WriteLine("Input type (sym or asym):");
            srcType = Console.ReadLine();

            if (srcType.Equals(choiceSym)){
                choiceLoopOut = 0;

                do{ //Choose Algorithm (XOR,AES,RC4):
                  Console.WriteLine("Choose Algorithm (XOR,AES,RC4):");
                  srcAlgo = Console.ReadLine();

                  if ((srcAlgo.Equals(choiceAlgoXOR))|(srcAlgo.Equals(choiceAlgoAES))|(srcAlgo.Equals(choiceAlgoRC4))){
                      choiceLoopOut = 0;


                    }else{
                      Console.WriteLine("Invalid choice. Try again. \n");
                      choiceLoopOut = 1;
                  }
                }while(choiceLoopOut == 1);


              }else if (srcType.Equals(choiceAsym)){
                choiceLoopOut = 0;

                do{ // Choose Algorithm (RSA,ECC):
                  Console.WriteLine("Choose Algorithm (RSA,ECC):");
                  srcAlgo = Console.ReadLine();

                  if ((srcAlgo.Equals(choiceAlgoRSA))|(srcAlgo.Equals(choiceAlgoECC))){
                      choiceLoopOut = 0;
                    }else{
                      Console.WriteLine("Invalid choice. Try again. \n");
                      choiceLoopOut = 1;
                  }
                }while(choiceLoopOut == 1);


              }else{
                Console.WriteLine("Invalid choice. Try again. \n");
                choiceLoopOut = 1;
            }

          }while(choiceLoopOut == 1);
          if (srcAlgo.Equals(choiceAlgoRSA)){
              Console.WriteLine("Input a prime value less then 1.8x10^153 (\"auto\" to encrypt each file with a new and random prime):");  ///maybe add an auto key function later - like for each file in a folder a new key is generated and stored in a txt file
              srcKey = Console.ReadLine();
              currentDir = Directory.GetCurrentDirectory();
                if(File.Exists(currentDir+autokeyFileLocation)){
                }else{
                  using (StreamWriter sw = File.CreateText(currentDir+autokeyFileLocation))  { }
                    Console.WriteLine("File created: "+ autokeyFileLocation);
                }
              if (srcKey.Equals(choiceAuto)){

                // implentation for the auto choice is in SelectorForAlgo since we do not need to get up any more strings

              }else{

                if(double.Parse(srcKey) == null){
                  while(double.Parse(srcKey)!= null){
                    Console.WriteLine(srcKey+" is not a valid number.\n");
                    Console.WriteLine("Input a prime value less then 1.8x10^153");
                    srcKey = Console.ReadLine();
                  }
                }
                RSAp = BigInteger.Parse(srcKey);

                Console.WriteLine("Input a second prime value less then 1.8x10^153:");
                srcKey = Console.ReadLine();
                if(double.Parse(srcKey) == null){
                  while(double.Parse(srcKey)!= null){
                    Console.WriteLine(srcKey+" is not a valid number.\n");
                    Console.WriteLine("Input a prime value less then 1.8x10^153:");
                    srcKey = Console.ReadLine();
                  }
              }
              RSAq = BigInteger.Parse(srcKey);

              Console.WriteLine("Input a valid \"e\" value:");
              srcKey = Console.ReadLine();
              if(double.Parse(srcKey) == null){
                while(double.Parse(srcKey)!= null){
                  Console.WriteLine(srcKey+" is not a valid number.\n");
                  Console.WriteLine("Input a valid \"e\" value:");
                  srcKey = Console.ReadLine();
                }
            }
            RSAe = BigInteger.Parse(srcKey);
             }

          }else{
            Console.WriteLine("Input key (\"auto\" to encrypt each file with a new and random key):");  ///maybe add an auto key function later - like for each file in a folder a new key is generated and stored in a txt file
            srcKey = Console.ReadLine();
            if (srcKey.Equals(choiceAuto)){
                  currentDir = Directory.GetCurrentDirectory();
                  if(File.Exists(currentDir+autokeyFileLocation)){

                  }else{
                    using (StreamWriter sw = File.CreateText(currentDir+autokeyFileLocation))  { }
                      Console.WriteLine("File created: "+ autokeyFileLocation);
                  }
            }
          }




          do{ // Input action (decrypt/encrypt):
            Console.WriteLine("Input action (decrypt/encrypt):");

            srcAction = Console.ReadLine();
            if ((srcAction.Equals(choiceDecrypt))|(srcAction.Equals(choiceEncrypt))){
                choiceLoopOut = 0;
                if (srcAction.Equals(choiceDecrypt)){
                  autoDecryptLine = File.ReadAllLines(currentDir+autokeyFileLocation);
                }else{
                  File.Delete(currentDir+autokeyFileLocation);
                  using (StreamWriter sw = File.CreateText(currentDir+autokeyFileLocation))  { }
                //  Console.WriteLine("File rewritten: "+ autokeyFileLocation);
                }

              }else{
                Console.WriteLine("Invalid choice. Try again. \n");
                choiceLoopOut = 1;
            }

          }while(choiceLoopOut == 1);

          do{ // Single file or Folder (Folder or File):
            Console.WriteLine("Single file or Folder (Folder or File): "); // add folder scan option here later
            srcFileFolder = Console.ReadLine();

            if (srcFileFolder.Equals(choiceFolder)){ // add code for folders
                choiceLoopOut = 0;

                Console.WriteLine("Enter Folder Path: ");
                srcFolder = Console.ReadLine();

                TraverseTree(srcFolder,srcAlgo,srcKey,srcAction);//Taken and modified from https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/file-system/how-to-iterate-through-a-directory-tree

              }else if (srcFileFolder.Equals(choiceFile)){
                choiceLoopOut = 0;
                Console.WriteLine("Enter file name or path: ");
                srcFile = Console.ReadLine();
                SelectorForAlgo(srcFile,srcAlgo,srcKey,srcAction);

              }else{
                Console.WriteLine("Invalid choice. Try again. \n");
                choiceLoopOut = 1;
            }

          }while(choiceLoopOut == 1);








          }

          private static void SelectorForAlgo( string chosenFile, string chosenAlgo, string chosenKey, string chosenAction){

            if ((chosenKey.Equals(choiceAuto))||((chosenAlgo.Equals(choiceAlgoRSA))&&(chosenAction.Equals(choiceDecrypt)))){

                  if(chosenAction.Equals(choiceEncrypt)){

                    using (StreamWriter file = File.AppendText(currentDir+autokeyFileLocation)){

                      if(chosenAlgo.Equals(choiceAlgoAES)){
                        ranIVgen = GetRandomAlphaNumeric(4);
                        ranPasswordgen = GetRandomAlphaNumeric(8);
                        file.WriteLine(ranPasswordgen +"="+ ranIVgen);
                      }else{
                        ranPasswordgen = GetRandomAlphaNumeric(8);
                        file.WriteLine(ranPasswordgen);
                      }
                    }
                  }else if (chosenAction.Equals(choiceDecrypt)){

                      autoDecryptString = autoDecryptLine[autoDecryptCounter];
                      autoDecryptCounter = (autoDecryptCounter + 1);


                    if(chosenAlgo.Equals(choiceAlgoAES)){
                     autoDecryptLineAES = autoDecryptString.Split('=');
                     ranIVgen = autoDecryptLineAES[1];
                     ranPasswordgen = autoDecryptLineAES[0];

                    }else if(chosenAlgo.Equals(choiceAlgoRSA)){
                     autoDecryptLineAES = autoDecryptString.Split('=');
                     RSAd = (BigInteger) Double.Parse(autoDecryptLineAES[0]);
                     RSAn = (BigInteger) Double.Parse(autoDecryptLineAES[1]);

                     Console.WriteLine("\n \n"+RSAd+"="+RSAn+"\n \n");

                    }else{
                      ranPasswordgen = autoDecryptString;
                    }

                  }else{

                  }
            }else{
              ranPasswordgen = chosenKey;

            }


    if(chosenAlgo.Equals(choiceAlgoXOR)){
                try{
                  Byte[] Encrypt = xorEncrypt(File.ReadAllBytes(chosenFile), ranPasswordgen);
                  File.WriteAllBytes(chosenFile, Encrypt);
                  Console.WriteLine("\n "+chosenAction+" done for " + chosenFile + " with " + chosenAlgo + ".");
                }catch(System.Exception e)
                {
                  Console.WriteLine("\n Error with XOR Algorithm for "+ chosenFile);
                }
    }else if(chosenAlgo.Equals(choiceAlgoAES)){
            if (chosenKey.Equals(choiceAuto)){
                srcIV = ranIVgen;
            }else{
                Console.WriteLine("Enter a 4 character IV: ");
                srcIV = Console.ReadLine();
                ranPasswordgen = chosenKey;
            }


                AESWithCTR fc = new AESWithCTR(chosenFile,ranPasswordgen,srcIV);

                if(chosenAction.Equals(choiceEncrypt)){
                  fc.setAction(AESWithCTR.ENCRYPT);
                }else if(chosenAction.Equals(choiceDecrypt)){
                  fc.setAction(AESWithCTR.DECRYPT);
                }else{
                    Console.WriteLine("\n wroung choice for AES encrypt/decrypt");
                }

                fc.StartCrypto();
                Console.WriteLine("\n "+chosenAction+" done for " + chosenFile + " with " + chosenAlgo + ".");

  }else if(chosenAlgo.Equals(choiceAlgoECC)){
        // Console.WriteLine("--------------------------------------------------------------------------------------Passing: "+chosenFile);
        // Console.WriteLine("--------------------------------------------------------------------------------------Passing: "+ranPasswordgen);

         ECCore ecc = new ECCore();

         if(chosenAction.Equals(choiceEncrypt)){
            ecc.Encrypt(ranPasswordgen, chosenFile);

         }else if(chosenAction.Equals(choiceDecrypt)){
            ecc.Decrypt(ranPasswordgen,chosenFile);
         }else{
             Console.WriteLine("\n wroung choice for ECC encrypt/decrypt");
         }

  }else if(chosenAlgo.Equals(choiceAlgoRC4)){
                Rc4 a = new Rc4();

                if(chosenAction.Equals(choiceEncrypt)){
                            File.WriteAllBytes(chosenFile, a.RC4Encrypt(File.ReadAllBytes(chosenFile),ranPasswordgen));
                          }else if(chosenAction.Equals(choiceDecrypt)){
                            File.WriteAllBytes(chosenFile, a.RC4Decrypt(File.ReadAllBytes(chosenFile),ranPasswordgen));
                          }else{
                          Console.WriteLine("\n wroung choice for RC4 encrypt/decrypt");
                        }
                Console.WriteLine("\n "+chosenAction+" done for " + chosenFile + " with " + chosenAlgo + ".");


  }else if(chosenAlgo.Equals(choiceAlgoRSA)){
                RSAstate rsa = new RSAstate();
                if(chosenAction.Equals(choiceEncrypt)){
                                    File.WriteAllBytes(chosenFile, rsa.encrypt(File.ReadAllBytes(chosenFile),RSAp,RSAq,RSAe));// RSAp,RSAq));
                                    RSAd = rsa.getTheD();
                                    RSAn = rsa.getTheN();
                                    double safeRSAd = (double) RSAd;
                                    double safeRSAn = (double) RSAn;
                                    Console.WriteLine("\n \n The private key Generated is \n  D = "+RSAd+"\n  N = "+RSAn+"\n");
                                    using (StreamWriter file = File.AppendText(currentDir+autokeyFileLocation)){
                                        file.WriteLine(safeRSAd+"="+safeRSAn);
                                    }

                                    // using (StreamWriter file = File.AppendText(currentDir+autokeyFileLocation)){
                                    //     file.WriteLine(rsa.getTheD() +"="+ rsa.getTheN());
                                    // }

                        }else if(chosenAction.Equals(choiceDecrypt)){
                              //  Console.WriteLine("OUTOUT=======================================================@ "+File.ReadAllBytes(chosenFile)[0]+File.ReadAllBytes(chosenFile)[0]+File.ReadAllBytes(chosenFile)[0]+);


                              //File.WriteAllBytes(chosenFile, rsa.decrypt(converted,RSAd,RSAn));

                              Console.WriteLine("\n \n The private key used in decryption is \n  D = "+RSAd+"\n  N = "+RSAn+"\n");
                              RSAd = 3;
                              RSAn = 33;
                                File.WriteAllBytes(chosenFile, rsa.decrypt(File.ReadAllBytes(chosenFile),RSAd,RSAn));
                                  }else{
                                  Console.WriteLine("\n wroung choice for RCA encrypt/decrypt");
                                }
                        Console.WriteLine("\n "+chosenAction+" done for " + chosenFile + " with " + chosenAlgo + ".");




  }else{
                Console.WriteLine("Something went teriably wrong, the Algo selected is: "+ chosenAlgo);
              }


    }


          private static Byte[] xorEncrypt (byte[] filePathInBytes, string key){
            List<Byte> converetdOutput = new List<byte>();
            Byte[] convertedKey = Encoding.UTF8.GetBytes(key);

            for (int i = 0; i < filePathInBytes.Length; i++){
              converetdOutput.Add((Byte)(filePathInBytes[i] ^ convertedKey[i % convertedKey.Length]));
            }
            return converetdOutput.ToArray();

          }

          public static string GetRandomAlphaNumeric(int sizeGen){
                return Path.GetRandomFileName().Replace(".", "").Substring(0, sizeGen);
            }



           public static void TraverseTree(string root, string TchosenAlgo, string TchosenKey, string TchosenAction){ //taken from, but modified https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/file-system/how-to-iterate-through-a-directory-tree
                // Data structure to hold names of subfolders to be
                // examined for files.

                Stack<string> dirs = new Stack<string>(20);

                if (!System.IO.Directory.Exists(root))
                {
                    throw new ArgumentException();
                }
                dirs.Push(root);

                while (dirs.Count > 0)
                {
                    string currentDir = dirs.Pop();
                    string[] subDirs;
                    try
                    {
                        subDirs = System.IO.Directory.GetDirectories(currentDir);
                    }
                    // An UnauthorizedAccessException exception will be thrown if we do not have
                    // discovery permission on a folder or file. It may or may not be acceptable
                    // to ignore the exception and continue enumerating the remaining files and
                    // folders. It is also possible (but unlikely) that a DirectoryNotFound exception
                    // will be raised. This will happen if currentDir has been deleted by
                    // another application or thread after our call to Directory.Exists. The
                    // choice of which exceptions to catch depends entirely on the specific task
                    // you are intending to perform and also on how much you know with certainty
                    // about the systems on which this code will run.
                    catch (UnauthorizedAccessException e)
                    {
                        Console.WriteLine(e.Message);
                        continue;
                    }
                    catch (System.IO.DirectoryNotFoundException e)
                    {
                        Console.WriteLine(e.Message);
                        continue;
                    }

                    string[] files = null;
                    try
                    {
                        files = System.IO.Directory.GetFiles(currentDir);
                    }

                    catch (UnauthorizedAccessException e)
                    {

                        Console.WriteLine(e.Message);
                        continue;
                    }

                    catch (System.IO.DirectoryNotFoundException e)
                    {
                        Console.WriteLine(e.Message);
                        continue;
                    }
                    // Perform the required action on each file here.
                    // Modify this block to perform your required task.
                    foreach (string file in files)
                    {
                        try
                        {
                            // Perform whatever action is required in your scenario.
                            System.IO.FileInfo fi = new System.IO.FileInfo(file);
// My Selector

                            SelectorForAlgo(fi.FullName,TchosenAlgo,TchosenKey,TchosenAction);// My Selector
                        }
                        catch (System.IO.FileNotFoundException e)
                        {
                            // If file was deleted by a separate application
                            //  or thread since the call to TraverseTree()
                            // then just continue.
                            Console.WriteLine(e.Message);
                            continue;
                        }
                    }

                    // Push the subdirectories onto the stack for traversal.
                    // This could also be done before handing the files.
                    foreach (string str in subDirs)
                        dirs.Push(str);
                }
            }
    }
}
