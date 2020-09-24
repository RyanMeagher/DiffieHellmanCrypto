using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;

namespace P3
{
    class Program
    {
        public static byte[] StringToByteArr(String hex)
        {
            string initVec=String.Join("",hex.Split(" "));
            int numberChars = initVec.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(initVec.Substring(i, 2), 16);
            return bytes;
        }

        public static (byte[], BigInteger, BigInteger, BigInteger, BigInteger, 
            BigInteger, BigInteger, byte[], string) init(string[] args)
        {
            return (StringToByteArr(args[0]),
                (BigInteger) Convert.ToDecimal(args[1]),
                (BigInteger) Convert.ToDecimal(args[2]),
                (BigInteger) Convert.ToDecimal(args[3]),
                (BigInteger) Convert.ToDecimal(args[4]),
                (BigInteger) Convert.ToDecimal(args[5]),
                BigInteger.Parse(args[6]),
                StringToByteArr(args[7]),
                args[8]);

        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] key, byte[] IV)
        {
            byte[] encrypted;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    
        static void Main(string[] args)
        {
            var (initVec, g_e, g_c, N_e, N_c, x, g_y, cipherText, plainText) = init(args);

            BigInteger g=BigInteger.Pow(2, (int) g_e)-g_c;
            BigInteger N = BigInteger.Pow(2, (int) N_e)-N_c;
            byte[] Key = BigInteger.ModPow(g_y, x, N).ToByteArray();
            
            byte[] encryption= EncryptStringToBytes_Aes(plainText, Key,initVec);
            string decryption = DecryptStringFromBytes_Aes(cipherText, Key, initVec);
            
            Console.WriteLine($"{decryption},{BitConverter.ToString(encryption).Replace("-"," ")}");
        }
    }
}