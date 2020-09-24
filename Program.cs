using System;
using System.Numerics;

namespace P3
{
    class Program
    {
        static void Main(string[] args)
        {
            //initialize input variables 
            var (initVec, g_e, g_c, N_e, N_c, x, g_y, cipherText, plainText) = Init.Compute(args);

            // this is the base being used in the key  when calculating (g^x)^y modN
            // this is usually a 1024 bit prime number and is the primitive root of n
            // g is the primitive root of n, then g mod n, g² mod n … gⁿ⁻¹ mod n
            // generates all the integers within the range [1, n-1]
            BigInteger g = BigInteger.Pow(2, (int) g_e) - g_c;

            // this is  another 1024 bit prime number  
            BigInteger N = BigInteger.Pow(2, (int) N_e) - N_c;

            // this is the secret key, given that the person sharing secrets with you gives you
            // g^y mod N. you generate your shared key by raising this to the exponent of x -> your secret key 
            // the secret key is calculated via (g^y)^x modN. 
            byte[] Key = BigInteger.ModPow(g_y, x, N).ToByteArray();

            //given plaintext, the secret key and the initialization vector plaintext -> ciphertext 
            byte[] encryption = AesEncDec.EncryptStringToBytes(plainText, Key, initVec);

            //given ciphertext, the secret key and the initialization vector ciphertext -> plaintext 
            string decryption = AesEncDec.DecryptStringFromBytes(cipherText, Key, initVec);

            Console.WriteLine($"{decryption},{BitConverter.ToString(encryption).Replace("-", " ")}");
        }
    }
}