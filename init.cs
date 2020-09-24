using System;
using System.Numerics;

namespace P3
{
    public class Init
    {
        /* given the following inputs, initialized accordingly. 128 bit string given via bytes in hex
           seperated by " " is converted to a byte array by StringToByteArr method 
           1) 128-bit IV in hex
           2) g_e in base 10
           3) g_c in base 10
           4) N_e in base 10
           5) N_c in base 10
           6) x inbase10
           7) g^y modN inbase10
           8) An encrypted message C in hex
           9) A plaintext message P as a string */
        
        public static (byte[], BigInteger, BigInteger, BigInteger, BigInteger, 
            BigInteger, BigInteger, byte[], string) Compute(string[] args)
        {
            return (StringToByteArr(args[0]),
                BigInteger.Parse(args[1]),
                BigInteger.Parse(args[2]),
                BigInteger.Parse(args[3]),
                BigInteger.Parse(args[4]),
                BigInteger.Parse(args[5]),
                BigInteger.Parse(args[6]),
                StringToByteArr(args[7]),
                args[8]);

        }
        
        public static  byte[] StringToByteArr(String hex)
        {
            // given a string of bytes in hex format with a space in between give the appropriate 
            // conversion to a byte array. Used to get out initialization vector in the proper format 
            // for aes encryption and decryption 
            string initVec=String.Join("",hex.Split(" "));
            int numberChars = initVec.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(initVec.Substring(i, 2), 16);
            return bytes;
        }
    }
}