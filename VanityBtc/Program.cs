using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Numerics;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Math.EC;
using System.Diagnostics;
using Org.BouncyCastle.Asn1.X9;
using System.Threading;
using System.IO;

namespace VanityBitcoin
{
    class Program
    {
        public static int GetHexVal(char hex)
        {
            int val = hex;
            return val - (val < 58 ? 48 : 55);
        }
        static long count = 0;
        static void Main(string[] args)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            TimeSpan ts = new TimeSpan();
            int threadCount = 6;
            for (int i = 0; i < threadCount; i++)
            {
                ThreadStart thrdstrt = delegate
                {
                    DoGeneration();
                };
                Thread thrd = new Thread(thrdstrt);
                thrd.Start();
            }
            while (true)
            {
                Thread.Sleep(70);
                ts = sw.Elapsed;
                Console.Title = $"Threads={threadCount} | Count={count} | Elapsed ={ts.TotalMinutes.ToString("0.00")} min | Average rate={(count / ts.TotalSeconds).ToString("0.0")} address/s "; //count/sw.ElapsedMilliseconds/1000

            }
        }
        static void DoGeneration()
        {
            Org.BouncyCastle.Security.SecureRandom random = new Org.BouncyCastle.Security.SecureRandom();
            Org.BouncyCastle.Math.BigInteger number = new Org.BouncyCastle.Math.BigInteger(256, random);
            byte[] byteArray = new byte[32];
            Tuple<byte[], byte[]> publicXYkeys;
            byte[] prefix = new byte[] { 4 };
            byte[] finalBtcAddress = new byte[25];
            string base58Address = string.Empty;
            byte[] privateKey = new byte[1];
            while (true)
            {
                byteArray = number.ToByteArray();
                number = number.Add(new Org.BouncyCastle.Math.BigInteger("1"));
                privateKey = byteArray;
                publicXYkeys = GetPublicKey(byteArray);
                byteArray = new byte[65];
                prefix.CopyTo(byteArray, 0);
                publicXYkeys.Item1.CopyTo(byteArray, 1);
                publicXYkeys.Item2.CopyTo(byteArray, publicXYkeys.Item1.Length + 1);
                byteArray = SHA256.Create().ComputeHash(byteArray);
                byteArray = RIPEMD160.Create().ComputeHash(byteArray);
                byte[] pubkeySHA256RIPEMD160withPrefix = new byte[byteArray.Length + 1];
                byteArray.CopyTo(pubkeySHA256RIPEMD160withPrefix, 1);
                byteArray = SHA256.Create().ComputeHash(pubkeySHA256RIPEMD160withPrefix);
                byteArray = SHA256.Create().ComputeHash(byteArray);
                pubkeySHA256RIPEMD160withPrefix.CopyTo(finalBtcAddress, 0);
                finalBtcAddress[21] = byteArray[0];
                finalBtcAddress[22] = byteArray[1];
                finalBtcAddress[23] = byteArray[2];
                finalBtcAddress[24] = byteArray[3];
                base58Address = Base58Encode(finalBtcAddress);
                string base58Lower = base58Address.ToLower();
                List<char> list = new List<char>();
                if (base58Address.Length == 34)
                {
                    int j = 33;
                    while (j > 29)
                    {
                        if (!list.Contains(base58Lower[j]))
                            list.Add(base58Lower[j]);
                        j--;
                    }
                    if (list.Count < 2)
                    {
                        PrintAndSave(base58Address, privateKey);
                    }
                }
                else // sometimes bitcoin addresses have length of 33 symbols
                {
                    int j = 32;
                    while (j > 29)
                    {
                        if (!list.Contains(base58Lower[j]))
                            list.Add(base58Lower[j]);
                        j--;
                    }
                    if (list.Count < 2)
                    {
                        PrintAndSave(base58Address, privateKey);
                    }
                }
                base58Lower = base58Lower.Substring(27, base58Lower.Length - 27); // for accurate checking some last symbols of address
                if (base58Lower.Contains("fuck"))
                {
                    PrintAndSave(base58Address, privateKey);
                }
                count++;
            }
        }
        public static void PrintAndSave(string base58Address, byte[] privateKey)
        {
            string base58Private = Base58Encode(privateKey);
            Console.WriteLine(base58Address + ":" + base58Private);
            File.AppendAllText("result.txt", $"{base58Address}:{base58Private}\n");
        }
        public static string Base58Encode(byte[] array)
        {
            const string ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            string retString = string.Empty;
            BigInteger encodeSize = ALPHABET.Length;
            BigInteger arrayToInt = 0;
            for (int i = 0; i < array.Length; ++i)
            {
                arrayToInt = arrayToInt * 256 + array[i];
            }
            while (arrayToInt > 0)
            {
                int rem = (int)(arrayToInt % encodeSize);
                arrayToInt /= encodeSize;
                retString = ALPHABET[rem] + retString;
            }
            for (int i = 0; i < array.Length && array[i] == 0; ++i)
                retString = ALPHABET[0] + retString;
            return retString;
        }
        static Tuple<byte[], byte[]> GetPublicKey(byte[] privateKey)
        {
            Org.BouncyCastle.Math.BigInteger privKeyInt = new Org.BouncyCastle.Math.BigInteger(+1, privateKey);
            X9ECParameters parameters = SecNamedCurves.GetByName("secp256k1");
            ECPoint qa = parameters.G.Multiply(privKeyInt);
            byte[] pubKeyX = qa.XCoord.ToBigInteger().ToByteArrayUnsigned();
            byte[] pubKeyY = qa.YCoord.ToBigInteger().ToByteArrayUnsigned();
            return Tuple.Create(pubKeyX, pubKeyY);
        }
    }
}