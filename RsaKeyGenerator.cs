using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace BWRSAUtilities
{
    /// <summary>
    /// RSA key generator class
    /// Author: Wispmac Shah
    /// CreateDate: September 26, 2020
    /// </summary>
    public static class RsaKeyGenerator
    {
        /// <summary>
        /// Generate RSA Key in XML Format
        /// </summary>
        /// <param name="keySize">Key Size - 1024, 2048 or 4096 bytes</param>
        /// <returns>List<string></string>Where index 0 is the Private Key and index 1 is the Public Key</returns>
        public static List<string> XmlKey(int keySize)
        {
            RSA rsa = RSA.Create();

            rsa.KeySize = keySize;

            RSAParameters rsap = rsa.ExportParameters(true);

            List<string> res = new List<string>();

            XElement privatElement = new XElement("RSAKeyValue");

            XElement primodulus = new XElement("Modulus", Convert.ToBase64String(rsap.Modulus));

            XElement priexponent = new XElement("Exponent", Convert.ToBase64String(rsap.Exponent));

            XElement prip = new XElement("P", Convert.ToBase64String(rsap.P));

            XElement priq = new XElement("Q", Convert.ToBase64String(rsap.Q));

            XElement pridp = new XElement("DP", Convert.ToBase64String(rsap.DP));

            XElement pridq = new XElement("DQ", Convert.ToBase64String(rsap.DQ));

            XElement priinverseQ = new XElement("InverseQ", Convert.ToBase64String(rsap.InverseQ));

            XElement prid = new XElement("D", Convert.ToBase64String(rsap.D));

            privatElement.Add(primodulus);

            privatElement.Add(priexponent);

            privatElement.Add(prip);

            privatElement.Add(priq);

            privatElement.Add(pridp);

            privatElement.Add(pridq);

            privatElement.Add(priinverseQ);

            privatElement.Add(prid);

            res.Add(privatElement.ToString());

            XElement publicElement = new XElement("RSAKeyValue");

            XElement pubmodulus = new XElement("Modulus", Convert.ToBase64String(rsap.Modulus));

            XElement pubexponent = new XElement("Exponent", Convert.ToBase64String(rsap.Exponent));

            publicElement.Add(pubmodulus);

            publicElement.Add(pubexponent);

            res.Add(publicElement.ToString());

            return res;
        }

        /// <summary>
        /// Generate RSA Key in PKCS1 Format
        /// </summary>
        /// <param name="keySize">Key Size - 1024, 2048 or 4096 bytes</param>
        /// <param name="format">Boolean parameter if you want to format the key</param>
        /// <returns>List<string></string>Where index 0 is the Private Key and index 1 is the Public Key</returns>
        public static List<string> Pkcs1Key(int keySize, bool format)
        {
            List<string> res = new List<string>();

            IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");

            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));

            AsymmetricCipherKeyPair keyPair = kpGen.GenerateKeyPair();

            StringWriter sw = new StringWriter();

            PemWriter pWrt = new PemWriter(sw);

            pWrt.WriteObject(keyPair.Private);

            pWrt.Writer.Close();

            string privateKey = sw.ToString();

            if (!format)
            {
                privateKey = privateKey.Replace("-----BEGIN RSA PRIVATE KEY-----", "").Replace("-----END RSA PRIVATE KEY-----", "").Replace("\r\n", "");
            }

            res.Add(privateKey);

            StringWriter swpub = new StringWriter();

            PemWriter pWrtpub = new PemWriter(swpub);

            pWrtpub.WriteObject(keyPair.Public);

            pWrtpub.Writer.Close();

            string publicKey = swpub.ToString();

            if (!format)
            {
                publicKey = publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\r\n", "");
            }

            res.Add(publicKey);

            return res;
        }

        /// <summary>
        /// Generate RSA Key in PKCS8 Format
        /// </summary>
        /// <param name="keySize">Key Size - 1024, 2048 or 4096 bytes</param>
        /// <param name="format">Boolean parameter if you want to format the key</param>
        /// <returns>List<string></string>Where index 0 is the Private Key and index 1 is the Public Key</returns>
        public static List<string> Pkcs8Key(int keySize, bool format)
        {
            List<string> res = new List<string>();

            IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");

            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));

            AsymmetricCipherKeyPair keyPair = kpGen.GenerateKeyPair();

            StringWriter swpri = new StringWriter();

            PemWriter pWrtpri = new PemWriter(swpri);

            Pkcs8Generator pkcs8 = new Pkcs8Generator(keyPair.Private);

            pWrtpri.WriteObject(pkcs8);

            pWrtpri.Writer.Close();

            string privateKey = swpri.ToString();

            if (!format)
            {
                privateKey = privateKey.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace("\r\n", "");
            }

            res.Add(privateKey);

            StringWriter swpub = new StringWriter();

            PemWriter pWrtpub = new PemWriter(swpub);

            pWrtpub.WriteObject(keyPair.Public);

            pWrtpub.Writer.Close();

            string publicKey = swpub.ToString();

            if (!format)
            {
                publicKey = publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\r\n", "");
            }

            res.Add(publicKey);

            return res;
        }
    }
}
