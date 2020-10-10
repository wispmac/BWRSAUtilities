using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Xml.Linq;

namespace BWRSAUtilities
{
    /// <summary>
    /// RSA key convertor class
    /// Author: Wispmac Shah
    /// CreateDate: September 26, 2020
    /// </summary>
    public static class RsaKeyConvert
    {
        /// <summary>
        /// Convert RSA Public Key from PEM to XML format
        /// </summary>
        /// <param name="publicKey">Public Key</param>
        /// <returns></returns>
        public static string PublicKeyPemToXml(string publicKey)
        {
            publicKey = RsaPemFormatHelper.PublicKeyFormat(publicKey);

            PemReader pr = new PemReader(new StringReader(publicKey));

            object obj = pr.ReadObject();

            if (!(obj is RsaKeyParameters rsaKey))
            {
                throw new Exception("Public key format is incorrect");
            }

            XElement publicElement = new XElement("RSAKeyValue");

            XElement pubmodulus = new XElement("Modulus", Convert.ToBase64String(rsaKey.Modulus.ToByteArrayUnsigned()));

            XElement pubexponent = new XElement("Exponent", Convert.ToBase64String(rsaKey.Exponent.ToByteArrayUnsigned()));

            publicElement.Add(pubmodulus);

            publicElement.Add(pubexponent);

            return publicElement.ToString();
        }

        /// <summary>
        /// Convert RSA Public Key from XML to PEM format
        /// </summary>
        /// <param name="publicKey">Public Key</param>
        /// <returns></returns>
        public static string PublicKeyXmlToPem(string publicKey)
        {
            XElement root = XElement.Parse(publicKey);

            XElement modulus = root.Element("Modulus");

            XElement exponent = root.Element("Exponent");

            RsaKeyParameters rsaKeyParameters = new RsaKeyParameters(false, new BigInteger(1, Convert.FromBase64String(modulus.Value)), new BigInteger(1, Convert.FromBase64String(exponent.Value)));

            StringWriter sw = new StringWriter();

            PemWriter pWrt = new PemWriter(sw);

            pWrt.WriteObject(rsaKeyParameters);

            pWrt.Writer.Close();

            return sw.ToString();
        }

        /// <summary>
        /// Convert RSA Private Key from PKCS1 to XML format
        /// </summary>
        /// <param name="privateKey">Private Key</param>
        /// <returns></returns>
        public static string PrivateKeyPkcs1ToXml(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs1PrivateKeyFormat(privateKey);

            PemReader pr = new PemReader(new StringReader(privateKey));

            if (!(pr.ReadObject() is AsymmetricCipherKeyPair asymmetricCipherKeyPair))
            {
                throw new Exception("Private key format is incorrect");
            }

            RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricCipherKeyPair.Private));

            XElement privatElement = new XElement("RSAKeyValue");

            XElement primodulus = new XElement("Modulus", Convert.ToBase64String(rsaPrivateCrtKeyParameters.Modulus.ToByteArrayUnsigned()));

            XElement priexponent = new XElement("Exponent", Convert.ToBase64String(rsaPrivateCrtKeyParameters.PublicExponent.ToByteArrayUnsigned()));

            XElement prip = new XElement("P", Convert.ToBase64String(rsaPrivateCrtKeyParameters.P.ToByteArrayUnsigned()));

            XElement priq = new XElement("Q", Convert.ToBase64String(rsaPrivateCrtKeyParameters.Q.ToByteArrayUnsigned()));

            XElement pridp = new XElement("DP", Convert.ToBase64String(rsaPrivateCrtKeyParameters.DP.ToByteArrayUnsigned()));

            XElement pridq = new XElement("DQ", Convert.ToBase64String(rsaPrivateCrtKeyParameters.DQ.ToByteArrayUnsigned()));

            XElement priinverseQ = new XElement("InverseQ", Convert.ToBase64String(rsaPrivateCrtKeyParameters.QInv.ToByteArrayUnsigned()));

            XElement prid = new XElement("D", Convert.ToBase64String(rsaPrivateCrtKeyParameters.Exponent.ToByteArrayUnsigned()));

            privatElement.Add(primodulus);

            privatElement.Add(priexponent);

            privatElement.Add(prip);

            privatElement.Add(priq);

            privatElement.Add(pridp);

            privatElement.Add(pridq);

            privatElement.Add(priinverseQ);

            privatElement.Add(prid);

            return privatElement.ToString();
        }

        /// <summary>
        /// Convert RSA Private Key from XML to PKCS1 format
        /// </summary>
        /// <param name="privateKey">Private Key</param>
        /// <returns></returns>
        public static string PrivateKeyXmlToPkcs1(string privateKey)
        {
            XElement root = XElement.Parse(privateKey);

            XElement modulus = root.Element("Modulus");

            XElement exponent = root.Element("Exponent");

            XElement p = root.Element("P");

            XElement q = root.Element("Q");

            XElement dp = root.Element("DP");

            XElement dq = root.Element("DQ");

            XElement inverseQ = root.Element("InverseQ");

            XElement d = root.Element("D");

            RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters=new RsaPrivateCrtKeyParameters(
                new BigInteger(1,Convert.FromBase64String(modulus.Value)),
                new BigInteger(1, Convert.FromBase64String(exponent.Value)),
                new BigInteger(1, Convert.FromBase64String(d.Value)),
                new BigInteger(1, Convert.FromBase64String(p.Value)),
                new BigInteger(1, Convert.FromBase64String(q.Value)),
                new BigInteger(1, Convert.FromBase64String(dp.Value)),
                new BigInteger(1, Convert.FromBase64String(dq.Value)),
                new BigInteger(1, Convert.FromBase64String(inverseQ.Value)
            ));

            StringWriter sw = new StringWriter();

            PemWriter pWrt = new PemWriter(sw);

            pWrt.WriteObject(rsaPrivateCrtKeyParameters);

            pWrt.Writer.Close();

            return sw.ToString();
        }

        /// <summary>
        /// Convert RSA Private Key from PKCS8 to XML format
        /// </summary>
        /// <param name="privateKey">Private Key</param>
        /// <returns></returns>
        public static string PrivateKeyPkcs8ToXml(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs8PrivateKeyFormatRemove(privateKey);

            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters) PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

            XElement privatElement = new XElement("RSAKeyValue");

            XElement primodulus = new XElement("Modulus", Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()));

            XElement priexponent = new XElement("Exponent", Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()));

            XElement prip = new XElement("P", Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()));

            XElement priq = new XElement("Q", Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()));

            XElement pridp = new XElement("DP", Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()));

            XElement pridq = new XElement("DQ", Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()));

            XElement priinverseQ = new XElement("InverseQ", Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()));

            XElement prid = new XElement("D", Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));

            privatElement.Add(primodulus);

            privatElement.Add(priexponent);

            privatElement.Add(prip);

            privatElement.Add(priq);

            privatElement.Add(pridp);

            privatElement.Add(pridq);

            privatElement.Add(priinverseQ);

            privatElement.Add(prid);

            return privatElement.ToString();
        }

        /// <summary>
        /// Convert RSA Private Key from XML to PKCS8 format
        /// </summary>
        /// <param name="privateKey">Private Key</param>
        /// <returns></returns>
        public static string PrivateKeyXmlToPkcs8(string privateKey)
        {
            XElement root = XElement.Parse(privateKey);

            XElement modulus = root.Element("Modulus");

            XElement exponent = root.Element("Exponent");

            XElement p = root.Element("P");

            XElement q = root.Element("Q");

            XElement dp = root.Element("DP");

            XElement dq = root.Element("DQ");

            XElement inverseQ = root.Element("InverseQ");

            XElement d = root.Element("D");

            RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters = new RsaPrivateCrtKeyParameters(
                new BigInteger(1, Convert.FromBase64String(modulus.Value)),
                new BigInteger(1, Convert.FromBase64String(exponent.Value)),
                new BigInteger(1, Convert.FromBase64String(d.Value)),
                new BigInteger(1, Convert.FromBase64String(p.Value)),
                new BigInteger(1, Convert.FromBase64String(q.Value)),
                new BigInteger(1, Convert.FromBase64String(dp.Value)),
                new BigInteger(1, Convert.FromBase64String(dq.Value)),
                new BigInteger(1, Convert.FromBase64String(inverseQ.Value)
            ));

            StringWriter swpri = new StringWriter();

            PemWriter pWrtpri = new PemWriter(swpri);

            Pkcs8Generator pkcs8 = new Pkcs8Generator(rsaPrivateCrtKeyParameters);

            pWrtpri.WriteObject(pkcs8);

            pWrtpri.Writer.Close();

            return swpri.ToString();
        }

        /// <summary>
        /// Convert RSA Private Key from PKCS1 to PKCS8 format
        /// </summary>
        /// <param name="privateKey">Private Key</param>
        /// <returns></returns>
        public static string PrivateKeyPkcs1ToPkcs8(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs1PrivateKeyFormat(privateKey);

            PemReader pr = new PemReader(new StringReader(privateKey));

            AsymmetricCipherKeyPair kp = pr.ReadObject() as AsymmetricCipherKeyPair;

            StringWriter sw = new StringWriter();

            PemWriter pWrt = new PemWriter(sw);

            Pkcs8Generator pkcs8 = new Pkcs8Generator(kp.Private);

            pWrt.WriteObject(pkcs8);

            pWrt.Writer.Close();

            string result = sw.ToString();

            return result;
        }

        /// <summary>
        /// Convert RSA Private Key from PKCS8 to PKCS1 format
        /// </summary>
        /// <param name="privateKey">Private Key</param>
        /// <returns></returns>
        public static string PrivateKeyPkcs8ToPkcs1(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs8PrivateKeyFormat(privateKey);

            PemReader pr = new PemReader(new StringReader(privateKey));

            RsaPrivateCrtKeyParameters kp = pr.ReadObject() as RsaPrivateCrtKeyParameters;

            AsymmetricKeyParameter keyParameter = PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp));

            StringWriter sw = new StringWriter();

            PemWriter pWrt = new PemWriter(sw);

            pWrt.WriteObject(keyParameter);

            pWrt.Writer.Close();

            string result = sw.ToString();

            return result;
        }
    }
}
