using System.Collections.Generic;

namespace BWRSAUtilities
{
    /// <summary>
    /// RSA PEM Format key helper class
    /// Author: Wispmac Shah
    /// CreateDate: September 26, 2020
    /// </summary>
    public static class RsaPemFormatHelper
    {
        /// <summary>
        /// Add Header and Footer to RSA PKCS1 Private Key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string Pkcs1PrivateKeyFormat(string privateKey)
        {
            if (privateKey.StartsWith("-----BEGIN RSA PRIVATE KEY-----"))
            {
                return privateKey;
            }

            List<string> res = new List<string>();

            res.Add("-----BEGIN RSA PRIVATE KEY-----");

            int pos = 0;

            while (pos < privateKey.Length)
            {
                int count = privateKey.Length - pos<64? privateKey.Length - pos:64;

                res.Add(privateKey.Substring(pos, count));

                pos += count;
            }

            res.Add("-----END RSA PRIVATE KEY-----");

            string resStr = string.Join("\r\n", res);

            return resStr;
        }

        /// <summary>
        /// Remove Header and Footer from RSA PEM format PKCS1 Private Key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string Pkcs1PrivateKeyFormatRemove(string privateKey)
        {
            if (!privateKey.StartsWith("-----BEGIN RSA PRIVATE KEY-----"))
            {
                return privateKey;
            }

            return privateKey.Replace("-----BEGIN RSA PRIVATE KEY-----", "").Replace("-----END RSA PRIVATE KEY-----", "").Replace("\r\n", "");
        }

        /// <summary>
        /// Add Header and Footer to RSA PKCS8 Private Key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string Pkcs8PrivateKeyFormat(string privateKey)
        {
            if (privateKey.StartsWith("-----BEGIN PRIVATE KEY-----"))
            {
                return privateKey;
            }

            List<string> res = new List<string>();

            res.Add("-----BEGIN PRIVATE KEY-----");

            int pos = 0;

            while (pos < privateKey.Length)
            {
                int count = privateKey.Length - pos < 64 ? privateKey.Length - pos : 64;

                res.Add(privateKey.Substring(pos, count));

                pos += count;
            }

            res.Add("-----END PRIVATE KEY-----");

            string resStr = string.Join("\r\n", res);

            return resStr;
        }

        /// <summary>
        /// Remove Header and Footer from RSA PEM format PKCS8 Private Key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string Pkcs8PrivateKeyFormatRemove(string privateKey)
        {
            if (!privateKey.StartsWith("-----BEGIN PRIVATE KEY-----"))
            {
                return privateKey;
            }

            return privateKey.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace("\r\n", "");
        }

        /// <summary>
        /// Add Header and Footer to RSA Public Key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string PublicKeyFormat(string publicKey)
        {
            if (publicKey.StartsWith("-----BEGIN PUBLIC KEY-----"))
            {
                return publicKey;
            }

            List<string> res = new List<string>();

            res.Add("-----BEGIN PUBLIC KEY-----");

            int pos = 0;

            while (pos < publicKey.Length)
            {
                int count = publicKey.Length - pos < 64 ? publicKey.Length - pos : 64;

                res.Add(publicKey.Substring(pos, count));

                pos += count;
            }

            res.Add("-----END PUBLIC KEY-----");

            string resStr = string.Join("\r\n", res);

            return resStr;
        }

        /// <summary>
        /// Remove Header and Footer from RSA Public Key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string PublicKeyFormatRemove(string publicKey)
        {
            if (!publicKey.StartsWith("-----BEGIN PUBLIC KEY-----"))
            {
                return publicKey;
            }

            return publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\r\n", "");
        }
    }
}
