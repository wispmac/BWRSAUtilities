using System;
using System.Security.Cryptography;
using System.Text;

namespace BWRSAUtilities
{
    /// <summary>
    /// RSA Utilities Base Abstract Class
    /// Author: Wispmac Shah
    /// CreateDate: September 26, 2020
    /// </summary>
    public abstract class RSAUtilBase
    {
        public RSA PrivateRsa;
        public RSA PublicRsa;
        public Encoding DataEncoding;

        /// <summary>
        /// RSA Public Key Encryption
        /// </summary>
        /// <param name="data">Data to be encrypted</param>
        /// <param name="padding">Padding Algorithm</param>
        /// <returns></returns>
        public string Encrypt(string data, RSAEncryptionPadding padding)
        {
            if (PublicRsa == null)
            {
                throw new ArgumentException("public key can not null");
            }

            byte[] dataBytes = DataEncoding.GetBytes(data);

            byte[] resBytes = PublicRsa.Encrypt(dataBytes, padding);

            return Convert.ToBase64String(resBytes);
        }

        /// <summary>
        /// RSA Private Key Decryption
        /// </summary>
        /// <param name="data">Encrypted String</param>
        /// <param name="padding">Padding Algorithm</param>
        /// <returns></returns>
        public string Decrypt(string data, RSAEncryptionPadding padding)
        {
            if (PrivateRsa == null)
            {
                throw new ArgumentException("private key can not null");
            }

            byte[] dataBytes = Convert.FromBase64String(data);

            byte[] resBytes = PrivateRsa.Decrypt(dataBytes, padding);

            return DataEncoding.GetString(resBytes);
        }

        /// <summary>
        /// Use Private Key for Data Signing
        /// </summary>
        /// <param name="data">Data to be Signed/Encrypted</param>
        /// <param name="hashAlgorithmName">Hashing Algorithm</param>
        /// <param name="padding">Padding Algorithm</param>
        /// <returns>Signed Data as String</returns>
        public string SignData(string data, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            byte[] res = SignDataGetBytes(data, hashAlgorithmName, padding);

            return Convert.ToBase64String(res);
        }

        /// <summary>
        /// Use Private Key for Data Signing
        /// </summary>
        /// <param name="data">Data to be Signed/Encrypted</param>
        /// <param name="hashAlgorithmName">Hashing Algorithm</param>
        /// <param name="padding">Padding Algorithm</param>
        /// <returns>Signed Data as Bytes Array</returns>
        public byte[] SignDataGetBytes(string data, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            if (PrivateRsa == null)
            {
                throw new ArgumentException("private key can not null");
            }

            byte[] dataBytes = DataEncoding.GetBytes(data);

            return PrivateRsa.SignData(dataBytes, hashAlgorithmName, padding);
        }

        /// <summary>
        /// Verify Signed Data using Public Key
        /// </summary>
        /// <param name="data">Data to be verified</param>
        /// <param name="sign">Signature</param>
        /// <param name="hashAlgorithmName">Hashing Algorithm</param>
        /// <param name="padding">Padding Algorithm</param>
        /// <returns></returns>
        public bool VerifyData(string data, string sign, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            if (PublicRsa == null)
            {
                throw new ArgumentException("public key can not null");
            }

            byte[] dataBytes = DataEncoding.GetBytes(data);
            byte[] signBytes = Convert.FromBase64String(sign);
            bool res = PublicRsa.VerifyData(dataBytes, signBytes, hashAlgorithmName, padding);

            return res;
        }

        protected abstract RSAParameters CreateRsapFromPrivateKey(string privateKey);

        protected abstract RSAParameters CreateRsapFromPublicKey(string publicKey);
    }
}
