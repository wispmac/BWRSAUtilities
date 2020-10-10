using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace BWRSAUtilities
{
    /// <summary>
    /// RSA PKCS1 Format key helper class, derived from RSAUtilBase class
    /// Author: Wispmac Shah
    /// CreateDate: September 26, 2020
    /// </summary>
    public class RsaPkcs1Util : RSAUtilBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="dataEncoding">Data Encoding</param>
        /// <param name="publicKey">Public key</param>
        /// <param name="privateKey">Private Key</param>
        /// <param name="keySize">Key size</param>
        public RsaPkcs1Util(Encoding dataEncoding, string publicKey, string privateKey = null, int keySize = 2048)
        {
            if (string.IsNullOrEmpty(privateKey) && string.IsNullOrEmpty(publicKey))
            {
                throw new Exception("Public and private keys must not be empty at the same time");
            }


            if (!string.IsNullOrEmpty(privateKey))
            {
                PrivateRsa = RSA.Create();

                PrivateRsa.KeySize = keySize;

                RSAParameters priRsap = CreateRsapFromPrivateKey(privateKey);

                PrivateRsa.ImportParameters(priRsap);

                if (string.IsNullOrEmpty(publicKey))
                {
                    PublicRsa = RSA.Create();

                    PublicRsa.KeySize = keySize;

                    RSAParameters pubRasp = new RSAParameters
                    {
                        Modulus = priRsap.Modulus,

                        Exponent = priRsap.Exponent
                    };

                    PublicRsa.ImportParameters(pubRasp);
                }

            }

            if (!string.IsNullOrEmpty(publicKey))
            {
                PublicRsa = RSA.Create();

                PublicRsa.KeySize = keySize;

                PublicRsa.ImportParameters(CreateRsapFromPublicKey(publicKey));
            }

            DataEncoding = dataEncoding ?? Encoding.UTF8;
        }

        /// <summary>
        /// Create an RSA parameter based on XML format public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns>RSAParameters</returns>
        protected sealed override RSAParameters CreateRsapFromPublicKey(string publicKey)
        {
            publicKey = RsaPemFormatHelper.PublicKeyFormat(publicKey);

            PemReader pr = new PemReader(new StringReader(publicKey));

            object obj = pr.ReadObject();

            if (!(obj is RsaKeyParameters rsaKey))
            {
                throw new Exception("Public key format is incorrect");
            }

            RSAParameters rsap = new RSAParameters();

            rsap.Modulus = rsaKey.Modulus.ToByteArrayUnsigned();

            rsap.Exponent = rsaKey.Exponent.ToByteArrayUnsigned();

            return rsap;
        }

        /// <summary>
        /// Create an RSA parameter based on the XML Format private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns>RSAParameters</returns>
        protected sealed override RSAParameters CreateRsapFromPrivateKey(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs1PrivateKeyFormat(privateKey);

            PemReader pr = new PemReader(new StringReader(privateKey));

            if (!(pr.ReadObject() is AsymmetricCipherKeyPair asymmetricCipherKeyPair))
            {
                throw new Exception("Private key format is incorrect");
            }

            RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricCipherKeyPair.Private));

            RSAParameters rsap = new RSAParameters();

            rsap.Modulus = rsaPrivateCrtKeyParameters.Modulus.ToByteArrayUnsigned();

            rsap.Exponent = rsaPrivateCrtKeyParameters.PublicExponent.ToByteArrayUnsigned();

            rsap.P = rsaPrivateCrtKeyParameters.P.ToByteArrayUnsigned();

            rsap.Q = rsaPrivateCrtKeyParameters.Q.ToByteArrayUnsigned();

            rsap.DP = rsaPrivateCrtKeyParameters.DP.ToByteArrayUnsigned();

            rsap.DQ = rsaPrivateCrtKeyParameters.DQ.ToByteArrayUnsigned();

            rsap.InverseQ = rsaPrivateCrtKeyParameters.QInv.ToByteArrayUnsigned();

            rsap.D = rsaPrivateCrtKeyParameters.Exponent.ToByteArrayUnsigned();

            return rsap;
        }
    }
}
