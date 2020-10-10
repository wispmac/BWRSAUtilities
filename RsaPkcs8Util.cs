using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography;
using System.Text;

namespace BWRSAUtilities
{
    /// <summary>
    /// RSA PKCS8 Format key helper class, derived from RSAUtilBase class
    /// Author: Wispmac Shah
    /// CreateDate: September 26, 2020
    /// </summary>
    public class RsaPkcs8Util : RSAUtilBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="dataEncoding">Data Encoding</param>
        /// <param name="publicKey">Public key</param>
        /// <param name="privateKey">Private Key</param>
        /// <param name="keySize">Key size</param>
        public RsaPkcs8Util(Encoding dataEncoding, string publicKey, string privateKey = null, int keySize = 2048)
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

                    RSAParameters pubRsap = new RSAParameters
                    {
                        Modulus = priRsap.Modulus,

                        Exponent = priRsap.Exponent
                    };

                    PublicRsa.ImportParameters(pubRsap);
                }
            }

            if (!string.IsNullOrEmpty(publicKey))
            {
                PublicRsa = RSA.Create();

                PublicRsa.KeySize = keySize;

                RSAParameters pubRsap = CreateRsapFromPublicKey(publicKey);

                PublicRsa.ImportParameters(pubRsap);
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
            publicKey = RsaPemFormatHelper.PublicKeyFormatRemove(publicKey);

            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));

            RSAParameters rsap = new RSAParameters();

            rsap.Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();

            rsap.Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();

            return rsap;
        }

        /// <summary>
        /// Create an RSA parameter based on the XML Format private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns>RSAParameters</returns>
        protected sealed override RSAParameters CreateRsapFromPrivateKey(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs8PrivateKeyFormatRemove(privateKey);

            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

            RSAParameters rsap=new RSAParameters();

            rsap.Modulus = privateKeyParam.Modulus.ToByteArrayUnsigned();

            rsap.Exponent = privateKeyParam.PublicExponent.ToByteArrayUnsigned();

            rsap.P = privateKeyParam.P.ToByteArrayUnsigned();

            rsap.Q = privateKeyParam.Q.ToByteArrayUnsigned();

            rsap.DP = privateKeyParam.DP.ToByteArrayUnsigned();

            rsap.DQ = privateKeyParam.DQ.ToByteArrayUnsigned();

            rsap.InverseQ = privateKeyParam.QInv.ToByteArrayUnsigned();

            rsap.D = privateKeyParam.Exponent.ToByteArrayUnsigned();

            return rsap;
        }
    }
}
