## BWRSAUtilities

.NET Foundation RSA algorithm supporting data encryption, decryption, signature and verification. It supports xml, pkcs1, pkcs8 and pem formats. It also supports key conversion between pkcs1, pkcs8 and xml formats.

[![Latest version](https://img.shields.io/nuget/v/BWRSAUtilities.svg?style=flat-square)](https://www.nuget.org/packages/BWRSAUtilities/)

# Install

````shell
Install-Package BWRSAUtilities
````

# Documentation

### Generate the key

>Use class `RsaKeyGenerator`. The result returned is a list of two-element strings, Element 1 is the private key and element 2 is the public key.

Format: XML

```csharp
List<string> keyList = RsaKeyGenerator.XmlKey(2048);
string privateKey = keyList[0];
string publicKey = keyList[1];
```

Format: Pkcs1

```csharp
List<string> keyList = RsaKeyGenerator.Pkcs1Key(2048);
string privateKey = keyList[0];
string publicKey = keyList[1];
```

Format: Pkcs8

```csharp
List<string> keyList = RsaKeyGenerator.Pkcs8Key(2048);
string privateKey = keyList[0];
string publicKey = keyList[1];
```

### RSA key conversion

>Use class `RsaKeyConvert`. It  supports key conversion for xml, pkcs1 and pkcs8.

##### XML->Pkcs1:

- Private Key : `RsaKeyConvert.PrivateKeyXmlToPkcs1()`
- Public Key  : `RsaKeyConvert.PublicKeyXmlToPem()`

##### XML->Pkcs8:

- Private Key : `RsaKeyConvert.PrivateKeyXmlToPkcs8()`
- Public Key  : `RsaKeyConvert.PublicKeyXmlToPem()`

##### Pkcs1->XML:

- Private Key : `RsaKeyConvert.PrivateKeyPkcs1ToXml()`
- Public Key  : `RsaKeyConvert.PublicKeyPemToXml()`

##### Pkcs1->Pkcs8:

- Private Key : `RsaKeyConvert.PrivateKeyPkcs1ToPkcs8()`
- Public Key  : No conversion required

##### Pkcs8->XML:

- Private Key : `RsaKeyConvert.PrivateKeyPkcs8ToXml()`
- Public Key  : `RsaKeyConvert.PublicKeyPemToXml()`

##### Pkcs8->Pkcs1:

- Private Key : `RsaKeyConvert.PrivateKeyPkcs8ToPkcs1()`
- Public Key  : No conversion required

### Encrypt, decrypt, sign, and verify signatures

>XML, Pkcs1, Pkcs8 respectively corresponding categories: `RsaXmlUtil`, `RsaPkcs1Util`, `RsaPkcs8Util`. They inherit from the abstract class `RSAUtilBase`

- Encrypt: `RSAUtilBase.Encrypt()`
- Decrypt: `RSAUtilBase.Decrypt()`
- Sign: `RSAUtilBase.SignData()`
- Verify: `RSAUtilBase.VerifyData()`

### PEM formatting

>Use class `RsaPemFormatHelper`.

- Format Pkcs1 format private key: `RsaPemFormatHelper.Pkcs1PrivateKeyFormat()`

- Remove the Pkcs1 format private key format: `RsaPemFormatHelper.Pkcs1PrivateKeyFormatRemove()`

- Format Pkcs8 format private key: `RsaPemFormatHelper.Pkcs8PrivateKeyFormat()`

- Remove the Pkcs8 format private key format: `RsaPemFormatHelper.Pkcs8PrivateKeyFormatRemove()`
