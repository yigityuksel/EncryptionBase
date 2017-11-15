using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Encryption
{
    public class RSAEncryption : EncryptorBase
    {

        private readonly bool _optimalAsymmetricEncryptionPadding = true;

        private int KeySize = 2048;
        private string KeyContainerName = "CE858619-87A6-45FA-927F-D59E105E9F62";

        public RSAEncryption()
        {

        }

        public RSAEncryption(int keySize, string keyContainerName)
        {
            KeySize = keySize;
            KeyContainerName = keyContainerName;
        }

        public string GetPublicKey()
        {

            return GetKeyValue(false);

        }

        public override string Encrypt(string data)
        {
            var encrypted = EncryptByteArray(Encoding.UTF8.GetBytes(data), GetKeyValue(false), KeySize);

            return Convert.ToBase64String(encrypted);
        }

        public override string Decrypt(string encryptedData)
        {

            var decrypted = DecryptByteArray(Convert.FromBase64String(encryptedData), GetKeyValue(true), KeySize);

            return Encoding.UTF8.GetString(decrypted);
        }

        /// <summary>
        /// Gets and validates the RSA-encrypted text as a byte array
        /// </summary>
        /// <param name="data">The plain text in byte array format</param>
        /// <param name="publicKeyXml">The RSA public key in XML format</param>
        /// <param name="keySize">The RSA key length</param>
        /// <returns>The the RSA-encrypted byte array</returns>
        private byte[] EncryptByteArray(byte[] data, string publicKeyXml, int keySize)
        {
            if (data == null || data.Length == 0)
            {
                throw new ArgumentException("Data are empty", "data");
            }

            int maxLength = GetMaxDataLength(keySize);

            if (data.Length > maxLength)
            {
                throw new ArgumentException(String.Format("Maximum data length is {0}", maxLength), "data");
            }

            if (!IsKeySizeValid(keySize))
            {
                throw new ArgumentException("Key size is not valid", "keySize");
            }

            if (String.IsNullOrEmpty(publicKeyXml))
            {
                throw new ArgumentException("Key is null or empty", "publicKeyXml");
            }

            using (var provider = new RSACryptoServiceProvider(keySize))
            {
                provider.FromXmlString(publicKeyXml);
                return provider.Encrypt(data, _optimalAsymmetricEncryptionPadding);
            }
        }

        /// <summary>
        /// Gets and validates the RSA-decrypted text as a byte array
        /// </summary>
        /// <param name="data">The plain text in byte array format</param>
        /// <param name="publicKeyXml">The RSA public key in XML format</param>
        /// <param name="keySize">The RSA key length</param>
        /// <returns>The the RSA-decrypted byte array</returns>
        private byte[] DecryptByteArray(byte[] data, string publicAndPrivateKeyXml, int keySize)
        {
            if (data == null || data.Length == 0)
            {
                throw new ArgumentException("Data are empty", "data");
            }

            if (!IsKeySizeValid(keySize))
            {
                throw new ArgumentException("Key size is not valid", "keySize");
            }

            if (String.IsNullOrEmpty(publicAndPrivateKeyXml))
            {
                throw new ArgumentException("Key is null or empty", "publicAndPrivateKeyXml");
            }

            using (var provider = new RSACryptoServiceProvider(keySize))
            {
                provider.FromXmlString(publicAndPrivateKeyXml);
                return provider.Decrypt(data, _optimalAsymmetricEncryptionPadding);
            }
        }

        /// <summary>
        /// Gets the maximum data length for a given key
        /// </summary>       
        /// <param name="keySize">The RSA key length</param>
        /// <returns>The maximum allowable data length</returns>
        private int GetMaxDataLength(int keySize)
        {
            if (_optimalAsymmetricEncryptionPadding)
            {
                return ((keySize - 384) / 8) + 7;
            }
            return ((keySize - 384) / 8) + 37;
        }

        /// <summary>
        /// Checks if the given key size if valid
        /// </summary>       
        /// <param name="keySize">The RSA key length</param>
        /// <returns>True if valid; false otherwise</returns>
        private bool IsKeySizeValid(int keySize)
        {
            return keySize >= 384 &&
                   keySize <= 16384 &&
                   keySize % 8 == 0;
        }

        private string GetKeyValue(bool isPrivate)
        {

            // Create the CspParameters object and set the key container   
            // name used to store the RSA key pair.  
            CspParameters cp = new CspParameters()
            {
                KeyContainerName = KeyContainerName,
                Flags = CspProviderFlags.UseArchivableKey
            };

            // Create a new instance of RSACryptoServiceProvider that accesses  
            // the key container MyKeyContainerName.  
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KeySize, cp);

            return rsa.ToXmlString(isPrivate);

        }

    }

}
