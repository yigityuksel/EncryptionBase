using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Encryption
{
    public class AESEncryption : EncryptorBase
    {

        private string EncryptionKey = "74794ECB-BE5F-4886-88CD-C40A79ABC0AC";
        private byte[] Salt = { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 };

        public AESEncryption()
        {

        }

        public AESEncryption(string _EncryptionKey, byte[] _Salt)
        {
            EncryptionKey = _EncryptionKey;
            Salt = _Salt;
        }

        public override string Decrypt(string encryptedData)
        {
            encryptedData = encryptedData.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(encryptedData);

            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, Salt);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    encryptedData = Encoding.Unicode.GetString(ms.ToArray());
                }
            }

            return encryptedData;

        }

        public override string Encrypt(string data)
        {

            byte[] clearBytes = Encoding.Unicode.GetBytes(data);

            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, Salt);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    data = Convert.ToBase64String(ms.ToArray());
                }
            }

            return data;

        }

    }

}
