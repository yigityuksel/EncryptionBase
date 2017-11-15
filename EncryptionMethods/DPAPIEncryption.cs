using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Encryption
{
    public class DPAPIEncryption : EncryptorBase
    {

        private string optionalEntropy = null;
        private DataProtectionScope scope = DataProtectionScope.LocalMachine;

        public DPAPIEncryption()
        {

        }

        public DPAPIEncryption(string _optionalEntropy, DataProtectionScope _scope)
        {
            optionalEntropy = _optionalEntropy;
            scope = _scope;
        }

        public override string Decrypt(string encryptedData)
        {

            if (encryptedData == null) throw new ArgumentNullException("encryptedText");

            byte[] encryptedBytes = Convert.FromBase64String(encryptedData);
            byte[] entropyBytes = string.IsNullOrEmpty(optionalEntropy)
                ? null
                : Encoding.UTF8.GetBytes(optionalEntropy);
            byte[] clearBytes = ProtectedData.Unprotect(encryptedBytes, entropyBytes, scope);

            return Encoding.UTF8.GetString(clearBytes);

        }

        public override string Encrypt(string data)
        {

            if (data == null) throw new ArgumentNullException("clearText");

            byte[] clearBytes = Encoding.UTF8.GetBytes(data);
            byte[] entropyBytes = string.IsNullOrEmpty(optionalEntropy)
                ? null
                : Encoding.UTF8.GetBytes(optionalEntropy);
            byte[] encryptedBytes = ProtectedData.Protect(clearBytes, entropyBytes, scope);

            return Convert.ToBase64String(encryptedBytes);

        }

    }
}
