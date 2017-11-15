using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption
{
    public class EncryptionProvider<T> where T : EncryptorBase
    {

        public static T Get(EncryptionType type)
        {

            switch (type)
            {
                case EncryptionType.RSA:
                    return (T)(object)new RSAEncryption();
                case EncryptionType.AES:
                    return (T)(object)new AESEncryption();
                case EncryptionType.DPAPI:
                    return (T)(object)new DPAPIEncryption();
                default:
                    throw new NotSupportedException();
            }

        }

    }

    public enum EncryptionType
    {
        RSA,
        AES,
        DPAPI
    }

}
