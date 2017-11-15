using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption
{
    public abstract class EncryptorBase
    {

        public abstract string Encrypt(string data);

        public abstract string Decrypt(string encryptedData);

    }

}
