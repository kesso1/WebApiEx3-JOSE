using Jose;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace WebApiEx3_JOSE
{
    class Program
    {
        private static string clientCert = @"C:\temp\ottiCA\ClientCert.pfx";
        static void Main(string[] args)
        {
            createSigningToken();
            createEncryptionToken();
        }

        public static void createEncryptionToken()
        {
            var payload = new Dictionary<string, object>()
            {
                { "sub", "othmar.kesseli@outlook.com" },
                { "exp", 1300819380 }
            };

            var publicKey = new X509Certificate2(clientCert, "1234%%abcd").PublicKey.Key as RSACryptoServiceProvider;
            string token = JWT.Encode(payload, publicKey, JweAlgorithm.RSA_OAEP, JweEncryption.A256GCM);

            var privateKey = new X509Certificate2(clientCert, "1234%%abcd", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PrivateKey as RSACryptoServiceProvider;
            string json = JWT.Decode(token, privateKey);
            Console.WriteLine(json);
        }

        public static void createSigningToken()
        {
            var payload = new Dictionary<string, object>()
            {
                { "sub", "othmar.kesseli@outlook.com" },
                { "exp", 1300819380 }
            };

            var privateKey = new X509Certificate2(clientCert, "1234%%abcd", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PrivateKey as RSACryptoServiceProvider;
            var publicKey = new X509Certificate2(clientCert, "1234%%abcd", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PublicKey.Key;
            privateKey = FixCSP(privateKey);

            string token = JWT.Encode(payload, privateKey, JwsAlgorithm.RS512);

            string json = JWT.Decode(token, publicKey);
            Console.WriteLine(json);
        }

        public static RSACryptoServiceProvider FixCSP(RSACryptoServiceProvider key)
        {
            var privKey = key;

            RSACryptoServiceProvider newKey = new RSACryptoServiceProvider();
            newKey.ImportParameters(privKey.ExportParameters(true));

            return newKey;
        }
    }
}
