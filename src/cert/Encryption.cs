using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace cert
{
    public static class Encryption
    {
        public static byte[] Encrypt(byte[] plainBytes, X509Certificate2 cert)
        {
            RSA publicKey = cert.GetRSAPublicKey();
            return publicKey.Encrypt(plainBytes, RSAEncryptionPadding.Pkcs1);
        }

        public static byte[] Decrypt(byte[] encryptedBytes, X509Certificate2 cert)
        {
            RSA privateKey = cert.GetRSAPrivateKey();
            return privateKey.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
        }
    }
}
