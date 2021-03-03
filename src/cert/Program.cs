using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace cert
{
    class Program
    {
        static void Main(string[] args)
        {
            var outputDir = AppDomain.CurrentDomain.BaseDirectory + Path.DirectorySeparatorChar + "keys";

            // Generate Root CA and export it to a PFX file
            CertificateFactory.GenerateSelfSignedRootCaPfx(outputDir, "RootCertCA", "test", 4096, DateTime.UtcNow.AddYears(40), 
                new[] { "localhost", Environment.MachineName});

            // Load Root CA from the PFX file
            var rootCert = new X509Certificate2(outputDir + Path.DirectorySeparatorChar  + "RootCertCA.pfx", "test");

            // Use Root CA to generate a new certificate and export it to a PFX file
            CertificateFactory.GenerateSelfSignedCertificatePfx(outputDir, rootCert, "SubCert", "test2", 4096, 
                DateTime.UtcNow.AddYears(1), new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A }, 
                new[] { "localhost", Environment.MachineName });

            // Load the new certificate from the PFX file
            var newCert = new X509Certificate2(outputDir + Path.DirectorySeparatorChar + "SubCert.pfx", "test2");

            var plainText = "this is a secret test string";
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            // Encrypt the string (bytes)
            var encryptedBytes = newCert.GetRSAPublicKey().Encrypt(plainTextBytes, RSAEncryptionPadding.Pkcs1);

            // Decrypt the encrypted string (bytes)
            var decryptedBytes = newCert.GetRSAPrivateKey().Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
            var decryptedPlainText = Encoding.UTF8.GetString(decryptedBytes);

            Console.WriteLine(">>> THE SECRET STRING (PLAIN TEXT):\n" + plainText);
            Console.WriteLine();
            Console.WriteLine(">>> THE SECRET STRING (ENCRYPTED):\n" + Encoding.UTF8.GetString(encryptedBytes));
            Console.WriteLine();
            Console.WriteLine(">>> THE SECRET STRING (DECRYPTED):\n" + decryptedPlainText);

            Console.ReadKey();
        }
    }
}
