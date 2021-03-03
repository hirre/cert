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

            // Generate Root CA and export to a PFX file
            CertificateFactory.GenerateSelfSignedRootCaPfx(outputDir, "RootCertCA", "test", 4096, DateTime.UtcNow.AddYears(40), 
                new[] { "localhost", Environment.MachineName});

            // Load Root CA from the PFX file
            var rootCert = new X509Certificate2(outputDir + Path.DirectorySeparatorChar  + "RootCertCA.pfx", "test");

            // Use Root CA to generate a new certificate and export to a PFX file
            CertificateFactory.GenerateSelfSignedCertificatePfx(outputDir, rootCert, "SubCert", "test2", 4096, 
                DateTime.UtcNow.AddYears(1), new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A }, 
                new[] { "localhost", Environment.MachineName });

            // Load new certificate from the PFX file
            var newCert = new X509Certificate2(outputDir + Path.DirectorySeparatorChar + "SubCert.pfx", "test2", X509KeyStorageFlags.PersistKeySet);

            var plainText = "this is a secret string %¤#%/&%(%£$€@$£2";

            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            var encryptedBytes = Encryption.Encrypt(plainTextBytes, newCert);

            var decryptedBytes = Encryption.Decrypt(encryptedBytes, newCert);

            var decryptedPlainText = Encoding.UTF8.GetString(decryptedBytes);

            Console.WriteLine("THE SECRET STRING: " + decryptedPlainText);

            Console.ReadKey();
        }
    }
}
