using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace cert
{
    /// <summary>
    ///     Program to test certificate generation.
    /// </summary>
    public class Program
    {
        public static void Main(string[] args)
        {
            var outputDir = AppDomain.CurrentDomain.BaseDirectory + Path.DirectorySeparatorChar + "certificates";

            // Generate Root CA and export it to a PFX file
            var rootCert = CertificateFactory.GenerateRootCaPfx(outputDir, "RootCertCA", "Root certificate", "test", 4096, DateTime.UtcNow.AddYears(40), 
                new[] { "localhost", Environment.MachineName});

            // Load Root CA from the PFX file
            var loadedRootCert = new X509Certificate2(outputDir + Path.DirectorySeparatorChar  + "RootCertCA.pfx", "test");

            // Use Root CA to generate a new certificate for server TLS use cases and export the new certificate to a PFX file
            var newCert = CertificateFactory.GenerateCertificatePfx(outputDir, loadedRootCert, "SubCert", "Sub certificate", "test2", 4096, 
                DateTime.UtcNow.AddYears(1), new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A }, 
                new[] { "localhost", Environment.MachineName }, null, new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, 
                new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment, true));

            // Create a self signed certificate which we don't use below
            var selfSignedCert = CertificateFactory.GenerateCertificatePfx(null, null, "SelfSignedCert", "Self signed certificate", "test3", 4096,
                DateTime.UtcNow.AddYears(2), new byte[] { 0x12, 0x43, 0xCC, 0x54, 0x11, 0x87, 0x32, 0xFF, 0xBA, 0xEF },
                new[] { "localhost", Environment.MachineName }, null, new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },
                new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment, true));

            // Load the new certificate (issued by the Root CA) from the PFX file
            var loadedNewCert = new X509Certificate2(outputDir + Path.DirectorySeparatorChar + "SubCert.pfx", "test2");

            // Message to encrypt
            var plainText = "this is a secret test string";
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            // Sign the message
            var signedData = loadedNewCert.GetRSAPrivateKey().SignData(plainTextBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

            // Encrypt the string (bytes)
            var encryptedBytes = loadedNewCert.GetRSAPublicKey().Encrypt(plainTextBytes, RSAEncryptionPadding.Pkcs1);

            // Decrypt the encrypted string (bytes)
            var decryptedBytes = loadedNewCert.GetRSAPrivateKey().Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
            var decryptedPlainText = Encoding.UTF8.GetString(decryptedBytes);

            Console.WriteLine(">>> THE SECRET STRING (PLAIN TEXT):\n" + plainText);
            Console.WriteLine();
            Console.WriteLine(">>> THE SECRET STRING (ENCRYPTED):\n" + Encoding.UTF8.GetString(encryptedBytes));
            Console.WriteLine();
            Console.WriteLine(">>> THE SECRET STRING (DECRYPTED):\n" + decryptedPlainText);
            Console.WriteLine();
            Console.WriteLine(">>> SIGNATURE VERIFICATION OF DATA:\n" + loadedNewCert.GetRSAPublicKey().VerifyData(plainTextBytes, signedData, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));

            Console.ReadKey();
        }
    }
}
