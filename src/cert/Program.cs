using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace cert
{
    class Program
    {
        static void Main(string[] args)
        {
            var outputDir = AppDomain.CurrentDomain.BaseDirectory + Path.DirectorySeparatorChar + "keys";

            // Generate Root CA and export to a PFX file
            CertificateFactory.GenerateSelfSignedRootCaPfx(outputDir, "RootCert", "test", new Oid("1.1.1.1.1"), DateTime.UtcNow.AddYears(7000), 
                new[] { "localhost", Environment.MachineName});

            // Load Root CA from the PFX file
            var rootCert = new X509Certificate2(outputDir + Path.DirectorySeparatorChar  + "RootCert.pfx", "test");

            // Use Root CA to generate a new certificate and export to a PFX file
            CertificateFactory.GenerateSelfSignedCertificatePfx(outputDir, rootCert, "SubCert", "test2", new Oid("1.1.1.1.2"),
                DateTime.UtcNow.AddYears(1), new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A }, 
                new[] { "localhost", Environment.MachineName });

            // Load new certificate from the PFX file
            var newCert = new X509Certificate2(outputDir + Path.DirectorySeparatorChar + "SubCert.pfx", "test2");
        }
    }
}
