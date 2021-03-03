using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace cert
{
    public static class CertificateFactory
    {
        public static void GenerateSelfSignedRootCaPfx(string outputDir, string certificateName, string password, Oid oid, DateTime expirationDate, 
            string[] dnsNames, IPAddress[] ipAddresses = null)
        {
            SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
            
            if (ipAddresses != null && ipAddresses.Length != 0)
            {
                foreach (var ip in ipAddresses)
                {
                    sanBuilder.AddIpAddress(ip);
                }
            }

            foreach (var dns in dnsNames)
            {
                sanBuilder.AddDnsName(dns);
            }          

            X500DistinguishedName distinguishedName = new X500DistinguishedName($"CN={certificateName}");

            using RSA rsa = RSA.Create(4096);

            var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { oid }, true));

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.CrlSign |
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.KeyEncipherment |
                X509KeyUsageFlags.KeyAgreement | X509KeyUsageFlags.NonRepudiation, true));
            request.CertificateExtensions.Add(sanBuilder.Build());

            var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow), new DateTimeOffset(expirationDate));
            certificate.FriendlyName = certificateName;

            var newCert = new X509Certificate2(certificate.Export(X509ContentType.Pfx, password), password, X509KeyStorageFlags.Exportable);
            var certBytes = newCert.Export(X509ContentType.Pfx, password);

            if (!Directory.Exists($"{outputDir}"))
            {
                Directory.CreateDirectory($"{outputDir}");
            }

            var fileName = $"{outputDir}{Path.DirectorySeparatorChar}{certificateName}.pfx";

            if (!File.Exists(fileName))
                File.WriteAllBytes(fileName, certBytes);
        }

        public static void GenerateSelfSignedCertificatePfx(string outputDir, X509Certificate2 issuerCertificate, string certificateName, string password, Oid oid, 
            DateTime expirationDate, byte[] serialNumber, string[] dnsNames, IPAddress[] ipAddresses = null)
        {
            SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();

            if (ipAddresses != null && ipAddresses.Length != 0)
            {
                foreach (var ip in ipAddresses)
                {
                    sanBuilder.AddIpAddress(ip);
                }
            }

            foreach (var dns in dnsNames)
            {
                sanBuilder.AddDnsName(dns);
            }

            X500DistinguishedName distinguishedName = new X500DistinguishedName($"CN={certificateName}");

            using RSA rsa = RSA.Create(4096);

            var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));

            request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { oid }, false));

            request.CertificateExtensions.Add(sanBuilder.Build());

            var certificate = request.Create(issuerCertificate, new DateTimeOffset(DateTime.UtcNow), expirationDate, serialNumber);
            certificate.FriendlyName = certificateName;

            var newCert = new X509Certificate2(certificate.Export(X509ContentType.Pfx, password), password, X509KeyStorageFlags.Exportable);
            var certBytes = newCert.Export(X509ContentType.Pfx, password);

            if (!Directory.Exists($"{outputDir}"))
            {
                Directory.CreateDirectory($"{outputDir}");
            }

            var fileName = $"{outputDir}{Path.DirectorySeparatorChar}{certificateName}.pfx";

            if (!File.Exists(fileName))
                File.WriteAllBytes(fileName, certBytes);
        }
    }
}
