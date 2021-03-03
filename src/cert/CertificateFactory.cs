using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace cert
{
    public static class CertificateFactory
    {
        public static void GenerateSelfSignedRootCaPfx(string outputDir, string certificateName, string password, int keySize, DateTime expirationDate, 
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

            using RSA rsa = RSA.Create(keySize);

            var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);            
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(sanBuilder.Build());

            var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow), new DateTimeOffset(expirationDate));            
            certificate.FriendlyName = certificateName;            

            var newCert = new X509Certificate2(certificate.Export(X509ContentType.Pfx, password), password, 
                            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            var certBytes = newCert.Export(X509ContentType.Pfx, password);            

            if (!Directory.Exists($"{outputDir}"))
            {
                Directory.CreateDirectory($"{outputDir}");
            }

            var fileName = $"{outputDir}{Path.DirectorySeparatorChar}{certificateName}.pfx";

            if (!File.Exists(fileName))
                File.WriteAllBytes(fileName, certBytes);
        }

        public static void GenerateSelfSignedCertificatePfx(string outputDir, X509Certificate2 issuerCertificate, string certificateName, string password, 
            int keySize, DateTime expirationDate, byte[] serialNumber, string[] dnsNames, 
            IPAddress[] ipAddresses = null, OidCollection oids = null, X509KeyUsageExtension usages = null)
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

            using RSA rsa = RSA.Create(keySize);

            var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

            if (usages != null)
                request.CertificateExtensions.Add(usages);

            if (oids != null )
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, true));

            request.CertificateExtensions.Add(sanBuilder.Build());

            var certificate = request.Create(issuerCertificate, new DateTimeOffset(DateTime.UtcNow), expirationDate, serialNumber);
            certificate.FriendlyName = certificateName;

            var certWithKey = certificate.CopyWithPrivateKey(rsa);

            var newCert = new X509Certificate2(certWithKey.Export(X509ContentType.Pfx, password), password, 
                            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
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
