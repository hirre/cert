using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace cert
{
    /// <summary>
    ///     Factory for creating certificates.
    /// </summary>
    public static class CertificateFactory
    {
        /// <summary>
        ///     Generate a root CA certificate and store it as a PFX file.
        /// </summary>
        /// <param name="outputDir">Output directory (if null or empty, then the certificate isn't stored as a PFX file)</param>
        /// <param name="certificateName">Certificate name</param>
        /// <param name="friendlyName">Friendly certificate name</param>
        /// <param name="password">PFX password</param>
        /// <param name="keySize">Key size (e.g. 4096)</param>
        /// <param name="expirationDate">Expiration date</param>
        /// <param name="dnsNames">List of DNS names</param>
        /// <param name="ipAddresses">List of IP addresses</param>
        public static X509Certificate2 GenerateRootCaPfx(string outputDir, string certificateName, string friendlyName, string password, 
            int keySize, DateTime expirationDate, 
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

            var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(expirationDate));            
            certificate.FriendlyName = friendlyName;            

            var newCert = new X509Certificate2(certificate.Export(X509ContentType.Pfx, password), password, 
                            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            if (!string.IsNullOrEmpty(outputDir))
            {
                var certBytes = newCert.Export(X509ContentType.Pfx, password);

                if (!Directory.Exists($"{outputDir}"))
                {
                    Directory.CreateDirectory($"{outputDir}");
                }

                var fileName = $"{outputDir}{Path.DirectorySeparatorChar}{certificateName}.pfx";

                if (!File.Exists(fileName))
                    File.WriteAllBytes(fileName, certBytes);
            }

            return newCert;
        }

        /// <summary>
        ///     Generate a certificate based on a issuer and store it as a PFX file.
        /// </summary>
        /// <param name="outputDir">Output directory (if null or empty, then the certificate isn't stored as a PFX file)</param>
        /// <param name="issuerCertificate">Issuer certificate (when set to null creates a self signed)</param>
        /// <param name="certificateName">Certificate name</param>
        /// <param name="friendlyName">Friendly certificate name</param>
        /// <param name="password">PFX password</param>
        /// <param name="keySize">Key size (e.g. 4096)</param>
        /// <param name="expirationDate">Expiration date</param>
        /// <param name="serialNumber">Serial number</param>
        /// <param name="dnsNames">List of DNS names</param>
        /// <param name="ipAddresses">List of IP addresses</param>
        /// <param name="oids">List of Oids</param>
        /// <param name="usages">Key usages</param>
        public static X509Certificate2 GenerateCertificatePfx(string outputDir, X509Certificate2 issuerCertificate, string certificateName, string friendlyName, 
            string password, int keySize, DateTime expirationDate, byte[] serialNumber, string[] dnsNames, 
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

            X509Certificate2 certificate;

            if (issuerCertificate != null)
                certificate = request.Create(issuerCertificate, new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), expirationDate, serialNumber);
            else
                certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), expirationDate);

            certificate.FriendlyName = friendlyName;

            X509Certificate2 certWithKey = certificate;

            if (!certWithKey.HasPrivateKey)
            {
                certWithKey = certificate.CopyWithPrivateKey(rsa);
                certWithKey.FriendlyName = friendlyName;
            }

            var newCert = new X509Certificate2(certWithKey.Export(X509ContentType.Pfx, password), password, 
                            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            if (!string.IsNullOrEmpty(outputDir))
            {
                var certBytes = newCert.Export(X509ContentType.Pfx, password);

                if (!Directory.Exists($"{outputDir}"))
                {
                    Directory.CreateDirectory($"{outputDir}");
                }

                var fileName = $"{outputDir}{Path.DirectorySeparatorChar}{certificateName}.pfx";

                if (!File.Exists(fileName))
                    File.WriteAllBytes(fileName, certBytes);
            }

            return newCert;
        }
    }
}
