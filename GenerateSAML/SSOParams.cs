using System;

namespace GenerateSAML
{

public class SSOParameters
    {
        public string Issuer { get; set; }
        public string IssuerFormat { get; set; }
        public string Destination { get; set; }
        public string SigniningCertPath { get; set; }
        public string SigniningCertPass { get; set; }
        public string EncryptionCertPath { get; set; }
        public string SignatureUrl { get; set; }
        public string SignatureRsaUrl { get; set; }
        public string Audience { get; set; }
        public string NameID { get; set; }
        public string NameIDFormat { get; set; }

    }

}