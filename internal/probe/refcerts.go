package probe

// ReferenceCAs contains well-known root CA certificates for comparison.
// When encountered certificates have subjects matching these reference CAs but
// different fingerprints/key IDs, this may indicate an MITM proxy.

// TeleportCAEndpoints documents the Teleport CA endpoints for x509+PEM formatted CAs.
// These endpoints are available on Teleport clusters (v18.x and later may have all types).
var TeleportCAEndpoints = []TeleportCAEndpoint{
	{
		Type:        "tls-host",
		Path:        "/webapi/auth/export?type=tls-host",
		Description: "Host CA - Used for TLS connections to Teleport services",
		Required:    true,
	},
	{
		Type:        "tls-user",
		Path:        "/webapi/auth/export?type=tls-user",
		Description: "User CA - Used for user certificate authentication",
		Required:    false,
	},
	{
		Type:        "tls-spiffe",
		Path:        "/webapi/auth/export?type=tls-spiffe",
		Description: "SPIFFE CA - Used for SPIFFE workload identity",
		Required:    false,
	},
	{
		Type:        "db",
		Path:        "/webapi/auth/export?type=db",
		Description: "Database CA - Used for database access",
		Required:    false,
	},
	{
		Type:        "db-client",
		Path:        "/webapi/auth/export?type=db-client",
		Description: "Database Client CA - Used for database client authentication",
		Required:    false,
	},
	{
		Type:        "awsra",
		Path:        "/webapi/auth/export?type=awsra",
		Description: "AWS Roles Anywhere CA - Used for AWS IAM Roles Anywhere",
		Required:    false,
	},
}

// TeleportCAEndpoint describes a Teleport CA export endpoint.
type TeleportCAEndpoint struct {
	Type        string `json:"type"`
	Path        string `json:"path"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// ReferenceCA represents a well-known CA for comparison purposes.
// Uses pre-computed values instead of embedding the full certificate to avoid
// certificate parsing issues.
type ReferenceCA struct {
	Name        string
	Fingerprint string
	SubjectCN   string
}

// GetReferenceCAs returns the list of reference CAs for MITM detection.
// These are well-known root CAs that, if impersonated, may indicate an MITM proxy.
func GetReferenceCAs() []ReferenceCA {
	// Pre-computed fingerprints for well-known CAs
	// Fingerprints are SHA-256 of the DER-encoded certificate
	return []ReferenceCA{
		{
			Name:        "Let's Encrypt ISRG Root X1",
			Fingerprint: "96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6",
			SubjectCN:   "ISRG Root X1",
		},
		{
			Name:        "Let's Encrypt ISRG Root X2",
			Fingerprint: "69729B8E15A86EFC177A57AFB7171DFC64ADD28C2FCA8CF1507E34453CCB1470",
			SubjectCN:   "ISRG Root X2",
		},
		{
			Name:        "DigiCert Global Root CA",
			Fingerprint: "4348A0E9444C78CB265E058D5E8944B4D84F9662BD26DB257F8934A443C70161",
			SubjectCN:   "DigiCert Global Root CA",
		},
		{
			Name:        "DigiCert Global Root G2",
			Fingerprint: "CB3CCBB76031E5E0138F8DD39A23F9DE47FFC35E43C1144CEA27D46A5AB1CB5F",
			SubjectCN:   "DigiCert Global Root G2",
		},
	}
}

// CheckMITMSuspicion checks if a certificate might be from an MITM proxy
// by comparing its issuer against known reference CAs.
func CheckMITMSuspicion(cert *CertInfo, referenceCAs []ReferenceCA) *CertTrustInfo {
	if cert == nil {
		return nil
	}

	trustInfo := &CertTrustInfo{}

	for _, ref := range referenceCAs {
		// Check if the issuer CN matches a known CA
		if cert.Issuer.CommonName == ref.SubjectCN {
			// If the issuer matches but the fingerprint doesn't, it's suspicious
			if cert.IssuerFingerprint != "" && cert.IssuerFingerprint != ref.Fingerprint {
				trustInfo.MITMSuspected = true
				trustInfo.MITMReason = "Issuer CN matches " + ref.Name + " but fingerprint differs"
			} else if cert.IssuerFingerprint == ref.Fingerprint {
				trustInfo.MatchesReference = true
				trustInfo.TrustedBy = append(trustInfo.TrustedBy, ref.Name)
			}
		}
	}

	if !trustInfo.MITMSuspected && len(trustInfo.TrustedBy) == 0 {
		return nil
	}

	return trustInfo
}
