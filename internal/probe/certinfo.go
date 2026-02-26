package probe

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"strconv"
	"strings"
)

// CertExtensionInfo represents a parsed x509 certificate extension.
type CertExtensionInfo struct {
	OID      string `json:"oid" jsonschema:"description=OID of the certificate extension in dotted-decimal notation"`
	Name     string `json:"name,omitempty" jsonschema:"description=Human-readable name of the extension (set for well-known Teleport OIDs)"`
	Critical bool   `json:"critical,omitempty" jsonschema:"description=Whether the extension is marked critical"`
	Value    string `json:"value" jsonschema:"description=Decoded UTF-8 string value of the extension when possible; otherwise hex-encoded bytes"`
}

// teleportOIDNames maps known Teleport x509 extension OIDs to human-readable names.
// OIDs sourced from https://github.com/gravitational/teleport/blob/v18.6.8/lib/tlsca/ca.go
var teleportOIDNames = map[string]string{
	"1.3.9999.1.1":  "KubeUsers",
	"1.3.9999.1.2":  "KubeGroups",
	"1.3.9999.1.3":  "KubeCluster",
	"1.3.9999.1.4":  "AppSessionID",
	"1.3.9999.1.5":  "AppClusterName",
	"1.3.9999.1.6":  "AppPublicAddr",
	"1.3.9999.1.7":  "TeleportCluster",
	"1.3.9999.1.8":  "MFAVerified",
	"1.3.9999.1.9":  "LoginIP",
	"1.3.9999.1.10": "AppName",
	"1.3.9999.1.11": "AppAWSRoleARN",
	"1.3.9999.1.12": "AWSRoleARNs",
	"1.3.9999.1.13": "RenewableCertificate",
	"1.3.9999.1.14": "Generation",
	"1.3.9999.1.15": "PrivateKeyPolicy",
	"1.3.9999.1.16": "AppAzureIdentity",
	"1.3.9999.1.17": "AzureIdentity",
	"1.3.9999.1.18": "AppGCPServiceAccount",
	"1.3.9999.1.19": "GCPServiceAccounts",
	"1.3.9999.1.20": "UserType",
	"1.3.9999.1.21": "AppTargetPort",
	"1.3.9999.1.22": "AppAWSCredentialProcessCredentials",
	"1.3.9999.2.1":  "DatabaseServiceName",
	"1.3.9999.2.2":  "DatabaseProtocol",
	"1.3.9999.2.3":  "DatabaseUsername",
	"1.3.9999.2.4":  "DatabaseName",
	"1.3.9999.2.5":  "DatabaseNames",
	"1.3.9999.2.6":  "DatabaseUsers",
	"1.3.9999.2.7":  "Impersonator",
	"1.3.9999.2.8":  "ActiveRequests",
	"1.3.9999.2.9":  "DisallowReissue",
	"1.3.9999.2.10": "AllowedResources",
	"1.3.9999.2.11": "SystemRoles",
	"1.3.9999.2.12": "PreviousIdentityExpires",
	"1.3.9999.2.13": "ConnectionDiagnosticID",
	"1.3.9999.2.14": "License",
	"1.3.9999.2.15": "PinnedIP",
	"1.3.9999.2.16": "CreateWindowsUser",
	"1.3.9999.2.17": "DesktopsLimitExceeded",
	"1.3.9999.2.18": "Bot",
	"1.3.9999.2.19": "RequestedDatabaseRoles",
	"1.3.9999.2.20": "BotInstance",
	"1.3.9999.2.21": "JoinAttributes",
	"1.3.9999.2.22": "ADStatus",
	"1.3.9999.2.23": "JoinToken",
	"1.3.9999.2.24": "ScopePin",
	"1.3.9999.2.25": "AgentScope",
	"1.3.9999.2.27": "ImmutableLabelHash",
	"1.3.9999.3.1":  "DeviceID",
	"1.3.9999.3.2":  "DeviceAssetTag",
	"1.3.9999.3.3":  "DeviceCredentialID",
}

// oidToString converts an ASN.1 OID to its dotted-decimal string representation.
func oidToString(oid asn1.ObjectIdentifier) string {
	parts := make([]string, len(oid))
	for i, v := range oid {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ".")
}

// decodeExtensionValue attempts to decode an ASN.1-encoded extension value in
// the following order: single UTF-8 string → sequence of UTF-8 strings (joined
// with ", ") → hex fallback.
func decodeExtensionValue(raw []byte) string {
	// Try single UTF-8 string
	var s string
	if rest, err := asn1.Unmarshal(raw, &s); err == nil && len(rest) == 0 {
		return s
	}
	// Try a sequence of UTF-8 strings
	var strs []string
	if rest, err := asn1.Unmarshal(raw, &strs); err == nil && len(rest) == 0 && len(strs) > 0 {
		return strings.Join(strs, ", ")
	}
	// Fall back to hex
	return strings.ToUpper(hex.EncodeToString(raw))
}

// CertInfo contains expanded certificate metadata for JSON output.
type CertInfo struct {
	PEM               string              `json:"pem" jsonschema:"description=Certificate in PEM-encoded format"`
	Fingerprint       string              `json:"fingerprint" jsonschema:"description=SHA-256 fingerprint of the certificate (uppercase hex)"`
	Subject           CertName            `json:"subject" jsonschema:"description=Subject distinguished name from the certificate"`
	Issuer            CertName            `json:"issuer" jsonschema:"description=Issuer distinguished name from the certificate"`
	Validity          CertValidity        `json:"validity" jsonschema:"description=Certificate validity period (notBefore and notAfter timestamps)"`
	SANs              CertSANs            `json:"sans" jsonschema:"description=Subject Alternative Names from the certificate"`
	AuthorityKeyID    string              `json:"authority_key_id,omitempty" jsonschema:"description=Authority Key Identifier extension (colon-separated hex bytes)"`
	SubjectKeyID      string              `json:"subject_key_id,omitempty" jsonschema:"description=Subject Key Identifier extension (colon-separated hex bytes)"`
	IsCA              bool                `json:"is_ca" jsonschema:"description=Whether this certificate is a Certificate Authority"`
	IssuerFingerprint string              `json:"issuer_fingerprint,omitempty" jsonschema:"description=SHA-256 fingerprint of the issuer's certificate if present in the chain"`
	SerialNumber      string              `json:"serial_number,omitempty" jsonschema:"description=Certificate serial number as a decimal string"`
	SignatureAlgo     string              `json:"signature_algorithm,omitempty" jsonschema:"description=Signature algorithm used (e.g. SHA256-RSA, ECDSA-SHA256)"`
	PublicKeyAlgo     string              `json:"public_key_algorithm,omitempty" jsonschema:"description=Public key algorithm (e.g. RSA, ECDSA)"`
	KeyUsage          []string            `json:"key_usage,omitempty" jsonschema:"description=Key usage extensions (e.g. DigitalSignature, KeyEncipherment)"`
	ExtKeyUsage       []string            `json:"ext_key_usage,omitempty" jsonschema:"description=Extended key usage extensions (e.g. ServerAuth, ClientAuth)"`
	Extensions        []CertExtensionInfo `json:"extensions,omitempty" jsonschema:"description=Custom certificate extensions with OID, optional Teleport name, and decoded value"`
	Source            CertSource          `json:"source,omitempty" jsonschema:"description=How this certificate was obtained (server, client, or reference)"`
	TrustStatus       *CertTrustInfo      `json:"trust_status,omitempty" jsonschema:"description=Trust and MITM detection information for this certificate"`
}

// CertName represents a certificate subject or issuer name.
type CertName struct {
	CommonName         string   `json:"common_name,omitempty" jsonschema:"description=Common Name (CN) from the distinguished name"`
	Organization       []string `json:"organization,omitempty" jsonschema:"description=Organization (O) values from the distinguished name"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty" jsonschema:"description=Organizational Unit (OU) values from the distinguished name"`
	Country            []string `json:"country,omitempty" jsonschema:"description=Country (C) values from the distinguished name"`
	Province           []string `json:"province,omitempty" jsonschema:"description=Province/State (ST) values from the distinguished name"`
	Locality           []string `json:"locality,omitempty" jsonschema:"description=Locality/City (L) values from the distinguished name"`
	SerialNumber       string   `json:"serial_number,omitempty" jsonschema:"description=Serial number from the distinguished name (distinct from certificate serial number)"`
}

// CertValidity contains the certificate validity period.
type CertValidity struct {
	NotBefore string `json:"not_before" jsonschema:"description=Timestamp when the certificate becomes valid (ISO 8601 format)"`
	NotAfter  string `json:"not_after" jsonschema:"description=Timestamp when the certificate expires (ISO 8601 format)"`
}

// CertSANs contains the certificate Subject Alternative Names.
type CertSANs struct {
	DNS   []string `json:"dns,omitempty" jsonschema:"description=DNS names from the Subject Alternative Name extension"`
	IP    []string `json:"ip,omitempty" jsonschema:"description=IP addresses from the Subject Alternative Name extension"`
	URI   []string `json:"uri,omitempty" jsonschema:"description=URIs from the Subject Alternative Name extension"`
	Email []string `json:"email,omitempty" jsonschema:"description=Email addresses from the Subject Alternative Name extension"`
}

// CertSource indicates how the certificate was obtained.
type CertSource string

const (
	// CertSourceServer indicates a server certificate from TLS handshake.
	CertSourceServer CertSource = "server"
	// CertSourceClient indicates a client certificate for mutual TLS.
	CertSourceClient CertSource = "client"
	// CertSourceReference indicates a reference certificate (e.g., Let's Encrypt).
	CertSourceReference CertSource = "reference"
	// CertSourceHostCA indicates a CA certificate fetched from the Teleport /webapi/auth/export endpoint.
	CertSourceHostCA CertSource = "host_ca"
)

// CertTrustInfo contains information about certificate trust status.
type CertTrustInfo struct {
	TrustedBy        []string `json:"trusted_by,omitempty" jsonschema:"description=List of known certificate authorities that could have issued this certificate"`
	MITMSuspected    bool     `json:"mitm_suspected,omitempty" jsonschema:"description=Whether this certificate might be from a man-in-the-middle proxy"`
	MITMReason       string   `json:"mitm_reason,omitempty" jsonschema:"description=Explanation of why MITM is suspected"`
	MatchesReference bool     `json:"matches_reference,omitempty" jsonschema:"description=Whether this certificate matches a known reference certificate"`
}

// ParseCertInfo extracts detailed certificate information from a parsed x509 certificate.
func ParseCertInfo(cert *x509.Certificate, pemData string) *CertInfo {
	info := &CertInfo{
		PEM:         pemData,
		Fingerprint: computeFingerprint(cert),
		Subject:     parseCertName(cert.Subject),
		Issuer:      parseCertName(cert.Issuer),
		Validity: CertValidity{
			NotBefore: cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
			NotAfter:  cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		},
		SANs:           parseSANs(cert),
		AuthorityKeyID: formatKeyID(cert.AuthorityKeyId),
		SubjectKeyID:   formatKeyID(cert.SubjectKeyId),
		IsCA:           cert.IsCA,
		SerialNumber:   cert.SerialNumber.String(),
		SignatureAlgo:  cert.SignatureAlgorithm.String(),
		PublicKeyAlgo:  cert.PublicKeyAlgorithm.String(),
		KeyUsage:       parseKeyUsage(cert.KeyUsage),
		ExtKeyUsage:    parseExtKeyUsage(cert.ExtKeyUsage),
		Extensions:     parseExtensions(cert.Extensions),
	}

	return info
}

func computeFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func parseCertName(name pkix.Name) CertName {
	return CertName{
		CommonName:         name.CommonName,
		Organization:       copySlice(name.Organization),
		OrganizationalUnit: copySlice(name.OrganizationalUnit),
		Country:            copySlice(name.Country),
		Province:           copySlice(name.Province),
		Locality:           copySlice(name.Locality),
		SerialNumber:       name.SerialNumber,
	}
}

func parseSANs(cert *x509.Certificate) CertSANs {
	sans := CertSANs{}

	if len(cert.DNSNames) > 0 {
		sans.DNS = copySlice(cert.DNSNames)
	}

	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		sans.IP = ips
	}

	if len(cert.URIs) > 0 {
		uris := make([]string, len(cert.URIs))
		for i, uri := range cert.URIs {
			uris[i] = uri.String()
		}
		sans.URI = uris
	}

	if len(cert.EmailAddresses) > 0 {
		sans.Email = copySlice(cert.EmailAddresses)
	}

	return sans
}

func formatKeyID(keyID []byte) string {
	if len(keyID) == 0 {
		return ""
	}
	// Format as colon-separated hex bytes (e.g., "12:AB:34:...")
	parts := make([]string, len(keyID))
	for i, b := range keyID {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(parts, ":")
}

func parseKeyUsage(usage x509.KeyUsage) []string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}
	return usages
}

func parseExtKeyUsage(extUsage []x509.ExtKeyUsage) []string {
	var usages []string
	for _, u := range extUsage {
		switch u {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSPSigning")
		}
	}
	return usages
}

// parseExtensions parses the raw x509 extensions, skipping standard extensions
// that are already captured as typed fields, and decoding Teleport-specific ones by name.
func parseExtensions(exts []pkix.Extension) []CertExtensionInfo {
	// Standard extension OIDs handled by the x509 package (skip them to avoid duplication).
	standardOIDs := map[string]bool{
		"2.5.29.14":         true, // SubjectKeyIdentifier
		"2.5.29.15":         true, // KeyUsage
		"2.5.29.17":         true, // SubjectAltName
		"2.5.29.19":         true, // BasicConstraints
		"2.5.29.31":         true, // CRLDistributionPoints
		"2.5.29.32":         true, // CertificatePolicies
		"2.5.29.35":         true, // AuthorityKeyIdentifier
		"2.5.29.37":         true, // ExtKeyUsage
		"1.3.6.1.5.5.7.1.1": true, // AuthorityInformationAccess
	}

	var result []CertExtensionInfo
	for _, ext := range exts {
		oidStr := oidToString(ext.Id)
		if standardOIDs[oidStr] {
			continue
		}
		info := CertExtensionInfo{
			OID:      oidStr,
			Critical: ext.Critical,
			Value:    decodeExtensionValue(ext.Value),
		}
		if name, ok := teleportOIDNames[oidStr]; ok {
			info.Name = name
		}
		result = append(result, info)
	}
	return result
}

func copySlice(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	out := make([]string, len(input))
	copy(out, input)
	return out
}

// ParseCertFromPEM parses a PEM-encoded certificate and returns CertInfo.
func ParseCertFromPEM(pemData []byte) (*CertInfo, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return ParseCertInfo(cert, string(pemData)), nil
}

// SetIssuerFingerprint sets the issuer fingerprint on a CertInfo.
func (c *CertInfo) SetIssuerFingerprint(fingerprint string) {
	c.IssuerFingerprint = fingerprint
}

// SetSource sets the source on a CertInfo.
func (c *CertInfo) SetSource(source CertSource) {
	c.Source = source
}

// ParseCertBundleFromPEM parses all PEM-encoded certificates from a bundle and returns
// a map of fingerprint -> CertInfo. Each certificate is tagged with the given source.
// Invalid PEM blocks and certificates that cannot be parsed are silently skipped.
// Returns an empty (non-nil) map if no valid certificates are found.
func ParseCertBundleFromPEM(pemData []byte, source CertSource) map[string]*CertInfo {
	result := make(map[string]*CertInfo)
	rest := pemData
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		pemStr := string(pem.EncodeToMemory(block))
		info := ParseCertInfo(cert, pemStr)
		info.SetSource(source)
		result[info.Fingerprint] = info
	}
	return result
}
