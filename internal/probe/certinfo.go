package probe

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"strings"
)

// CertInfo contains expanded certificate metadata for JSON output.
type CertInfo struct {
	PEM               string         `json:"pem"`
	Fingerprint       string         `json:"fingerprint"`
	Subject           CertName       `json:"subject"`
	Issuer            CertName       `json:"issuer"`
	Validity          CertValidity   `json:"validity"`
	SANs              CertSANs       `json:"sans"`
	AuthorityKeyID    string         `json:"authority_key_id,omitempty"`
	SubjectKeyID      string         `json:"subject_key_id,omitempty"`
	IsCA              bool           `json:"is_ca"`
	IssuerFingerprint string         `json:"issuer_fingerprint,omitempty"`
	SerialNumber      string         `json:"serial_number,omitempty"`
	SignatureAlgo     string         `json:"signature_algorithm,omitempty"`
	PublicKeyAlgo     string         `json:"public_key_algorithm,omitempty"`
	KeyUsage          []string       `json:"key_usage,omitempty"`
	ExtKeyUsage       []string       `json:"ext_key_usage,omitempty"`
	Source            CertSource     `json:"source,omitempty"`
	TrustStatus       *CertTrustInfo `json:"trust_status,omitempty"`
}

// CertName represents a certificate subject or issuer name.
type CertName struct {
	CommonName         string   `json:"common_name,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	SerialNumber       string   `json:"serial_number,omitempty"`
}

// CertValidity contains the certificate validity period.
type CertValidity struct {
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

// CertSANs contains the certificate Subject Alternative Names.
type CertSANs struct {
	DNS   []string `json:"dns,omitempty"`
	IP    []string `json:"ip,omitempty"`
	URI   []string `json:"uri,omitempty"`
	Email []string `json:"email,omitempty"`
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
)

// CertTrustInfo contains information about certificate trust status.
type CertTrustInfo struct {
	TrustedBy        []string `json:"trusted_by,omitempty"`
	MITMSuspected    bool     `json:"mitm_suspected,omitempty"`
	MITMReason       string   `json:"mitm_reason,omitempty"`
	MatchesReference bool     `json:"matches_reference,omitempty"`
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
