package probe

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseCertInfo(t *testing.T) {
	t.Parallel()

	// Generate a test certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Example Org"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Example CA",
			Organization: []string{"Example PKI"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"test.example.com", "www.example.com"},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	info := ParseCertInfo(cert, pemData)

	// Verify fields
	if info.Subject.CommonName != "test.example.com" {
		t.Errorf("Subject.CommonName = %q, want 'test.example.com'", info.Subject.CommonName)
	}
	if len(info.Subject.Organization) != 1 || info.Subject.Organization[0] != "Example Org" {
		t.Errorf("Subject.Organization = %v, want ['Example Org']", info.Subject.Organization)
	}
	if info.Fingerprint == "" {
		t.Error("Fingerprint is empty")
	}
	if info.PEM != pemData {
		t.Error("PEM data mismatch")
	}
	if len(info.SANs.DNS) != 2 {
		t.Errorf("SANs.DNS = %v, want 2 entries", info.SANs.DNS)
	}
	if info.IsCA {
		t.Error("IsCA should be false")
	}
	if len(info.KeyUsage) == 0 {
		t.Error("KeyUsage should be populated")
	}
	if len(info.ExtKeyUsage) == 0 || info.ExtKeyUsage[0] != "ServerAuth" {
		t.Errorf("ExtKeyUsage = %v, want ['ServerAuth']", info.ExtKeyUsage)
	}
	if info.Validity.NotBefore == "" || info.Validity.NotAfter == "" {
		t.Error("Validity dates should be populated")
	}
	if info.SerialNumber == "" {
		t.Error("SerialNumber should be populated")
	}

	t.Logf("CertInfo parsed successfully:")
	t.Logf("  Fingerprint: %s", info.Fingerprint)
	t.Logf("  Subject CN: %s", info.Subject.CommonName)
	t.Logf("  Issuer CN: %s", info.Issuer.CommonName)
	t.Logf("  SANs DNS: %v", info.SANs.DNS)
	t.Logf("  Validity: %s to %s", info.Validity.NotBefore, info.Validity.NotAfter)
}

func TestGetReferenceCAs(t *testing.T) {
	t.Parallel()

	refs := GetReferenceCAs()
	if len(refs) == 0 {
		t.Fatal("GetReferenceCAs returned empty list")
	}

	// Check for Let's Encrypt ISRG Root X1
	var foundX1, foundX2 bool
	for _, ref := range refs {
		if ref.Name == "Let's Encrypt ISRG Root X1" {
			foundX1 = true
			if ref.SubjectCN != "ISRG Root X1" {
				t.Errorf("ISRG Root X1 SubjectCN = %q, want 'ISRG Root X1'", ref.SubjectCN)
			}
			if ref.Fingerprint == "" {
				t.Error("ISRG Root X1 Fingerprint is empty")
			}
		}
		if ref.Name == "Let's Encrypt ISRG Root X2" {
			foundX2 = true
			if ref.SubjectCN != "ISRG Root X2" {
				t.Errorf("ISRG Root X2 SubjectCN = %q, want 'ISRG Root X2'", ref.SubjectCN)
			}
			if ref.Fingerprint == "" {
				t.Error("ISRG Root X2 Fingerprint is empty")
			}
		}
		t.Logf("Reference CA: %s (CN=%s, FP=%s...)", ref.Name, ref.SubjectCN, ref.Fingerprint[:16])
	}

	if !foundX1 {
		t.Error("Let's Encrypt ISRG Root X1 not found")
	}
	if !foundX2 {
		t.Error("Let's Encrypt ISRG Root X2 not found")
	}
}

func TestTeleportCAEndpoints(t *testing.T) {
	t.Parallel()

	if len(TeleportCAEndpoints) == 0 {
		t.Fatal("TeleportCAEndpoints is empty")
	}

	// Check that tls-host is present and required
	var foundTLSHost bool
	for _, ep := range TeleportCAEndpoints {
		if ep.Type == "tls-host" {
			foundTLSHost = true
			if !ep.Required {
				t.Error("tls-host should be required")
			}
			if ep.Path != "/webapi/auth/export?type=tls-host" {
				t.Errorf("tls-host Path = %q, want '/webapi/auth/export?type=tls-host'", ep.Path)
			}
		}
		t.Logf("Teleport CA Endpoint: %s (%s) - required=%v", ep.Type, ep.Description, ep.Required)
	}

	if !foundTLSHost {
		t.Error("tls-host endpoint not found")
	}
}

func TestCheckMITMSuspicion(t *testing.T) {
	t.Parallel()

	refs := GetReferenceCAs()
	if len(refs) == 0 {
		t.Skip("no reference CAs available")
	}

	// Test cert that matches a reference CA
	matchingCert := &CertInfo{
		Issuer: CertName{
			CommonName: refs[0].SubjectCN,
		},
		IssuerFingerprint: refs[0].Fingerprint,
	}

	trustInfo := CheckMITMSuspicion(matchingCert, refs)
	if trustInfo == nil {
		t.Fatal("expected trust info for matching cert")
	}
	if trustInfo.MITMSuspected {
		t.Error("matching cert should not be MITM suspected")
	}
	if !trustInfo.MatchesReference {
		t.Error("matching cert should have MatchesReference=true")
	}

	// Test cert with same issuer CN but different fingerprint (potential MITM)
	mitmCert := &CertInfo{
		Issuer: CertName{
			CommonName: refs[0].SubjectCN,
		},
		IssuerFingerprint: "DIFFERENT_FINGERPRINT_ABCDEF1234567890",
	}

	trustInfo = CheckMITMSuspicion(mitmCert, refs)
	if trustInfo == nil {
		t.Fatal("expected trust info for MITM cert")
	}
	if !trustInfo.MITMSuspected {
		t.Error("MITM cert should be suspected")
	}
	if trustInfo.MITMReason == "" {
		t.Error("MITM cert should have a reason")
	}
	t.Logf("MITM reason: %s", trustInfo.MITMReason)

	// Test cert with unrelated issuer
	unrelatedCert := &CertInfo{
		Issuer: CertName{
			CommonName: "Some Random CA",
		},
		IssuerFingerprint: "SOME_FINGERPRINT",
	}

	trustInfo = CheckMITMSuspicion(unrelatedCert, refs)
	if trustInfo != nil {
		t.Error("unrelated cert should not have trust info")
	}
}

func TestFormatKeyID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"empty", nil, ""},
		{"single byte", []byte{0xAB}, "AB"},
		{"two bytes", []byte{0x12, 0xCD}, "12:CD"},
		{"multiple bytes", []byte{0x12, 0xAB, 0x34, 0xCD, 0xEF}, "12:AB:34:CD:EF"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatKeyID(tc.input)
			if result != tc.expected {
				t.Errorf("formatKeyID(%v) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestCertSource(t *testing.T) {
	t.Parallel()

	info := &CertInfo{}

	info.SetSource(CertSourceServer)
	if info.Source != CertSourceServer {
		t.Errorf("Source = %q, want 'server'", info.Source)
	}

	info.SetSource(CertSourceClient)
	if info.Source != CertSourceClient {
		t.Errorf("Source = %q, want 'client'", info.Source)
	}

	info.SetSource(CertSourceReference)
	if info.Source != CertSourceReference {
		t.Errorf("Source = %q, want 'reference'", info.Source)
	}
}

func TestOIDToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    asn1.ObjectIdentifier
		expected string
	}{
		{"single", asn1.ObjectIdentifier{1}, "1"},
		{"two parts", asn1.ObjectIdentifier{1, 3}, "1.3"},
		{"teleport cluster", asn1.ObjectIdentifier{1, 3, 9999, 1, 7}, "1.3.9999.1.7"},
		{"zero component", asn1.ObjectIdentifier{0, 0}, "0.0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := oidToString(tc.input)
			if result != tc.expected {
				t.Errorf("oidToString(%v) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestTeleportOIDNames(t *testing.T) {
	t.Parallel()

	// Spot-check a few known Teleport OIDs
	known := map[string]string{
		"1.3.9999.1.7": "TeleportCluster",
		"1.3.9999.1.9": "LoginIP",
		"1.3.9999.2.3": "DatabaseUsername",
		"1.3.9999.3.1": "DeviceID",
	}
	for oid, want := range known {
		got, ok := teleportOIDNames[oid]
		if !ok {
			t.Errorf("OID %s not found in teleportOIDNames", oid)
			continue
		}
		if got != want {
			t.Errorf("teleportOIDNames[%s] = %q, want %q", oid, got, want)
		}
	}
}
