package report

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersion identifies the canonical envelope format this package accepts.
const SchemaVersion = "tlscheck.v1"

// Envelope wraps a Report plus associated certificate metadata.
// This structure is designed to be dependency-free and stable for ingestion by collectors.
type Envelope struct {
	SchemaVersion string  `json:"schema_version"`
	Report        *Report `json:"report"`
	Certs         []*Cert `json:"certs,omitempty"`
}

// Report captures a single execution of tlscheck against a target.
type Report struct {
	ID               string                 `json:"id,omitempty"`
	Timestamp        time.Time              `json:"timestamp"`
	Target           string                 `json:"target"`
	CertFingerprints []string               `json:"cert_fingerprints,omitempty"`
	Results          map[string]interface{} `json:"results,omitempty"`
}

// Cert holds detailed certificate information that the collector may want to index separately.
type Cert struct {
	Fingerprint string                 `json:"fingerprint"`
	PEM         string                 `json:"pem"`
	Subject     string                 `json:"subject,omitempty"`
	Issuer      string                 `json:"issuer,omitempty"`
	NotBefore   time.Time              `json:"not_before"`
	NotAfter    time.Time              `json:"not_after"`
	SANs        []string               `json:"sans,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

// EnsureTimestamp normalizes the report timestamp to UTC and ensures it is not zero.
// If the timestamp is zero, it sets it to the current time.
func EnsureTimestamp(r *Report) {
	if r == nil {
		return
	}
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	} else {
		r.Timestamp = r.Timestamp.UTC()
	}
}

// ValidateEnvelope checks that the envelope has the expected schema version and required fields.
func ValidateEnvelope(env *Envelope) error {
	if env == nil {
		return fmt.Errorf("envelope is nil")
	}
	if env.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema version %q, expected %q", env.SchemaVersion, SchemaVersion)
	}
	if env.Report == nil {
		return fmt.Errorf("envelope missing report")
	}
	if env.Report.Target == "" {
		return fmt.Errorf("report missing target")
	}
	return nil
}

// MarshalEnvelope serializes an Envelope to JSON.
func MarshalEnvelope(env *Envelope) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("envelope is nil")
	}
	return json.Marshal(env)
}

// UnmarshalEnvelope deserializes JSON data into an Envelope.
func UnmarshalEnvelope(data []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("failed to unmarshal envelope: %w", err)
	}
	return &env, nil
}

// GenerateID creates a random hex ID suitable for use as a report ID.
func GenerateID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random ID: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
