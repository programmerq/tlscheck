# tlscheck Persistence Collectors

This directory contains lightweight persistence implementations for collecting tlscheck envelopes.

## HTTP Collector

A simple HTTP server that accepts tlscheck envelopes via POST requests.

### Usage

**Disk-based storage** (writes JSON files to a directory):
```bash
cd contrib/persistence/http-collector
go run main.go -listen 127.0.0.1:8080 -data-dir ./data
```

**MongoDB storage** (persists to MongoDB with indexes):
```bash
cd contrib/persistence/http-collector
go run main.go -listen 0.0.0.0:8080 \
  -mongo-uri mongodb://localhost:27017 \
  -mongo-db tlscheck
```

### Endpoints

- `POST /upload` - Accept and persist tlscheck envelope (schema version: tlscheck.v1)
- `GET /health` - Health check endpoint

### Example Request

```bash
curl -X POST http://localhost:8080/upload \
  -H "Content-Type: application/json" \
  -d '{
    "schema_version": "tlscheck.v1",
    "report": {
      "timestamp": "2024-12-14T00:00:00Z",
      "target": "example.com:443",
      "cert_fingerprints": ["ABC123"],
      "results": {"status": "success"}
    },
    "certs": [{
      "fingerprint": "ABC123",
      "pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
      "subject": "CN=example.com",
      "issuer": "CN=Example CA",
      "not_before": "2024-01-01T00:00:00Z",
      "not_after": "2025-01-01T00:00:00Z",
      "sans": ["example.com"]
    }]
  }'
```

## MongoDB Store

The `mongo` package provides a lightweight MongoDB-backed persistence layer.

### Collections

- **reports**: Stores report documents with searchable fields (timestamp, target, cert_fingerprints) plus raw envelope JSON
  - Index on `timestamp` for time-based queries
- **certs**: Stores certificate documents with atomic upserts
  - Unique index on `fingerprint`
  - Tracks `first_seen`, `last_seen`, and `seen_count`

### Usage Example

```go
import (
    "context"
    "github.com/programmerq/tlscheck/contrib/persistence/mongo"
    "github.com/programmerq/tlscheck/pkg/report"
)

ctx := context.Background()
store, err := mongo.NewMongoStore(ctx, "mongodb://localhost:27017", "tlscheck")
if err != nil {
    log.Fatal(err)
}
defer store.Close(ctx)

// Save a report
err = store.SaveReport(ctx, myReport, rawJSON)

// Upsert certificates
for _, cert := range certs {
    store.UpsertCert(ctx, cert)
}
```

## pkg/report

The `pkg/report` package defines the canonical data model and is intentionally dependency-free.

See the [package documentation](../../pkg/report/models.go) for details on:
- Envelope, Report, and Cert types
- Schema version ("tlscheck.v1")
- Helper functions for validation and marshaling
