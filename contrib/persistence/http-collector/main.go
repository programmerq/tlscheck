// Package main provides a simple HTTP server for collecting tlscheck envelopes.
//
// The collector accepts POST /upload requests containing Envelope JSON (schema version tlscheck.v1).
// It validates the envelope and persists it either to MongoDB (if -mongo-uri is set) or to disk.
//
// Usage:
//
//	# Disk-based mode (writes JSON files to ./data)
//	http-collector -listen 127.0.0.1:8080 -data-dir ./data
//
//	# MongoDB mode
//	http-collector -listen 0.0.0.0:8080 -mongo-uri mongodb://localhost:27017 -mongo-db tlscheck
//
// The MongoDB store creates:
//   - reports collection with an index on timestamp
//   - certs collection with a unique index on fingerprint
//
// Certs are upserted atomically to track first_seen, last_seen, and seen_count.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/programmerq/tlscheck/contrib/persistence/mongo"
	"github.com/programmerq/tlscheck/pkg/report"
)

var (
	listen   = flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	dataDir  = flag.String("data-dir", "./data", "Directory to store JSON files (used when mongo-uri is not set)")
	mongoURI = flag.String("mongo-uri", "", "MongoDB connection URI (optional; if not set, files are written to disk)")
	mongoDB  = flag.String("mongo-db", "tlscheck", "MongoDB database name")
)

func main() {
	flag.Parse()

	var store *mongo.MongoStore
	var err error

	// If mongo-uri is provided, connect to MongoDB
	if *mongoURI != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		store, err = mongo.NewMongoStore(ctx, *mongoURI, *mongoDB)
		if err != nil {
			log.Fatalf("Failed to connect to MongoDB: %v", err)
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := store.Close(ctx); err != nil {
				log.Printf("Error closing MongoDB connection: %v", err)
			}
		}()
		log.Printf("Connected to MongoDB at %s (database: %s)", *mongoURI, *mongoDB)
	} else {
		// Ensure data directory exists
		if err := os.MkdirAll(*dataDir, 0755); err != nil {
			log.Fatalf("Failed to create data directory: %v", err)
		}
		log.Printf("Using disk-based storage in directory: %s", *dataDir)
	}

	handler := &collectorHandler{
		mongoStore: store,
		dataDir:    *dataDir,
	}

	http.HandleFunc("/upload", handler.handleUpload)
	http.HandleFunc("/health", handleHealth)

	log.Printf("HTTP collector listening on %s", *listen)
	if err := http.ListenAndServe(*listen, nil); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

type collectorHandler struct {
	mongoStore *mongo.MongoStore
	dataDir    string
}

// handleUpload accepts POST requests with Envelope JSON and persists them.
// If mongoStore is configured, it saves to MongoDB; otherwise it writes to disk.
func (h *collectorHandler) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Unmarshal and validate the envelope
	envelope, err := report.UnmarshalEnvelope(body)
	if err != nil {
		log.Printf("Error unmarshaling envelope: %v", err)
		http.Error(w, fmt.Sprintf("Invalid envelope: %v", err), http.StatusBadRequest)
		return
	}

	if err := report.ValidateEnvelope(envelope); err != nil {
		log.Printf("Envelope validation failed: %v", err)
		http.Error(w, fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
		return
	}

	// Ensure timestamp is normalized
	report.EnsureTimestamp(envelope.Report)

	// Persist to MongoDB or disk
	if h.mongoStore != nil {
		if err := h.persistToMongo(r.Context(), envelope, body); err != nil {
			log.Printf("Error persisting to MongoDB: %v", err)
			http.Error(w, "Failed to persist data", http.StatusInternalServerError)
			return
		}
	} else {
		if err := h.persistToDisk(envelope, body); err != nil {
			log.Printf("Error persisting to disk: %v", err)
			http.Error(w, "Failed to persist data", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "accepted",
		"id":     envelope.Report.ID,
	})
}

// persistToMongo saves the envelope to MongoDB using the MongoStore.
func (h *collectorHandler) persistToMongo(ctx context.Context, envelope *report.Envelope, rawJSON []byte) error {
	// Save the report
	if err := h.mongoStore.SaveReport(ctx, envelope.Report, rawJSON); err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	// Upsert each certificate
	for _, cert := range envelope.Certs {
		if err := h.mongoStore.UpsertCert(ctx, cert); err != nil {
			log.Printf("Warning: failed to upsert cert %s: %v", cert.Fingerprint, err)
		}
	}

	log.Printf("Persisted report %s (target: %s) to MongoDB", envelope.Report.ID, envelope.Report.Target)
	return nil
}

// persistToDisk writes the raw JSON to a file in the data directory.
// The filename is based on the report timestamp and ID.
func (h *collectorHandler) persistToDisk(envelope *report.Envelope, rawJSON []byte) error {
	// Generate an ID if not present
	if envelope.Report.ID == "" {
		id, err := report.GenerateID()
		if err != nil {
			return fmt.Errorf("failed to generate ID: %w", err)
		}
		envelope.Report.ID = id
	}

	// Create filename using timestamp and ID
	timestamp := envelope.Report.Timestamp.Format("20060102-150405")
	filename := fmt.Sprintf("%s-%s.json", timestamp, envelope.Report.ID)
	filepath := filepath.Join(h.dataDir, filename)

	// Write the file
	if err := os.WriteFile(filepath, rawJSON, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	log.Printf("Persisted report %s (target: %s) to file: %s", envelope.Report.ID, envelope.Report.Target, filename)
	return nil
}

// handleHealth provides a simple health check endpoint.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
	})
}
