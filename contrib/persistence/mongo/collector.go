package mongo

import (
	"context"
	"fmt"
	"time"

	"github.com/programmerq/tlscheck/pkg/report"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoStore provides a lightweight persistence layer for tlscheck reports and certs.
type MongoStore struct {
	client  *mongo.Client
	db      *mongo.Database
	reports *mongo.Collection
	certs   *mongo.Collection
	dbName  string
}

// NewMongoStore connects to MongoDB and prepares collections with required indexes.
// It creates:
// - A unique index on certs.fingerprint
// - An index on reports.timestamp for efficient time-based queries
func NewMongoStore(ctx context.Context, uri, dbName string) (*MongoStore, error) {
	if uri == "" {
		return nil, fmt.Errorf("mongo URI is required")
	}
	if dbName == "" {
		dbName = "tlscheck"
	}

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	db := client.Database(dbName)
	reportsCol := db.Collection("reports")
	certsCol := db.Collection("certs")

	store := &MongoStore{
		client:  client,
		db:      db,
		reports: reportsCol,
		certs:   certsCol,
		dbName:  dbName,
	}

	// Create indexes
	if err := store.ensureIndexes(ctx); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	return store, nil
}

// ensureIndexes creates the required indexes on reports and certs collections.
func (s *MongoStore) ensureIndexes(ctx context.Context) error {
	// Index on reports.timestamp for time-based queries
	timestampIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "timestamp", Value: 1}},
	}
	if _, err := s.reports.Indexes().CreateOne(ctx, timestampIndex); err != nil {
		return fmt.Errorf("failed to create timestamp index on reports: %w", err)
	}

	// Unique index on certs.fingerprint
	fingerprintIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: "fingerprint", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	if _, err := s.certs.Indexes().CreateOne(ctx, fingerprintIndex); err != nil {
		return fmt.Errorf("failed to create fingerprint index on certs: %w", err)
	}

	return nil
}

// SaveReport inserts a report document into the reports collection.
// The document includes searchable fields (timestamp, target, cert_fingerprints)
// plus the raw envelope JSON for future flexibility.
// If the report ID is empty, one is generated.
func (s *MongoStore) SaveReport(ctx context.Context, r *report.Report, rawJSON []byte) error {
	if r == nil {
		return fmt.Errorf("report is nil")
	}

	// Ensure the report has an ID
	if r.ID == "" {
		id, err := report.GenerateID()
		if err != nil {
			return fmt.Errorf("failed to generate report ID: %w", err)
		}
		r.ID = id
	}

	// Ensure timestamp is normalized
	report.EnsureTimestamp(r)

	doc := bson.M{
		"id":                r.ID,
		"timestamp":         r.Timestamp,
		"target":            r.Target,
		"cert_fingerprints": r.CertFingerprints,
		"raw":               rawJSON,
	}

	if _, err := s.reports.InsertOne(ctx, doc); err != nil {
		return fmt.Errorf("failed to insert report: %w", err)
	}

	return nil
}

// UpsertCert atomically upserts a certificate document in the certs collection.
// It maintains first_seen, last_seen, and seen_count fields to track certificate usage.
// Multiple concurrent reporters can safely update the same certificate.
func (s *MongoStore) UpsertCert(ctx context.Context, cert *report.Cert) error {
	if cert == nil {
		return fmt.Errorf("cert is nil")
	}
	if cert.Fingerprint == "" {
		return fmt.Errorf("cert fingerprint is required")
	}

	now := time.Now().UTC()

	filter := bson.M{"fingerprint": cert.Fingerprint}

	// Use $setOnInsert to set fields only on insert (first_seen)
	// Use $set to always update fields (last_seen, pem, subject, issuer, etc.)
	// Use $inc to increment seen_count
	update := bson.M{
		"$setOnInsert": bson.M{
			"first_seen": now,
		},
		"$set": bson.M{
			"last_seen":  now,
			"pem":        cert.PEM,
			"subject":    cert.Subject,
			"issuer":     cert.Issuer,
			"not_before": cert.NotBefore,
			"not_after":  cert.NotAfter,
			"sans":       cert.SANs,
			"extra":      cert.Extra,
		},
		"$inc": bson.M{
			"seen_count": 1,
		},
	}

	opts := options.Update().SetUpsert(true)
	if _, err := s.certs.UpdateOne(ctx, filter, update, opts); err != nil {
		return fmt.Errorf("failed to upsert cert: %w", err)
	}

	return nil
}

// Close disconnects the MongoDB client.
func (s *MongoStore) Close(ctx context.Context) error {
	if s.client == nil {
		return nil
	}
	return s.client.Disconnect(ctx)
}
