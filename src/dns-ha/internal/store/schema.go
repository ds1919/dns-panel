package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
)

// SchemaSQL is the final local database schema, embedded in the binary.
//
// Embedded on purpose: the manager deploys the pair itself (`-bootstrap`) instead of an operator copying a
// file to the node, and schema and code cannot drift apart because they ship in one build.
//
//go:embed dns_ha.sql
var SchemaSQL string

// ApplySchema deploys the schema into the given database. Idempotent: every CREATE is IF NOT EXISTS.
//
// Everything runs on ONE connection: `USE` applies per connection and the pool hands them out arbitrarily,
// so without pinning some statements would silently create tables in another database.
func ApplySchema(ctx context.Context, db *sql.DB, dbName string) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "USE "+dbName); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	for _, q := range SchemaStatements() {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("schema: %w (%s)", err, firstLine(q))
		}
	}
	return nil
}

// SchemaStatements returns the individual schema statements. Comments are stripped BEFORE splitting: the
// file header contains example commands, and a naive split on ";" would turn them into executable pieces.
func SchemaStatements() []string {
	var body strings.Builder
	for _, line := range strings.Split(SchemaSQL, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		body.WriteString(line)
		body.WriteString("\n")
	}
	var out []string
	for _, stmt := range strings.Split(body.String(), ";") {
		if q := strings.TrimSpace(stmt); q != "" {
			out = append(out, q)
		}
	}
	return out
}

func firstLine(q string) string {
	if i := strings.IndexByte(q, '\n'); i > 0 {
		return q[:i]
	}
	return q
}
