package agentd

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
)

// What the node holds before its data is replaced.
//
// It answers one question — "whose data do we keep" — for a human, who needs to see how many zones, records
// and users they would lose, not just "database not empty". Counts are EXACT (COUNT), not the
// information_schema estimate: InnoDB's is approximate, and "about zero" is a poor basis for wiping a database.
//
// The agent reads this, not the manager: the manager only has access to its own dns_ha, not to `pdns` and
// `dns_panel`, and must not. The command is read-only and bypasses the mutation contract.

// Inventory is the node's data as seen by a human choosing the donor.
type Inventory struct {
	Databases []DatabaseInventory `json:"databases"`
	// Empty means not a SINGLE row in any transferred database. That distinguishes a fresh install that can
	// be rebuilt silently from a node whose data must be wiped deliberately.
	Empty bool `json:"empty"`
}

type DatabaseInventory struct {
	Name string `json:"name"`
	// Present means the database exists. A missing database differs from an empty one: the former is a node
	// where the application was never deployed.
	Present bool             `json:"present"`
	Rows    map[string]int64 `json:"rows,omitempty"` // table → exact row count (non-empty only)
	Error   string           `json:"error,omitempty"`
}

// Inventory lists the transferred databases.
func (n *Node) Inventory() (Inventory, error) {
	db, err := n.db()
	if err != nil {
		return Inventory{}, err
	}
	inv := Inventory{Empty: true}
	for _, name := range n.Cfg.Replication.Databases {
		d := DatabaseInventory{Name: name}
		var found string
		err := db.QueryRowContext(n.ctx(), "SELECT schema_name FROM information_schema.schemata WHERE schema_name = ?", name).Scan(&found)
		if err == sql.ErrNoRows {
			inv.Databases = append(inv.Databases, d)
			continue
		}
		if err != nil {
			d.Error = err.Error()
			inv.Databases = append(inv.Databases, d)
			inv.Empty = false // unknown, so we may not call it empty
			continue
		}
		d.Present = true
		rows, err := countRows(n.ctx(), db, name)
		if err != nil {
			d.Error = err.Error()
			inv.Empty = false
			inv.Databases = append(inv.Databases, d)
			continue
		}
		if len(rows) > 0 {
			d.Rows = rows
			inv.Empty = false
		}
		inv.Databases = append(inv.Databases, d)
	}
	return inv, nil
}

// countRows counts rows in each table and returns only NON-EMPTY ones: forty tables of zeros tell a human
// nothing, "users: 3, domains: 12" tells everything.
func countRows(ctx context.Context, db *sql.DB, dbName string) (map[string]int64, error) {
	rows, err := db.QueryContext(ctx, "SELECT table_name FROM information_schema.tables "+
		"WHERE table_schema = ? AND table_type = 'BASE TABLE'", dbName)
	if err != nil {
		return nil, err
	}
	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return nil, err
		}
		tables = append(tables, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(tables)

	out := map[string]int64{}
	for _, t := range tables {
		var n int64
		// Names come from information_schema but are escaped anyway: one day a table name will contain a backtick.
		if err := db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM `%s`.`%s`", esc(dbName), esc(t))).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			out[t] = n
		}
	}
	return out, nil
}

func esc(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '`' {
			out = append(out, '`')
		}
		out = append(out, r)
	}
	return string(out)
}
