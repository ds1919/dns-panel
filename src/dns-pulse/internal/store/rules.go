// Rule loading for the handler. Decisions are made by internal/rules as a pure function; this file only
// supplies its inputs, so no rule logic ends up spread across SQL.
package store

import (
	"context"
	"database/sql"
	"time"

	"dnspanel/dns-pulse/internal/rules"
)

// Applied is a rule together with what is currently published: decisions are compared against the
// current state, never applied blindly.
type Applied struct {
	rules.Rule
	Enabled      bool
	State        string // default | switched | held
	ActiveBranch uint32 // 0 = no branch holds the set
	Label        string // "name type" for the log; an id means nothing to a human
}

func (d *DB) LoadRule(ctx context.Context, id uint32) (*Applied, error) {
	var a Applied
	var tz string
	var hold uint32
	var active sql.NullInt64
	var name, rtype string
	err := d.sql.QueryRowContext(ctx, `
		SELECT schedule_tz, default_hold_seconds, enabled, state, active_branch_id, rr_name, rr_type
		  FROM pulse_rules WHERE id = ?`, id).
		Scan(&tz, &hold, &a.Enabled, &a.State, &active, &name, &rtype)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.ID = id
	a.DefaultHold = time.Duration(hold) * time.Second
	a.ActiveBranch = uint32(active.Int64)
	a.Label = name + " " + rtype
	// An unknown time zone falls back to UTC rather than failing: the rule is already saved, and silently
	// ignoring it is worse than evaluating it in UTC.
	if loc, err := time.LoadLocation(tz); err == nil {
		a.TZ = loc
	} else {
		a.TZ = time.UTC
	}

	rows, err := d.sql.QueryContext(ctx, `
		SELECT id, match_mode, hold_seconds FROM pulse_branches WHERE rule_id = ? ORDER BY position, id`, id)
	if err != nil {
		return nil, err
	}
	byID := map[uint32]int{}
	for rows.Next() {
		var b rules.Branch
		var mode string
		var hs uint32
		if err := rows.Scan(&b.ID, &mode, &hs); err != nil {
			rows.Close()
			return nil, err
		}
		b.MatchAll = mode == "all"
		b.Hold = time.Duration(hs) * time.Second
		byID[b.ID] = len(a.Branches)
		a.Branches = append(a.Branches, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Condition testers are a separate table (one check may be asked of many agents); load them in one
	// query for the whole rule.
	trows, err := d.sql.QueryContext(ctx, `
		SELECT ct.condition_id, ct.tester_id
		  FROM pulse_condition_testers ct
		  JOIN pulse_conditions c ON c.id = ct.condition_id
		  JOIN pulse_branches b   ON b.id = c.branch_id
		 WHERE b.rule_id = ? ORDER BY ct.tester_id`, id)
	if err != nil {
		return nil, err
	}
	byCond := map[uint32][]uint32{}
	for trows.Next() {
		var cid, tid uint32
		if err := trows.Scan(&cid, &tid); err != nil {
			trows.Close()
			return nil, err
		}
		byCond[cid] = append(byCond[cid], tid)
	}
	trows.Close()
	if err := trows.Err(); err != nil {
		return nil, err
	}

	crows, err := d.sql.QueryContext(ctx, `
		SELECT c.id, c.branch_id, c.kind, COALESCE(c.check_id,0), COALESCE(c.expect,''), c.agg, c.agg_n,
		       c.days_mask, c.time_from, c.time_to, c.date_from, c.date_to
		  FROM pulse_conditions c JOIN pulse_branches b ON b.id = c.branch_id
		 WHERE b.rule_id = ? ORDER BY c.position, c.id`, id)
	if err != nil {
		return nil, err
	}
	defer crows.Close()
	for crows.Next() {
		var cid, bid uint32
		var kind, agg string
		var checkID uint32
		var aggN uint32
		var c rules.Cond
		var mask sql.NullInt64
		var tf, tt sql.NullString
		var df, dt sql.NullTime
		if err := crows.Scan(&cid, &bid, &kind, &checkID, &c.Expect, &agg, &aggN,
			&mask, &tf, &tt, &df, &dt); err != nil {
			return nil, err
		}
		c.Schedule = kind == "schedule"
		switch agg {
		case "all":
			c.Agg = rules.AggAll
		case "at_least":
			c.Agg = rules.AggAtLeast
		}
		c.AggN = int(aggN)
		for _, tid := range byCond[cid] {
			c.Pairs = append(c.Pairs, rules.Pair{CheckID: checkID, TesterID: tid})
		}
		if mask.Valid {
			c.DaysMask = uint8(mask.Int64)
		}
		// TIME columns come back as "09:00:00"; the decision compares "15:04".
		if tf.Valid && len(tf.String) >= 5 {
			c.TimeFrom = tf.String[:5]
		}
		if tt.Valid && len(tt.String) >= 5 {
			c.TimeTo = tt.String[:5]
		}
		if df.Valid {
			c.DateFrom = df.Time.Format("2006-01-02")
		}
		if dt.Valid {
			c.DateTo = dt.Time.Format("2006-01-02")
		}
		if i, ok := byID[bid]; ok {
			a.Branches[i].Conds = append(a.Branches[i].Conds, c)
		}
	}
	return &a, crows.Err()
}

// RuleStates returns the states of the pairs a rule references. Pairs with no result row are omitted:
// "nobody to ask" is unknown and must not be reported as healthy.
func (d *DB) RuleStates(ctx context.Context, id uint32) (map[rules.Pair]string, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT DISTINCT c.check_id, ct.tester_id, COALESCE(r.state,'')
		  FROM pulse_conditions c
		  JOIN pulse_branches b ON b.id = c.branch_id
		  JOIN pulse_condition_testers ct ON ct.condition_id = c.id
		  LEFT JOIN pulse_results r ON r.check_id = c.check_id AND r.tester_id = ct.tester_id
		 WHERE b.rule_id = ? AND c.kind = 'check' AND c.check_id IS NOT NULL`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[rules.Pair]string{}
	for rows.Next() {
		var p rules.Pair
		var st string
		if err := rows.Scan(&p.CheckID, &p.TesterID, &st); err != nil {
			return nil, err
		}
		if st != "" {
			out[p] = st
		}
	}
	return out, rows.Err()
}

// RulesForPair returns the ENABLED rules that depend on this pair; recomputation is event-driven.
func (d *DB) RulesForPair(ctx context.Context, checkID, testerID uint32) ([]uint32, error) {
	return d.ruleIDs(ctx, `
		SELECT DISTINCT b.rule_id FROM pulse_conditions c
		  JOIN pulse_branches b ON b.id = c.branch_id
		  JOIN pulse_rules r    ON r.id = b.rule_id
		  JOIN pulse_condition_testers ct ON ct.condition_id = c.id
		 WHERE c.check_id = ? AND ct.tester_id = ? AND r.enabled = 1`, checkID, testerID)
}

// RulesForTester returns rules that ask this tester about ANY check, for when the agent itself goes
// silent and all its pairs lose data at once.
func (d *DB) RulesForTester(ctx context.Context, testerID uint32) ([]uint32, error) {
	return d.ruleIDs(ctx, `
		SELECT DISTINCT b.rule_id FROM pulse_conditions c
		  JOIN pulse_branches b ON b.id = c.branch_id
		  JOIN pulse_rules r    ON r.id = b.rule_id
		  JOIN pulse_condition_testers ct ON ct.condition_id = c.id
		 WHERE ct.tester_id = ? AND r.enabled = 1`, testerID)
}

// EnabledRules returns all enabled rules; used on cold start and on node promotion.
func (d *DB) EnabledRules(ctx context.Context) ([]uint32, error) {
	return d.ruleIDs(ctx, `SELECT id FROM pulse_rules WHERE enabled = 1`)
}

func (d *DB) ruleIDs(ctx context.Context, q string, args ...any) ([]uint32, error) {
	rows, err := d.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uint32
	for rows.Next() {
		var id uint32
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
