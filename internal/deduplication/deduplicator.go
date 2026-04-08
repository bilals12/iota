package deduplication

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

var DedupNamespace = uuid.MustParse("a3bb189e-8bf9-3888-9912-ace4e6543002")

type Deduplicator struct {
	db *sql.DB
}

type AlertInfo struct {
	AlertID           string
	RuleID            string
	DedupKey          string
	AlertCreationTime time.Time
	AlertUpdateTime   time.Time
	ResolvedAt        *time.Time
	Title             string
	Severity          string
}

func New(stateFile string) (*Deduplicator, error) {
	db, err := sql.Open("sqlite3", stateFile)
	if err != nil {
		return nil, fmt.Errorf("open dedup db: %w", err)
	}

	if err := initDedupDB(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("init dedup db: %w", err)
	}

	return &Deduplicator{db: db}, nil
}

func initDedupDB(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS alerts (
			alert_id TEXT PRIMARY KEY,
			rule_id TEXT NOT NULL,
			dedup_key TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			resolved_at TIMESTAMP,
			title TEXT,
			severity TEXT
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_unique_open
			ON alerts(rule_id, dedup_key, resolved_at);
		CREATE INDEX IF NOT EXISTS idx_alerts_rule_dedup
			ON alerts(rule_id, dedup_key) WHERE resolved_at IS NULL;
	`)
	return err
}

func (d *Deduplicator) UpdateAlertInfo(ctx context.Context, ruleID, dedup, title, severity string, dedupPeriodMinutes int) (*AlertInfo, error) {
	dedupKey := GenerateDedupKey(ruleID, dedup)
	now := time.Now()
	dedupThreshold := now.Add(-time.Duration(dedupPeriodMinutes) * time.Minute)

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var existing AlertInfo
	err = tx.QueryRowContext(ctx, `
		SELECT alert_id, rule_id, dedup_key, created_at, updated_at, title, severity
		FROM alerts
		WHERE rule_id = ? AND dedup_key = ? AND resolved_at IS NULL
	`, ruleID, dedupKey).Scan(
		&existing.AlertID, &existing.RuleID, &existing.DedupKey,
		&existing.AlertCreationTime, &existing.AlertUpdateTime,
		&existing.Title, &existing.Severity,
	)

	if err == sql.ErrNoRows {
		alertID := GenerateAlertID(ruleID, dedupKey, now)
		_, err = tx.ExecContext(ctx, `
			INSERT INTO alerts (alert_id, rule_id, dedup_key, created_at, updated_at, title, severity)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, alertID, ruleID, dedupKey, now, now, title, severity)
		if err != nil {
			return nil, fmt.Errorf("insert alert: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit: %w", err)
		}

		return &AlertInfo{
			AlertID:           alertID,
			RuleID:            ruleID,
			DedupKey:          dedupKey,
			AlertCreationTime: now,
			AlertUpdateTime:   now,
			Title:             title,
			Severity:          severity,
		}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("query alert: %w", err)
	}

	if existing.AlertCreationTime.Before(dedupThreshold) {
		_, err = tx.ExecContext(ctx, `
			UPDATE alerts SET resolved_at = ? WHERE alert_id = ?
		`, now, existing.AlertID)
		if err != nil {
			return nil, fmt.Errorf("resolve alert: %w", err)
		}

		alertID := GenerateAlertID(ruleID, dedupKey, now)
		_, err = tx.ExecContext(ctx, `
			INSERT INTO alerts (alert_id, rule_id, dedup_key, created_at, updated_at, title, severity)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, alertID, ruleID, dedupKey, now, now, title, severity)
		if err != nil {
			return nil, fmt.Errorf("insert new alert: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit: %w", err)
		}

		return &AlertInfo{
			AlertID:           alertID,
			RuleID:            ruleID,
			DedupKey:          dedupKey,
			AlertCreationTime: now,
			AlertUpdateTime:   now,
			Title:             title,
			Severity:          severity,
		}, nil
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE alerts SET updated_at = ?, title = ?, severity = ? WHERE alert_id = ?
	`, now, title, severity, existing.AlertID)
	if err != nil {
		return nil, fmt.Errorf("update alert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &AlertInfo{
		AlertID:           existing.AlertID,
		RuleID:            ruleID,
		DedupKey:          dedupKey,
		AlertCreationTime: existing.AlertCreationTime,
		AlertUpdateTime:   now,
		Title:             title,
		Severity:          severity,
	}, nil
}

func (d *Deduplicator) ResolveAlert(ctx context.Context, alertID string) error {
	_, err := d.db.ExecContext(ctx, `
		UPDATE alerts SET resolved_at = ? WHERE alert_id = ? AND resolved_at IS NULL
	`, time.Now(), alertID)
	return err
}

func (d *Deduplicator) GetOpenAlerts(ctx context.Context, ruleID string) ([]AlertInfo, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT alert_id, rule_id, dedup_key, created_at, updated_at, title, severity
		FROM alerts
		WHERE rule_id = ? AND resolved_at IS NULL
		ORDER BY created_at DESC
	`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []AlertInfo
	for rows.Next() {
		var a AlertInfo
		if err := rows.Scan(&a.AlertID, &a.RuleID, &a.DedupKey, &a.AlertCreationTime, &a.AlertUpdateTime, &a.Title, &a.Severity); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func GenerateDedupKey(ruleID, dedup string) string {
	return uuid.NewSHA1(DedupNamespace, []byte(ruleID+":"+dedup)).String()
}

func GenerateAlertID(ruleID, dedupKey string, ts time.Time) string {
	return uuid.NewSHA1(DedupNamespace, []byte(fmt.Sprintf("%s:%s:%d", ruleID, dedupKey, ts.UnixNano()))).String()
}

func (d *Deduplicator) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}
