package deduplication

import (
	"context"
	"crypto/md5"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Deduplicator struct {
	db *sql.DB
}

type AlertInfo struct {
	AlertID         string
	AlertCount      int
	AlertCreationTime time.Time
	AlertUpdateTime   time.Time
	Title           string
	Severity        string
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
		CREATE TABLE IF NOT EXISTS alert_dedup (
			rule_id TEXT NOT NULL,
			dedup_string TEXT NOT NULL,
			alert_count INTEGER DEFAULT 1,
			alert_creation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			alert_update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			title TEXT,
			severity TEXT,
			PRIMARY KEY (rule_id, dedup_string)
		)
	`)
	return err
}

func (d *Deduplicator) UpdateAlertInfo(ctx context.Context, ruleID, dedup, title, severity string, dedupPeriodMinutes int) (*AlertInfo, error) {
	dedupKey := generateDedupKey(ruleID, dedup)
	now := time.Now()
	dedupThreshold := now.Add(-time.Duration(dedupPeriodMinutes) * time.Minute)

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var existingCount int
	var existingCreationTime time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT alert_count, alert_creation_time
		FROM alert_dedup
		WHERE rule_id = ? AND dedup_string = ?
	`, ruleID, dedupKey).Scan(&existingCount, &existingCreationTime)

	if err == sql.ErrNoRows {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO alert_dedup (rule_id, dedup_string, alert_count, alert_creation_time, alert_update_time, title, severity)
			VALUES (?, ?, 1, ?, ?, ?, ?)
		`, ruleID, dedupKey, now, now, title, severity)
		if err != nil {
			return nil, fmt.Errorf("insert alert: %w", err)
		}

		alertID := generateAlertID(ruleID, 1, dedup)
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit: %w", err)
		}

		return &AlertInfo{
			AlertID:          alertID,
			AlertCount:        1,
			AlertCreationTime: now,
			AlertUpdateTime:   now,
			Title:            title,
			Severity:         severity,
		}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("query alert: %w", err)
	}

	if existingCreationTime.Before(dedupThreshold) {
		newCount := existingCount + 1
		_, err = tx.ExecContext(ctx, `
			UPDATE alert_dedup
			SET alert_count = ?, alert_update_time = ?, title = ?, severity = ?
			WHERE rule_id = ? AND dedup_string = ?
		`, newCount, now, title, severity, ruleID, dedupKey)
		if err != nil {
			return nil, fmt.Errorf("update alert: %w", err)
		}

		alertID := generateAlertID(ruleID, newCount, dedup)
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit: %w", err)
		}

		return &AlertInfo{
			AlertID:          alertID,
			AlertCount:        newCount,
			AlertCreationTime: existingCreationTime,
			AlertUpdateTime:   now,
			Title:            title,
			Severity:         severity,
		}, nil
	}

	alertID := generateAlertID(ruleID, existingCount, dedup)
	return &AlertInfo{
		AlertID:          alertID,
		AlertCount:        existingCount,
		AlertCreationTime: existingCreationTime,
		AlertUpdateTime:   existingCreationTime,
		Title:            title,
		Severity:         severity,
	}, nil
}

func generateDedupKey(ruleID, dedup string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(ruleID+":"+dedup)))
}

func generateAlertID(ruleID string, count int, dedup string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%d:%s", ruleID, count, dedup))))
}

func (d *Deduplicator) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}
