package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/adrg/xdg"
	"github.com/nmeilick/netclip/common"
	_ "modernc.org/sqlite"
)

const (
	cacheFileName = "cache.db"
)

// Cache represents a SQLite-based caching system
type Cache struct {
	db         *sql.DB
	path       string
	mu         sync.Mutex
	tables     map[string]bool
	maxAge     time.Duration
	autoClean  bool
	cleanEvery time.Duration
	lastClean  time.Time
}

// Option is a function that configures a Cache
type Option func(*Cache) error

// NewCache creates a new cache with the given options
func NewCache(path string, options ...Option) (*Cache, error) {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Open database
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache database: %w", err)
	}

	os.Chmod(path, 0600)

	// Create cache instance
	cache := &Cache{
		db:         db,
		path:       path,
		tables:     make(map[string]bool),
		maxAge:     180 * 24 * time.Hour, // Default 180 days
		autoClean:  true,
		cleanEvery: 24 * time.Hour,
		lastClean:  time.Now(),
	}

	// Apply options
	for _, option := range options {
		if err := option(cache); err != nil {
			db.Close()
			return nil, err
		}
	}

	return cache, nil
}

// WithMaxAge sets the maximum age for cached items
func WithMaxAge(maxAge time.Duration) Option {
	return func(c *Cache) error {
		if maxAge < 0 {
			return errors.New("max age cannot be negative")
		}
		c.maxAge = maxAge
		return nil
	}
}

// WithAutoClean enables or disables automatic cleanup
func WithAutoClean(enabled bool) Option {
	return func(c *Cache) error {
		c.autoClean = enabled
		return nil
	}
}

// WithCleanInterval sets how often cleanup runs
func WithCleanInterval(interval time.Duration) Option {
	return func(c *Cache) error {
		if interval < 0 {
			return errors.New("clean interval cannot be negative")
		}
		c.cleanEvery = interval
		return nil
	}
}

// Close closes the cache database
func (c *Cache) Close() error {
	return c.db.Close()
}

// CacheEntry represents a single entry in the cache with metadata
type CacheEntry struct {
	Key          string
	Value        string
	Created      time.Time
	LastAccessed time.Time
}

// ListEntriesWithTime returns all entries in a table with their timestamps, sorted by last_accessed (newest first)
func (c *Cache) ListEntriesWithTime(table string) ([]CacheEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if table exists
	if !c.tables[table] {
		// Try to ensure the table exists
		if err := c.ensureTable(table); err != nil {
			return nil, err
		}

		// If it still doesn't exist after ensuring, it's empty
		if !c.tables[table] {
			return []CacheEntry{}, nil
		}
	}

	// Query all entries, ordered by last_accessed descending (newest first)
	query := fmt.Sprintf("SELECT key, value, created, last_accessed FROM %q ORDER BY last_accessed DESC", table)
	rows, err := c.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []CacheEntry
	for rows.Next() {
		var entry CacheEntry
		if err := rows.Scan(&entry.Key, &entry.Value, &entry.Created, &entry.LastAccessed); err != nil {
			return nil, err
		}
		result = append(result, entry)
	}

	return result, nil
}

// ListEntries returns all key-value pairs in a table
func (c *Cache) ListEntries(table string) (map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if table exists
	if !c.tables[table] {
		// Try to ensure the table exists
		if err := c.ensureTable(table); err != nil {
			return nil, err
		}

		// If it still doesn't exist after ensuring, it's empty
		if !c.tables[table] {
			return make(map[string]string), nil
		}
	}

	// Query all entries
	query := fmt.Sprintf("SELECT key, value FROM %q", table)
	rows, err := c.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		result[key] = value
	}

	return result, nil
}

// GetRaw retrieves a raw value from the cache
func (c *Cache) GetRaw(table, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if table exists, create if not
	if err := c.ensureTable(table); err != nil {
		return "", err
	}

	// Maybe run cleanup
	c.maybeCleanup()

	var value string
	query := fmt.Sprintf("SELECT value FROM %q WHERE key = ?", table)
	err := c.db.QueryRow(query, key).Scan(&value)

	if err == sql.ErrNoRows {
		return "", nil
	} else if err != nil {
		return "", err
	}

	// Update last accessed time
	query = fmt.Sprintf("UPDATE %q SET last_accessed = ? WHERE key = ?", table)
	_, err = c.db.Exec(query, time.Now().UTC(), key)
	if err != nil {
		return "", err
	}

	return value, nil
}

// Get retrieves a value from the cache and unmarshals it
func (c *Cache) Get(table, key string, valuePtr interface{}) error {
	s, err := c.GetRaw(table, key)
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(s), valuePtr)
}

// SetRaw stores a raw value in the cache
func (c *Cache) SetRaw(table, key, value string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if table exists, create if not
	if err := c.ensureTable(table); err != nil {
		return err
	}

	// Maybe run cleanup
	c.maybeCleanup()

	// Insert or replace the value
	now := time.Now().UTC()
	query := fmt.Sprintf("INSERT OR REPLACE INTO %q (key, value, created, last_accessed) VALUES (?, ?, ?, ?)", table)
	_, err := c.db.Exec(query, key, value, now, now)
	return err
}

// Set marshals and stores a value in the cache
func (c *Cache) Set(table, key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.SetRaw(table, key, string(data))
}

// Delete removes a value from the cache
func (c *Cache) Delete(table, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if table exists
	if !c.tables[table] {
		return nil // Table doesn't exist, nothing to delete
	}

	// Delete the value
	query := fmt.Sprintf("DELETE FROM %q WHERE key = ?", table)
	_, err := c.db.Exec(query, key)
	return err
}

// Cleanup removes expired entries from all tables
func (c *Cache) Cleanup() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get list of tables
	rows, err := c.db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return err
		}
		tables = append(tables, table)
	}

	// Clean each table
	cutoff := time.Now().UTC().Add(-c.maxAge)
	for _, table := range tables {
		query := fmt.Sprintf("DELETE FROM %q WHERE last_accessed < ?", table)
		_, err := c.db.Exec(query, cutoff)
		if err != nil {
			return err
		}
	}

	c.lastClean = time.Now()
	return nil
}

// ensureTable makes sure the specified table exists
func (c *Cache) ensureTable(table string) error {
	// Check if we already know this table exists
	if c.tables[table] {
		return nil
	}

	// Create the table if it doesn't exist
	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %q (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			created TIMESTAMP NOT NULL,
			last_accessed TIMESTAMP NOT NULL
		)
	`, table)
	_, err := c.db.Exec(query)

	if err != nil {
		return err
	}

	// Mark table as existing
	c.tables[table] = true
	return nil
}

// maybeCleanup runs cleanup if it's time to do so
func (c *Cache) maybeCleanup() {
	if !c.autoClean {
		return
	}

	if time.Since(c.lastClean) > c.cleanEvery {
		// Run cleanup in a goroutine to avoid blocking
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Create a new connection for the cleanup to avoid locking issues
			db, err := sql.Open("sqlite", c.path)
			if err != nil {
				return
			}
			defer db.Close()

			// Get list of tables
			rows, err := db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table'")
			if err != nil {
				return
			}
			defer rows.Close()

			var tables []string
			for rows.Next() {
				var table string
				if err := rows.Scan(&table); err != nil {
					return
				}
				tables = append(tables, table)
			}

			// Clean each table
			cutoff := time.Now().UTC().Add(-c.maxAge)
			for _, table := range tables {
				query := fmt.Sprintf("DELETE FROM %q WHERE last_accessed < ?", table)
				db.ExecContext(ctx, query, cutoff)
			}

			c.mu.Lock()
			c.lastClean = time.Now()
			c.mu.Unlock()
		}()
	}
}

func PrivateCache(options ...Option) (*Cache, error) {
	file, err := xdg.CacheFile(filepath.Join(common.AppName, cacheFileName))
	if err != nil {
		return nil, err
	}

	return NewCache(file, options...)
}
