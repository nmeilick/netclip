package queue

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nmeilick/netclip/common/duration"
	"github.com/rs/zerolog"
)

const (
	DefaultMaxConcurrent      = 500
	DefaultMaxQueueSize       = 50000
	DefaultMaxWaitTime        = 30 * time.Second
	DefaultPerIPMaxConcurrent = 100
	DefaultPerIPMaxQueueSize  = 10000
	DefaultPerIPMaxWaitTime   = 30 * time.Second
)

// QueueConfig defines configuration for the queue middleware
type QueueConfig struct {
	// MaxConcurrent is the maximum number of concurrent requests allowed
	MaxConcurrent int `json:"max_concurrent,omitempty" hcl:"max_concurrent,optional"`

	// MaxQueueSize is the maximum number of requests that can be queued
	MaxQueueSize int `json:"max_queue_size,omitempty" hcl:"max_queue_size,optional"`

	// MaxWaitTime is the maximum time a request can wait in the queue
	MaxWaitTime string `json:"max_wait_time,omitempty" hcl:"max_wait_time,optional"`

	// Parsed durations
	parsedMaxWaitTime time.Duration
}

// ConfigOption defines a function type for configuring QueueConfig
type ConfigOption func(*QueueConfig)

// WithMaxConcurrent sets the maximum concurrent requests for the queue config
func WithMaxConcurrent(max int) ConfigOption {
	return func(c *QueueConfig) {
		c.MaxConcurrent = max
	}
}

// WithMaxQueueSize sets the maximum queue size for the queue config
func WithMaxQueueSize(max int) ConfigOption {
	return func(c *QueueConfig) {
		c.MaxQueueSize = max
	}
}

// WithMaxWaitTime sets the maximum wait time for the queue config
func WithMaxWaitTime(d time.Duration) ConfigOption {
	return func(c *QueueConfig) {
		c.MaxWaitTime = duration.String(d)
		c.parsedMaxWaitTime = d
	}
}

// NewConfig creates a new QueueConfig with default values and applies options
func NewConfig(options ...ConfigOption) *QueueConfig {
	cfg := QueueConfig{
		MaxConcurrent:     DefaultMaxConcurrent,
		MaxQueueSize:      DefaultMaxQueueSize,
		MaxWaitTime:       duration.String(DefaultMaxWaitTime),
		parsedMaxWaitTime: DefaultMaxWaitTime,
	}
	for _, opt := range options {
		opt(&cfg)
	}
	cfg.Normalize()
	return &cfg
}

// Normalize sets default values for vital settings that haven't been set
func (qc *QueueConfig) Normalize() error {
	var err error

	// Set default values for main queue
	if qc.MaxConcurrent <= 0 {
		qc.MaxConcurrent = DefaultMaxConcurrent
	}
	if qc.MaxQueueSize <= 0 {
		qc.MaxQueueSize = DefaultMaxQueueSize
	}

	// Parse max wait time
	if qc.MaxWaitTime != "" {
		qc.parsedMaxWaitTime, err = duration.Parse(qc.MaxWaitTime)
		if err != nil {
			return fmt.Errorf("invalid max_wait_time: %w", err)
		}
	}
	if qc.parsedMaxWaitTime <= 0 {
		qc.parsedMaxWaitTime = DefaultMaxWaitTime
	}

	return qc.Validate()
}

// GetMaxWaitTime returns the parsed max wait time duration
func (qc *QueueConfig) GetMaxWaitTime() time.Duration {
	return qc.parsedMaxWaitTime
}

// Validate checks the queue configuration for errors
func (qc *QueueConfig) Validate() error {
	// Validate main queue settings
	if qc.MaxConcurrent <= 0 {
		return fmt.Errorf("max_concurrent must be positive when connection queue is enabled")
	}
	if qc.MaxQueueSize <= 0 {
		return fmt.Errorf("max_queue_size must be positive when connection queue is enabled")
	}
	if qc.parsedMaxWaitTime <= 0 {
		return fmt.Errorf("max_wait_time must be positive when connection queue is enabled")
	}
	return nil
}

// Queue represents a queue for managing concurrent connections
type Queue struct {
	config      QueueConfig
	semaphore   chan struct{}
	queue       chan struct{}
	parent      *Queue
	active      int
	waiting     int
	mutex       sync.RWMutex
	name        string
	totalActive int64
	totalQueued int64
	logger      zerolog.Logger
}

// Option defines a function type for configuring a Queue
type Option func(*Queue)

// WithConfig applies a pre-configured QueueConfig to the Queue.
// It assumes the passed config is already initialized (e.g., via NewConfig).
func WithConfig(config *QueueConfig) Option {
	return func(q *Queue) {
		q.config = *config
	}
}

// WithParent sets the parent queue for hierarchical queueing
func WithParent(parent *Queue) Option {
	return func(q *Queue) {
		q.parent = parent
	}
}

// WithLogger sets the logger for the queue config
func WithLogger(logger zerolog.Logger) Option {
	return func(q *Queue) {
		q.logger = logger
	}
}

// NewQueue creates a new connection queue with the given name and options
func NewQueue(name string, options ...Option) *Queue {
	// Start with default configuration using NewConfig
	q := &Queue{
		name:   name,
		config: *NewConfig(),
		mutex:  sync.RWMutex{},
	}

	// Apply all provided options
	for _, opt := range options {
		opt(q)
	}
	q.config.Normalize()

	// Initialize channels based on the final configuration
	q.semaphore = make(chan struct{}, q.config.MaxConcurrent)
	q.queue = make(chan struct{}, q.config.MaxQueueSize)

	return q
}

// Middleware returns a Gin middleware that applies connection queueing
func (cq *Queue) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create a context with timeout for queue waiting
		ctx, cancel := context.WithTimeout(c.Request.Context(), cq.config.GetMaxWaitTime())
		defer cancel()

		// First, check if we need to go through a parent queue
		if cq.parent != nil {
			// Try to acquire from parent first
			if !cq.parent.acquire(ctx) {
				// Failed to acquire from parent
				c.AbortWithStatus(http.StatusServiceUnavailable)
				return
			}
			// Make sure we release the parent when done
			defer cq.parent.release()
		}

		// Now try to acquire from our own queue
		if !cq.acquire(ctx) {
			// Failed to acquire
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}

		// Make sure we release when done
		defer cq.release()

		// Continue with the request
		c.Next()
	}
}

// acquire attempts to acquire a slot in the queue
// Returns true if successful, false if timed out or queue is full
func (cq *Queue) acquire(ctx context.Context) bool {
	// First check if we can immediately acquire a semaphore slot
	select {
	case cq.semaphore <- struct{}{}:
		// Successfully acquired a slot
		cq.mutex.Lock()
		cq.active++
		cq.totalActive++
		cq.mutex.Unlock()

		cq.logger.Debug().
			Str("queue", cq.name).
			Int("active", cq.active).
			Int("waiting", cq.waiting).
			Msg("Request acquired slot immediately")

		return true
	default:
		// No immediate slot available, try to queue
	}

	// Try to enter the queue
	select {
	case cq.queue <- struct{}{}:
		// Successfully entered the queue
		cq.mutex.Lock()
		cq.waiting++
		cq.totalQueued++
		cq.mutex.Unlock()

		cq.logger.Debug().
			Str("queue", cq.name).
			Int("active", cq.active).
			Int("waiting", cq.waiting).
			Msg("Request entered queue")
	case <-ctx.Done():
		// Timeout or context canceled while trying to enter queue
		cq.logger.Debug().
			Str("queue", cq.name).
			Msg("Request rejected, queue full")
		return false
	}

	// We're in the queue, now wait for a semaphore slot
	defer func() {
		// Remove from queue when we're done waiting
		<-cq.queue
		cq.mutex.Lock()
		cq.waiting--
		cq.mutex.Unlock()
	}()

	select {
	case cq.semaphore <- struct{}{}:
		// Successfully acquired a slot
		cq.mutex.Lock()
		cq.active++
		cq.totalActive++
		cq.mutex.Unlock()

		cq.logger.Debug().
			Str("queue", cq.name).
			Int("active", cq.active).
			Int("waiting", cq.waiting).
			Msg("Queued request acquired slot")

		return true
	case <-ctx.Done():
		// Timeout or context canceled while waiting for a slot
		cq.logger.Debug().
			Str("queue", cq.name).
			Msg("Request timed out in queue")
		return false
	}
}

// release releases a slot in the queue
func (cq *Queue) release() {
	<-cq.semaphore
	cq.mutex.Lock()
	cq.active--
	cq.mutex.Unlock()

	cq.logger.Debug().
		Str("queue", cq.name).
		Int("active", cq.active).
		Int("waiting", cq.waiting).
		Msg("Request completed, slot released")
}

// QueueStats holds statistics about a queue
type QueueStats struct {
	Name          string      `json:"name"`
	Active        int         `json:"active"`
	Waiting       int         `json:"waiting"`
	MaxConcurrent int         `json:"max_concurrent"`
	MaxQueueSize  int         `json:"max_queue_size"`
	TotalServed   int64       `json:"total_served"`
	TotalQueued   int64       `json:"total_queued"`
	Parent        *QueueStats `json:"parent,omitempty"`
}

// Stats returns current statistics about the queue
func (cq *Queue) Stats() QueueStats {
	cq.mutex.RLock()
	defer cq.mutex.RUnlock()

	stats := QueueStats{
		Name:          cq.name,
		Active:        cq.active,
		Waiting:       cq.waiting,
		MaxConcurrent: cq.config.MaxConcurrent,
		MaxQueueSize:  cq.config.MaxQueueSize,
		TotalServed:   cq.totalActive,
		TotalQueued:   cq.totalQueued,
	}

	if cq.parent != nil {
		parentStats := cq.parent.Stats()
		stats.Parent = &parentStats // Assign the address of the parent stats
	}

	return stats
}
