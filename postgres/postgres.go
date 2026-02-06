package postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/meikuraledutech/auth"
)

// PGStore implements auth.Store using PostgreSQL via pgx.
type PGStore struct {
	db  *pgxpool.Pool
	cfg auth.Config
}

// New creates a new PGStore backed by the given pgx connection pool.
func New(db *pgxpool.Pool, cfg auth.Config) *PGStore {
	return &PGStore{db: db, cfg: cfg}
}
