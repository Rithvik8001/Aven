package post

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type Store struct{ db *sql.DB }

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

const columns = `id, author_id, title, slug, excerpt, content, status, created_at, updated_at, published_at`

func (s *Store) Create(ctx context.Context, authorID string, in CreateInput) (Post, error) {
	timestamp := now()
	var publishedAt any
	if in.Status == StatusPublished {
		publishedAt = timestamp
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Post{}, fmt.Errorf("post: generate id: %w", err)
	}
	created := Post{ID: id.String(), AuthorID: authorID, Title: in.Title, Slug: in.Slug, Excerpt: in.Excerpt, Content: in.Content, Status: in.Status, CreatedAt: timestamp, UpdatedAt: timestamp}
	if value, ok := publishedAt.(string); ok {
		created.PublishedAt = &value
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO posts (id, author_id, title, slug, excerpt, content, status, created_at, updated_at, published_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		created.ID, created.AuthorID, created.Title, created.Slug, created.Excerpt, created.Content, created.Status, created.CreatedAt, created.UpdatedAt, publishedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return Post{}, ErrSlugTaken
		}
		return Post{}, fmt.Errorf("post: insert: %w", err)
	}
	return created, nil
}

func (s *Store) BySlug(ctx context.Context, slug string) (Post, error) {
	return s.queryOne(ctx, `SELECT `+columns+` FROM posts WHERE slug = ? AND status = 'published'`, slug)
}

func (s *Store) ListPublished(ctx context.Context, page Page) (PageResult, error) {
	query := `SELECT ` + columns + ` FROM posts WHERE status = 'published' AND published_at IS NOT NULL`
	args := []any{}
	if page.Cursor.ID != "" {
		query += ` AND (published_at < ? OR (published_at = ? AND id < ?))`
		args = append(args, page.Cursor.Value, page.Cursor.Value, page.Cursor.ID)
	}
	query += ` ORDER BY published_at DESC, id DESC LIMIT ?`
	args = append(args, page.Limit+1)
	return s.list(ctx, query, args, page.Limit)
}

func (s *Store) ListMine(ctx context.Context, authorID, status string, page Page) (PageResult, error) {
	query := `SELECT ` + columns + ` FROM posts WHERE author_id = ?`
	args := []any{authorID}
	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	if page.Cursor.ID != "" {
		query += ` AND (updated_at < ? OR (updated_at = ? AND id < ?))`
		args = append(args, page.Cursor.Value, page.Cursor.Value, page.Cursor.ID)
	}
	query += ` ORDER BY updated_at DESC, id DESC LIMIT ?`
	args = append(args, page.Limit+1)
	return s.list(ctx, query, args, page.Limit)
}

func (s *Store) Update(ctx context.Context, id, authorID string, in UpdateInput) (Post, error) {
	timestamp := now()
	var publishedAt any
	if in.Status == StatusPublished {
		var previous sql.NullString
		err := s.db.QueryRowContext(ctx, `SELECT published_at FROM posts WHERE id = ? AND author_id = ?`, id, authorID).Scan(&previous)
		if errors.Is(err, sql.ErrNoRows) {
			return Post{}, ErrNotFound
		}
		if err != nil {
			return Post{}, fmt.Errorf("post: find before update: %w", err)
		}
		if previous.Valid {
			publishedAt = previous.String
		} else {
			publishedAt = timestamp
		}
	}
	result, err := s.db.ExecContext(ctx, `UPDATE posts SET title = ?, slug = ?, excerpt = ?, content = ?, status = ?, updated_at = ?, published_at = ? WHERE id = ? AND author_id = ?`,
		in.Title, in.Slug, in.Excerpt, in.Content, in.Status, timestamp, publishedAt, id, authorID)
	if err != nil {
		if isUniqueViolation(err) {
			return Post{}, ErrSlugTaken
		}
		return Post{}, fmt.Errorf("post: update: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return Post{}, fmt.Errorf("post: update result: %w", err)
	}
	if changed == 0 {
		return Post{}, ErrNotFound
	}
	return s.queryOne(ctx, `SELECT `+columns+` FROM posts WHERE id = ? AND author_id = ?`, id, authorID)
}

func (s *Store) Delete(ctx context.Context, id, authorID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM posts WHERE id = ? AND author_id = ?`, id, authorID)
	if err != nil {
		return fmt.Errorf("post: delete: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("post: delete result: %w", err)
	}
	if changed == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) queryOne(ctx context.Context, query string, args ...any) (Post, error) {
	var post Post
	var publishedAt sql.NullString
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&post.ID, &post.AuthorID, &post.Title, &post.Slug, &post.Excerpt, &post.Content, &post.Status, &post.CreatedAt, &post.UpdatedAt, &publishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Post{}, ErrNotFound
	}
	if err != nil {
		return Post{}, fmt.Errorf("post: query: %w", err)
	}
	if publishedAt.Valid {
		post.PublishedAt = &publishedAt.String
	}
	return post, nil
}

func (s *Store) list(ctx context.Context, query string, args []any, limit int) (PageResult, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return PageResult{}, fmt.Errorf("post: list: %w", err)
	}
	defer rows.Close()
	posts := make([]Post, 0, limit)
	for rows.Next() {
		var post Post
		var publishedAt sql.NullString
		if err := rows.Scan(&post.ID, &post.AuthorID, &post.Title, &post.Slug, &post.Excerpt, &post.Content, &post.Status, &post.CreatedAt, &post.UpdatedAt, &publishedAt); err != nil {
			return PageResult{}, fmt.Errorf("post: scan list: %w", err)
		}
		if publishedAt.Valid {
			post.PublishedAt = &publishedAt.String
		}
		posts = append(posts, post)
	}
	if err := rows.Err(); err != nil {
		return PageResult{}, fmt.Errorf("post: list rows: %w", err)
	}
	result := PageResult{Posts: make([]Summary, 0, len(posts))}
	for _, post := range posts {
		result.Posts = append(result.Posts, post.Summary())
	}
	if len(posts) > limit {
		last := posts[limit-1]
		result.Posts = result.Posts[:limit]
		value := last.UpdatedAt
		if last.Status == StatusPublished && last.PublishedAt != nil {
			value = *last.PublishedAt
		}
		result.NextCursor, err = EncodeCursor(Cursor{Value: value, ID: last.ID})
		if err != nil {
			return PageResult{}, fmt.Errorf("post: encode cursor: %w", err)
		}
	}
	return result, nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
