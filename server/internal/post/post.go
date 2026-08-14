// Package post handles blog posts: validation, storage, and HTTP endpoints.
package post

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrNotFound  = errors.New("post: not found")
	ErrSlugTaken = errors.New("post: slug already used")
)

const (
	StatusDraft     = "draft"
	StatusPublished = "published"
	maxTitleLength  = 200
	maxSlugLength   = 120
	maxExcerpt      = 500
	maxContentBytes = 100000
)

var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type Post struct {
	ID          string  `json:"id"`
	AuthorID    string  `json:"author_id"`
	Title       string  `json:"title"`
	Slug        string  `json:"slug"`
	Excerpt     string  `json:"excerpt"`
	Content     string  `json:"content"`
	Status      string  `json:"status"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
	PublishedAt *string `json:"published_at,omitempty"`
}

type Summary struct {
	ID          string  `json:"id"`
	AuthorID    string  `json:"author_id"`
	Title       string  `json:"title"`
	Slug        string  `json:"slug"`
	Excerpt     string  `json:"excerpt"`
	Status      string  `json:"status"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
	PublishedAt *string `json:"published_at,omitempty"`
}

func (p Post) Summary() Summary {
	return Summary{ID: p.ID, AuthorID: p.AuthorID, Title: p.Title, Slug: p.Slug, Excerpt: p.Excerpt, Status: p.Status, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, PublishedAt: p.PublishedAt}
}

type CreateInput struct {
	Title   string `json:"title"`
	Slug    string `json:"slug"`
	Excerpt string `json:"excerpt"`
	Content string `json:"content"`
	Status  string `json:"status"`
}

type UpdateInput = CreateInput

func (in *CreateInput) Validate() map[string]string {
	in.Title = strings.TrimSpace(in.Title)
	in.Slug = strings.TrimSpace(in.Slug)
	in.Excerpt = strings.TrimSpace(in.Excerpt)
	in.Content = strings.TrimSpace(in.Content)
	in.Status = strings.TrimSpace(in.Status)

	problems := make(map[string]string)
	switch {
	case in.Title == "":
		problems["title"] = "is required"
	case utf8.RuneCountInString(in.Title) > maxTitleLength:
		problems["title"] = "must be 200 characters or fewer"
	}
	switch {
	case in.Slug == "":
		problems["slug"] = "is required"
	case len(in.Slug) > maxSlugLength:
		problems["slug"] = "must be 120 characters or fewer"
	case !slugPattern.MatchString(in.Slug):
		problems["slug"] = "must contain only lowercase letters, numbers, and single hyphens"
	}
	switch {
	case in.Excerpt == "":
		problems["excerpt"] = "is required"
	case utf8.RuneCountInString(in.Excerpt) > maxExcerpt:
		problems["excerpt"] = "must be 500 characters or fewer"
	}
	switch {
	case in.Content == "":
		problems["content"] = "is required"
	case len(in.Content) > maxContentBytes:
		problems["content"] = "must be 100000 bytes or fewer"
	}
	if in.Status != StatusDraft && in.Status != StatusPublished {
		problems["status"] = "must be draft or published"
	}
	if len(problems) == 0 {
		return nil
	}
	return problems
}

type Page struct {
	Limit  int
	Cursor Cursor
}

type Cursor struct {
	Value string `json:"value"`
	ID    string `json:"id"`
}

func EncodeCursor(cursor Cursor) (string, error) {
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func DecodeCursor(value string) (Cursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return Cursor{}, errors.New("invalid cursor")
	}
	var cursor Cursor
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.Value == "" || cursor.ID == "" {
		return Cursor{}, errors.New("invalid cursor")
	}
	return cursor, nil
}

type PageResult struct {
	Posts      []Summary `json:"posts"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
