// Package sqlfiles loads and splits embedded SQL migration files so each
// adapter can apply statements one at a time.
package sqlfiles

import (
	"embed"
	"io/fs"
	"sort"
	"strings"
)

// Load reads every SQL file in dir in filename order and returns the individual
// statements. Splitting is required because drivers such as pgx reject multiple
// commands in a single Exec in their default protocol mode.
func Load(files embed.FS, dir string) ([]string, error) {
	entries, err := fs.ReadDir(files, dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	var statements []string
	for _, name := range names {
		content, err := files.ReadFile(dir + "/" + name)
		if err != nil {
			return nil, err
		}
		for _, statement := range strings.Split(string(content), ";") {
			if trimmed := strings.TrimSpace(statement); trimmed != "" {
				statements = append(statements, trimmed)
			}
		}
	}
	return statements, nil
}

// LoadFile reads a single SQL file and returns its individual statements, so a
// caller can replay one migration in isolation.
func LoadFile(files embed.FS, dir, name string) ([]string, error) {
	content, err := files.ReadFile(dir + "/" + name)
	if err != nil {
		return nil, err
	}
	var statements []string
	for _, statement := range strings.Split(string(content), ";") {
		if trimmed := strings.TrimSpace(statement); trimmed != "" {
			statements = append(statements, trimmed)
		}
	}
	return statements, nil
}
