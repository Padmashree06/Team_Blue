package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// type Policy struct {
// 	DenyPathPatterns []string `json:"denyPathPatterns"`
// 	DenyKeywords     []string `json:"denyKeywords"`
// }

func loadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// func expandHome(p string) string {
// 	if strings.HasPrefix(p, "~") {
// 		if home, err := os.UserHomeDir(); err == nil {
// 			return filepath.Join(home, strings.TrimPrefix(p, "~"))
// 		}
// 	}
// 	return p
// }

// resolvePath makes a path absolute and resolves symlinks, so a relative
// path or a symlinked directory can't sneak past the string comparison.
func resolvePath(p string) string {
	p = expandHome(p)
	if !filepath.IsAbs(p) {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return p
}

func isDenied(path string, policy *Policy) (bool, string) {
	resolved := resolvePath(path)
	for _, pattern := range policy.DenyPathPatterns {
		denyResolved := resolvePath(pattern)
		if resolved == denyResolved || strings.HasPrefix(resolved, denyResolved+string(os.PathSeparator)) {
			return true, pattern
		}
	}
	return false, ""
}

// extractPaths pulls path-looking strings out of the tool call's arguments
// without hardcoding which tool or which argument name (path/paths/source/dest...).
func extractPaths(line string) []string {
	var msg struct {
		Params struct {
			Arguments map[string]interface{} `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		return nil
	}
	var paths []string
	for _, v := range msg.Params.Arguments {
		switch val := v.(type) {
		case string:
			if looksLikePath(val) {
				paths = append(paths, val)
			}
		case []interface{}:
			for _, item := range val {
				if s, ok := item.(string); ok && looksLikePath(s) {
					paths = append(paths, s)
				}
			}
		}
	}
	return paths
}

func looksLikePath(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") ||
		strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
}