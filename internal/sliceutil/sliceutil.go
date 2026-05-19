package sliceutil

import "strings"

// FirstNonEmpty returns the first value whose trimmed form is non-empty.
func FirstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// CloneStrings returns a shallow copy of the input slice, or nil if empty.
func CloneStrings(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	out := make([]string, len(input))
	copy(out, input)
	return out
}
