// Package route classifies API requests as reads or writes.
package route

import (
	"encoding/json"
	"strings"
)

type Kind int

const (
	Read Kind = iota
	Write
)

func IsGraphQLPath(path string) bool {
	return strings.TrimSuffix(path, "/") == "/graphql"
}

// Classify decides which credential a request needs. body is only used for
// POST /graphql; when unsure the answer is Write.
func Classify(method, path string, body []byte) Kind {
	switch method {
	case "GET", "HEAD":
		return Read
	case "POST":
		if IsGraphQLPath(path) && !GraphQLHasMutation(body) {
			return Read
		}
	}
	return Write
}

// GraphQLHasMutation reports whether a GraphQL request body may run a mutation.
// It is true whenever the body cannot be positively shown to hold only queries.
func GraphQLHasMutation(body []byte) bool {
	t := strings.TrimLeft(strings.TrimPrefix(string(body), "\xef\xbb\xbf"), " \t\r\n")
	if strings.HasPrefix(t, "[") {
		var batch []struct {
			Query string `json:"query"`
		}
		if json.Unmarshal(body, &batch) != nil || len(batch) == 0 {
			return true
		}
		for _, b := range batch {
			if DocumentHasMutation(b.Query) {
				return true
			}
		}
		return false
	}
	var one struct {
		Query string `json:"query"`
	}
	if json.Unmarshal(body, &one) != nil {
		return true
	}
	return DocumentHasMutation(one.Query)
}

// DocumentHasMutation scans a GraphQL document and reports whether any
// top-level operation is not a plain query. Anything it cannot parse counts as one.
func DocumentHasMutation(doc string) bool {
	const (
		start = iota // between definitions
		head         // after query/fragment keyword, before its body
	)
	state, depth, ops := start, 0, 0
	for i := 0; i < len(doc); {
		c := doc[i]
		switch {
		case c == '#':
			for i < len(doc) && doc[i] != '\n' && doc[i] != '\r' {
				i++
			}
		case c == '"':
			if strings.HasPrefix(doc[i:], `"""`) {
				j := i + 3
				for j < len(doc) && !(strings.HasPrefix(doc[j:], `"""`) && doc[j-1] != '\\') {
					j++
				}
				if j >= len(doc) {
					return true
				}
				i = j + 3
				continue
			}
			j := i + 1
			for j < len(doc) && doc[j] != '"' {
				if doc[j] == '\\' {
					j++
				}
				if j < len(doc) && doc[j] == '\n' {
					return true
				}
				j++
			}
			if j >= len(doc) {
				return true
			}
			i = j + 1
		case c == '{' || c == '(' || c == '[':
			if depth == 0 && state == start {
				if c != '{' {
					return true
				}
				ops++ // anonymous query
				state = head
			}
			depth++
			i++
		case c == '}' || c == ')' || c == ']':
			depth--
			if depth < 0 {
				return true
			}
			if depth == 0 && c == '}' {
				state = start
			}
			i++
		case isName(c):
			j := i
			for j < len(doc) && isName(doc[j]) {
				j++
			}
			if depth == 0 && state == start {
				switch doc[i:j] {
				case "query":
					ops++
					state = head
				case "fragment":
					state = head
				default: // mutation, subscription, extend, type, ...
					return true
				}
			}
			i = j
		default:
			i++ // whitespace, commas, $ @ : = ! . & | and BOM bytes
		}
	}
	return depth != 0 || state != start || ops == 0
}

func isName(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
