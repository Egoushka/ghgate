package route

import "testing"

func TestDocumentHasMutation(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want bool
	}{
		{"anon", `{ viewer { login } }`, false},
		{"query", `query Q($a: Int = 1) @x(y: {z: 1}) { repository(owner:"mutation") { id } }`, false},
		{"comment-mutation", "# mutation x\nquery { a }", false},
		{"string-mutation", `query { a(b: "mutation { }") }`, false},
		{"block-string", "query { a(b: \"\"\" mutation { \"\"\") }", false},
		{"mutation", `mutation { addStar(input:{}) { clientMutationId } }`, true},
		{"mutation-after-comment", "# hi\n\n  mutation M { a }", true},
		{"multi-op", `query A { a } mutation B { b }`, true},
		{"fragment-then-query", `fragment F on User { id } query { viewer { ...F } }`, false},
		{"subscription", `subscription { a }`, true},
		{"empty", ``, true},
		{"unbalanced", `query { a`, true},
		{"junk", `}}}`, true},
		{"unterminated-string", `query { a(b: "x) }`, true},
		{"extend", `extend type A { b: Int }`, true},
	}
	for _, c := range cases {
		if got := DocumentHasMutation(c.doc); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestClassify(t *testing.T) {
	if Classify("GET", "/repos/o/r", nil) != Read {
		t.Error("GET")
	}
	if Classify("PATCH", "/repos/o/r", nil) != Write || Classify("DELETE", "/x", nil) != Write {
		t.Error("write methods")
	}
	if Classify("POST", "/graphql", []byte(`{"query":"{ viewer { id } }"}`)) != Read {
		t.Error("graphql query")
	}
	if Classify("POST", "/graphql", []byte(`{"query":"mutation { a }"}`)) != Write {
		t.Error("graphql mutation")
	}
	if Classify("POST", "/graphql", []byte(`[{"query":"{a}"},{"query":"mutation {b}"}]`)) != Write {
		t.Error("batch")
	}
	if Classify("POST", "/graphql", []byte(`not json`)) != Write || Classify("POST", "/graphql", []byte(`{"id":"persisted"}`)) != Write {
		t.Error("unsure must be write")
	}
}

func TestGraphQLBodyEvasions(t *testing.T) {
	m := `mutation{addStar(input:{starrableId:\"1\"}){clientMutationId}}`
	q := `{viewer{login}}`
	cases := map[string]string{
		"mixed-case key":   `{"query":"` + m + `","QUERY":"` + q + `"}`,
		"mixed-case first": `{"QUERY":"` + q + `","query":"` + m + `"}`,
		"duplicate key":    `{"query":"` + m + `","query":"` + q + `"}`,
		"duplicate swap":   `{"query":"` + q + `","query":"` + m + `"}`,
		"batch":            `[{"query":"` + q + `"}]`,
		"extra key":        `{"query":"` + q + `","extensions":{}}`,
		"trailing data":    `{"query":"` + q + `"} {"query":"` + m + `"}`,
		"query not string": `{"query":5}`,
		"no query":         `{"variables":{}}`,
	}
	for name, body := range cases {
		if !GraphQLHasMutation([]byte(body)) {
			t.Errorf("%s must be treated as a write", name)
		}
	}
	ok := `{"query":"` + q + `","variables":{"a":1},"operationName":null}`
	if GraphQLHasMutation([]byte(ok)) {
		t.Error("a plain query body is a read")
	}
}
