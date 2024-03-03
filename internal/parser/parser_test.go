package parser

import (
	"testing"
)

func check(t *testing.T, original string, expected string) {
	requiredLabels := map[string]interface{}{"namespace=\"yes\"": nil}
	result, err := ProcessQuery(original, requiredLabels)
	if err != nil {
		t.Fatalf("parser error\nexpected: %#v\nerror   : %v", expected, err)
	}
	if result != expected {
		t.Fatalf("parser error\nexpected: %#v\nresult  : %#v", expected, result)
	}
}

func TestLogQuery(t *testing.T) {
	check(
		t,
		"{job_name=\"myapp\"} != ip(\"192.168.4.5-192.168.4.20\")",
		"{job_name=\"myapp\", namespace=\"yes\"} != ip(\"192.168.4.5-192.168.4.20\")",
	)
	check(
		t,
		"{job_name=\"myapp\", namespace=\"yes\"} != ip(\"192.168.4.5-192.168.4.20\")",
		"{job_name=\"myapp\", namespace=\"yes\"} != ip(\"192.168.4.5-192.168.4.20\")",
	)
	check(
		t,
		"{job_name=\"myapp\",namespace = \"yes\" } != ip(\"192.168.4.5-192.168.4.20\")",
		"{job_name=\"myapp\",namespace = \"yes\" } != ip(\"192.168.4.5-192.168.4.20\")",
	)

	check(
		t,
		"123{}",
		"123{namespace=\"yes\"}",
	)
}

func TestInternal(t *testing.T) {
	{
		parser := queryParser{
			pos:   1,
			query: "   {}",
		}
		parser.consumeWhiteSpace()
		if parser.pos != 3 {
			t.Fatalf("end of whitespace: %d, expected %d", parser.pos, 3)
		}
		expected := "  "
		if parser.result.String() != expected {
			t.Fatalf("parsed: %#v, expected %#v", parser.result.String(), expected)
		}
	}

	{
		parser := queryParser{
			pos:   3,
			query: "a=\"a long \\\"string\" here",
		}
		parser.consumeString()
		if parser.pos != 19 {
			t.Fatalf("end of string: %d, expected %d", parser.pos, 19)
		}
		expected := "a long \\\"string\""
		if parser.result.String() != expected {
			t.Fatalf("parsed: %#v, expected %#v", parser.result.String(), expected)
		}
	}
}
