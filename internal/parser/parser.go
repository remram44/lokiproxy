package parser

import (
	"log"
	"strings"
)

func ProcessQuery(query string, allowedNamespaces map[string]interface{}) string {
	var result strings.Builder
	// TODO
	result.WriteString(query)
	log.Printf("> %s", query)
	return result.String()
}
