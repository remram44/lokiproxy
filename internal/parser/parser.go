package parser

import (
	"fmt"
	"log"
	"maps"
	"os"
	"strings"
)

func isWhiteSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

type queryParser struct {
	pos            int
	query          string
	result         strings.Builder
	requiredLabels map[string]interface{}
}

func (self *queryParser) parse() error {
	for {
		self.consumeWhiteSpace()
		if self.pos >= len(self.query) {
			return nil
		}
		c := self.query[self.pos]
		switch {
		case c == '{':
			self.result.WriteByte(c)
			self.pos += 1
			self.consumeSelectors()
		case (c == '[' || c == '(') ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
			c == '=' || c == '<' || c == '>' || c == '!' ||
			c >= '0' || c <= '9':
			self.result.WriteByte(c)
			self.pos += 1
		case c == '"':
			self.pos += 1
			if _, err := self.consumeString(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected character %#v", c)
		}
	}
}

func (self *queryParser) consumeWhiteSpace() {
	for self.pos < len(self.query) && isWhiteSpace(self.query[self.pos]) {
		self.result.WriteByte(self.query[self.pos])
		self.pos += 1
	}
}

func (self *queryParser) consumeString() (string, error) {
	start := self.pos - 1
	for self.pos < len(self.query) {
		c := self.query[self.pos]
		self.result.WriteByte(c)
		switch c {
		case '"':
			self.pos += 1
			return self.query[start:self.pos], nil
		case '\\':
			self.pos += 1
			if self.pos >= len(self.query) {
				return "", fmt.Errorf("missing closing string delimiter")
			}
			self.result.WriteByte(self.query[self.pos])
		}
		self.pos += 1
	}
	return "", fmt.Errorf("missing closing string delimiter")
}

func (self *queryParser) consumeIdentifier() string {
	start := self.pos
	for self.pos < len(self.query) {
		c := self.query[self.pos]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || (self.pos > start && c >= '0' && c <= '9') {
			self.result.WriteByte(c)
			self.pos += 1
		} else {
			break
		}
	}
	return self.query[start:self.pos]
}

func (self *queryParser) consumeSelectors() error {
	missingLabels := maps.Clone(self.requiredLabels)
	insertComma := false
	for self.pos < len(self.query) {
		c := self.query[self.pos]
		if c == '}' {
			for label := range missingLabels {
				if insertComma {
					self.result.WriteString(", ")
				}
				self.result.WriteString(label)
				insertComma = true
			}
			self.result.WriteByte('}')
			self.pos += 1
			return nil
		} else if c == ',' || c == ' ' {
			self.result.WriteByte(c)
			self.pos += 1
		} else if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
			var label strings.Builder
			label.WriteString(self.consumeIdentifier())
			self.consumeWhiteSpace()
			if self.pos >= len(self.query) {
				return fmt.Errorf("missing selector operator")
			}
			for self.pos < len(self.query) {
				c := self.query[self.pos]
				self.result.WriteByte(c)
				self.pos += 1
				if isWhiteSpace(c) {
					continue
				}
				if c == '"' {
					s, err := self.consumeString()
					if err != nil {
						return err
					}
					label.WriteString(s)
					delete(missingLabels, label.String())
					insertComma = true
					break
				}
				label.WriteByte(c)
			}
		} else {
			return fmt.Errorf("syntax error in selectors")
		}
	}
	return fmt.Errorf("missing closing brace")
}

func ProcessQuery(query string, requiredLabels map[string]interface{}) (string, error) {
	parser := queryParser{
		pos:            0,
		query:          query,
		requiredLabels: requiredLabels,
	}
	if err := parser.parse(); err != nil {
		return "", err
	}
	if os.Getenv("LOKIPROXY_DEBUG_SHOW_QUERIES") != "" {
		log.Printf("%#v -> %#v", query, parser.result.String())
	}
	return parser.result.String(), nil
}
