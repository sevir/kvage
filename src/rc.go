package main

import (
	"fmt"
	"strings"
)

// A .kvagerc file may only define environment variables. Its decrypted text
// is never handed to the shell: it is parsed here as a strict subset of
// shell assignment syntax and re-emitted as single-quoted exports.
//
// age does not authenticate the sender, so anyone who knows a public key can
// produce a .kvagerc that decrypts correctly. The parser therefore treats
// the content as untrusted: nothing in it can run a command, and variables
// that change how programs are found or loaded are blocked by default.

// rcBlockedNames are the variables a .kvagerc may not set unless the user
// allows them in config.yaml (rc.allow). An entry ending in "*" is a prefix.
var rcBlockedNames = []string{
	// Command lookup and dynamic loading.
	"PATH", "CDPATH", "LD_*", "DYLD_*",
	// Shell behaviour and startup.
	"PROMPT_COMMAND", "BASH_ENV", "ENV", "IFS", "SHELLOPTS", "BASHOPTS",
	"BASH_FUNC_*", "GLOBIGNORE", "HISTFILE", "SHELL", "HOME",
	"PS0", "PS1", "PS2", "PS3", "PS4",
	// Programs started on the user's behalf.
	"EDITOR", "VISUAL", "PAGER", "MANPAGER", "BROWSER", "LESSOPEN", "LESSCLOSE",
	"GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_EDITOR", "GIT_PAGER",
	"GIT_EXEC_PATH", "GIT_CONFIG*", "GIT_EXTERNAL_DIFF", "SSH_ASKPASS", "SUDO_ASKPASS",
	// Interpreter code injection.
	"PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "NODE_OPTIONS", "NODE_PATH",
	"PERL5LIB", "PERL5OPT", "RUBYLIB", "RUBYOPT",
	// kvage itself.
	"AGE_KEY_FILE", "KVAGE_*",
}

func matchName(patterns []string, name string) bool {
	for _, p := range patterns {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		} else if p == name {
			return true
		}
	}
	return false
}

// rcNameBlocked reports whether a .kvagerc may not set name.
func rcNameBlocked(name string, allow []string) bool {
	return matchName(rcBlockedNames, name) && !matchName(allow, name)
}

type rcVar struct {
	Name  string
	Value string
}

// rcParser scans .kvagerc text. Supported, per line:
//
//	NAME=value
//	export NAME=value OTHER=value
//	# comment            (also after a value)
//
// Values follow shell quoting: 'literal', "with $VAR and \" escapes",
// unquoted with backslash escapes, and adjacent pieces are concatenated.
// Quoted values may span lines. $VAR and ${VAR} are replaced with variables
// defined earlier in the file or taken from the environment; a leading ~ is
// the home directory. Everything else (command substitution, ${VAR:-x},
// pipes, several commands, aliases, functions) makes the line invalid.
type rcParser struct {
	src    string
	pos    int
	line   int
	lookup func(string) (string, bool)
	local  map[string]string
}

type rcError struct {
	line int
	msg  string
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isNameChar(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}

func (p *rcParser) eof() bool { return p.pos >= len(p.src) }

func (p *rcParser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.src[p.pos]
}

// next consumes one byte, keeping the line counter up to date.
func (p *rcParser) next() byte {
	c := p.src[p.pos]
	p.pos++
	if c == '\n' {
		p.line++
	}
	return c
}

func (p *rcParser) skipBlanks() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t' || p.peek() == '\r') {
		p.pos++
	}
}

func (p *rcParser) skipLine() {
	for !p.eof() && p.next() != '\n' {
	}
}

func (p *rcParser) atLineEnd() bool {
	return p.eof() || p.peek() == '\n'
}

func (p *rcParser) name() string {
	start := p.pos
	if p.eof() || !isNameStart(p.peek()) {
		return ""
	}
	for !p.eof() && isNameChar(p.peek()) {
		p.pos++
	}
	return p.src[start:p.pos]
}

func (p *rcParser) get(name string) string {
	if v, ok := p.local[name]; ok {
		return v
	}
	if p.lookup != nil {
		if v, ok := p.lookup(name); ok {
			return v
		}
	}
	return ""
}

// expansion handles the text after a "$".
func (p *rcParser) expansion(b *strings.Builder) error {
	switch c := p.peek(); {
	case c == '{':
		p.pos++
		name := p.name()
		if name == "" || p.peek() != '}' {
			return fmt.Errorf("unsupported ${...} expansion")
		}
		p.pos++
		b.WriteString(p.get(name))
	case c == '(':
		return fmt.Errorf("command substitution is not allowed")
	case isNameStart(c):
		b.WriteString(p.get(p.name()))
	case c >= '0' && c <= '9', strings.IndexByte("?$!#@*-", c) >= 0 && c != 0:
		return fmt.Errorf("unsupported $%c expansion", c)
	default:
		b.WriteByte('$')
	}
	return nil
}

// value reads one shell word and returns its expanded text.
func (p *rcParser) value() (string, error) {
	var b strings.Builder
	first := true
	for !p.eof() {
		c := p.peek()
		if c == ' ' || c == '\t' || c == '\n' {
			break
		}
		if c == '\r' && (p.pos+1 >= len(p.src) || p.src[p.pos+1] == '\n') {
			break
		}
		p.next()
		switch c {
		case '\'':
			for {
				if p.eof() {
					return "", fmt.Errorf("unterminated single quote")
				}
				ch := p.next()
				if ch == '\'' {
					break
				}
				b.WriteByte(ch)
			}
		case '"':
			for {
				if p.eof() {
					return "", fmt.Errorf("unterminated double quote")
				}
				ch := p.next()
				if ch == '"' {
					break
				}
				switch ch {
				case '\\':
					if p.eof() {
						return "", fmt.Errorf("unterminated double quote")
					}
					esc := p.next()
					switch esc {
					case '"', '\\', '$', '`':
						b.WriteByte(esc)
					case '\n':
					default:
						b.WriteByte('\\')
						b.WriteByte(esc)
					}
				case '$':
					if err := p.expansion(&b); err != nil {
						return "", err
					}
				case '`':
					return "", fmt.Errorf("command substitution is not allowed")
				default:
					b.WriteByte(ch)
				}
			}
		case '\\':
			if p.eof() {
				break
			}
			if esc := p.next(); esc != '\n' {
				b.WriteByte(esc)
			}
		case '$':
			if err := p.expansion(&b); err != nil {
				return "", err
			}
		case '`':
			return "", fmt.Errorf("command substitution is not allowed")
		case ';', '|', '&', '<', '>', '(', ')':
			return "", fmt.Errorf("unsupported shell syntax %q", c)
		case '~':
			end := p.eof() || strings.IndexByte("/ \t\r\n", p.peek()) >= 0
			if first && end {
				b.WriteString(p.get("HOME"))
			} else {
				b.WriteByte(c)
			}
		default:
			b.WriteByte(c)
		}
		first = false
	}
	return b.String(), nil
}

// statement parses the assignments of one logical line.
func (p *rcParser) statement() ([]rcVar, error) {
	// An optional "export" keyword followed by blanks.
	if strings.HasPrefix(p.src[p.pos:], "export") {
		after := p.pos + len("export")
		if after < len(p.src) && (p.src[after] == ' ' || p.src[after] == '\t') {
			p.pos = after
			p.skipBlanks()
		}
	}

	var vars []rcVar
	for {
		name := p.name()
		if name == "" || p.peek() != '=' {
			return nil, fmt.Errorf("not a variable assignment")
		}
		p.pos++
		val, err := p.value()
		if err != nil {
			return nil, err
		}
		vars = append(vars, rcVar{name, val})

		p.skipBlanks()
		if p.atLineEnd() {
			return vars, nil
		}
		if p.peek() == '#' {
			return vars, nil
		}
	}
}

// parseRC extracts the variable assignments of a decrypted .kvagerc.
// Invalid lines and blocked names are skipped and reported in warnings,
// which never contain values.
func parseRC(text string, lookup func(string) (string, bool), allow []string) ([]rcVar, []string) {
	p := &rcParser{src: text, line: 1, lookup: lookup, local: make(map[string]string)}
	var vars []rcVar
	var warnings []string

	for {
		p.skipBlanks()
		if p.eof() {
			break
		}
		if p.peek() == '\n' {
			p.next()
			continue
		}
		if p.peek() == '#' {
			p.skipLine()
			continue
		}

		startLine := p.line
		stmt, err := p.statement()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("line %d ignored: %v", startLine, err))
			p.skipLine()
			continue
		}
		p.skipLine() // the newline, or a trailing comment
		for _, v := range stmt {
			if rcNameBlocked(v.Name, allow) {
				warnings = append(warnings, fmt.Sprintf("line %d: %s is not set: protected variable (allow it with rc.allow in the kvage config.yaml)", startLine, v.Name))
				continue
			}
			p.local[v.Name] = v.Value
			vars = append(vars, v)
		}
	}
	return vars, warnings
}
