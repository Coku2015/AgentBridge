package job

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// HostDefaults applies shared non-secret settings to every imported host
// (FR-014). No credential is ever part of defaults or the import payload (red
// line 1): secrets are supplied per-host in the Web UI at execute time only.
type HostDefaults struct {
	Port int
}

// ImportHosts parses a text/CSV blob of host identifiers into HostTasks
// (FR-014). Accepted line forms:
//   - `host`            (port = defaults.Port, or 22)
//   - `host,port`
//   - a header line beginning with `host` (case-insensitive) is skipped
//
// Blank lines and `#` comments are ignored. IDs are `host:port` and de-duplicated.
func ImportHosts(raw []byte, defaults HostDefaults) ([]HostTask, error) {
	if defaults.Port == 0 {
		defaults.Port = 22
	}
	seen := map[string]struct{}{}
	var out []HostTask
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		if isHeader(fields) {
			continue // skip a CSV header row
		}
		if len(fields) > 2 {
			return nil, fmt.Errorf("import: expected host[,port] on line %d", lineNo)
		}
		host := fields[0]
		if host == "" {
			return nil, fmt.Errorf("import: empty host on line %d", lineNo)
		}
		port := defaults.Port
		if len(fields) >= 2 && fields[1] != "" {
			p, err := strconv.Atoi(fields[1])
			if err != nil || p <= 0 || p > 65535 {
				return nil, fmt.Errorf("import: invalid port %q on line %d", fields[1], lineNo)
			}
			port = p
		}
		id := fmt.Sprintf("%s:%d", host, port)
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, HostTask{ID: id, Host: host, Port: port})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("import: scan: %w", err)
	}
	return out, nil
}

// isHeader detects a CSV header row whose first cell is literally "host".
func isHeader(fields []string) bool {
	return len(fields) > 0 && strings.EqualFold(fields[0], "host")
}
