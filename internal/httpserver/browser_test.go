package httpserver

import (
	"bytes"
	"reflect"
	"testing"
)

func TestWriteStartupStatus(t *testing.T) {
	var output bytes.Buffer
	writeStartupStatus(
		&output,
		"1.2.3",
		"http://127.0.0.1:8787/",
		"http://localhost:8787/",
		true,
	)
	want := "\n" +
		"AgentBridge 1.2.3\n" +
		"Veeam Agent deployment for Windows and Linux hosts\n" +
		"\n" +
		"Web interface:\n" +
		"  http://127.0.0.1:8787/\n" +
		"  http://localhost:8787/\n" +
		"\n" +
		"The web interface has been opened in your default browser.\n" +
		"Press Ctrl+C to stop AgentBridge.\n" +
		"\n"
	if output.String() != want {
		t.Fatalf("startup banner:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestAccessURLs(t *testing.T) {
	primary, alternative := accessURLs("127.0.0.1:8787", false)
	if primary != "http://127.0.0.1:8787/" {
		t.Fatalf("primary URL = %q", primary)
	}
	if alternative != "http://localhost:8787/" {
		t.Fatalf("alternative URL = %q", alternative)
	}

	primary, alternative = accessURLs("10.10.1.4:8443", true)
	if primary != "https://10.10.1.4:8443/" || alternative != "" {
		t.Fatalf("remote URLs = %q, %q", primary, alternative)
	}
}

func TestBrowserCommand(t *testing.T) {
	tests := []struct {
		goos string
		name string
		args []string
	}{
		{goos: "darwin", name: "open", args: []string{"http://localhost:8787/"}},
		{goos: "linux", name: "xdg-open", args: []string{"http://localhost:8787/"}},
		{goos: "windows", name: "rundll32.exe", args: []string{"url.dll,FileProtocolHandler", "http://localhost:8787/"}},
	}
	for _, test := range tests {
		t.Run(test.goos, func(t *testing.T) {
			name, args, err := browserCommand(test.goos, "http://localhost:8787/")
			if err != nil {
				t.Fatal(err)
			}
			if name != test.name || !reflect.DeepEqual(args, test.args) {
				t.Fatalf("command = %q %#v", name, args)
			}
		})
	}
}
