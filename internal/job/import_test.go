package job

import "testing"

func TestImportHostsPlainText(t *testing.T) {
	hosts, err := ImportHosts([]byte("10.0.0.1\n10.0.0.2\n# comment\n\n10.0.0.1\n"), HostDefaults{Port: 2222})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("want 2 hosts (deduped), got %d", len(hosts))
	}
	if hosts[0].ID != "10.0.0.1:2222" || hosts[0].Port != 2222 {
		t.Fatalf("host[0] = %+v", hosts[0])
	}
}

func TestImportHostsCSV(t *testing.T) {
	in := "host,port\n10.0.0.5,2222\n10.0.0.6\n"
	hosts, err := ImportHosts([]byte(in), HostDefaults{})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("want 2 hosts, got %d", len(hosts))
	}
	if hosts[0].Port != 2222 {
		t.Fatalf("csv row parsed wrong: %+v", hosts[0])
	}
	if hosts[1].Port != 22 {
		t.Fatalf("default port not applied: %+v", hosts[1])
	}
}

func TestImportHostsBadPort(t *testing.T) {
	if _, err := ImportHosts([]byte("10.0.0.1,999999\n"), HostDefaults{}); err == nil {
		t.Fatal("invalid port must error")
	}
	if _, err := ImportHosts([]byte("10.0.0.1,abc\n"), HostDefaults{}); err == nil {
		t.Fatal("non-numeric port must error")
	}
}

func TestImportHostsDefaults(t *testing.T) {
	hosts, err := ImportHosts([]byte("h1\n"), HostDefaults{})
	if err != nil {
		t.Fatal(err)
	}
	if hosts[0].Port != 22 {
		t.Fatalf("defaults wrong: %+v", hosts[0])
	}
}

func TestImportHostsRejectsLegacyProfileColumn(t *testing.T) {
	if _, err := ImportHosts([]byte("10.0.0.1,22,agent-only\n"), HostDefaults{}); err == nil {
		t.Fatal("legacy deployment-profile column must be rejected")
	}
}
