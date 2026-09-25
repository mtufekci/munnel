package client

import (
	"strings"
	"testing"
)

func TestConfigValidateDefaults(t *testing.T) {
	cases := []struct {
		name        string
		cfg         Config
		wantServer  string
		wantInspect string
		wantErr     string
	}{
		{name: "plaintext default port", cfg: Config{LocalPort: 3000, ServerAddr: "tunnels.example.com"},
			wantServer: "tunnels.example.com:7001", wantInspect: "127.0.0.1:4040"},
		{name: "tls default port", cfg: Config{LocalPort: 3000, ServerAddr: "tunnels.example.com", TLS: true},
			wantServer: "tunnels.example.com:7002", wantInspect: "127.0.0.1:4040"},
		{name: "explicit inspector address kept", cfg: Config{LocalPort: 3000, ServerAddr: "h:1", InspectAddr: ":5050"},
			wantServer: "h:1", wantInspect: ":5050"},
		{name: "pin without tls", cfg: Config{LocalPort: 3000, ServerAddr: "h:1", ServerCertSHA256: strings.Repeat("ab", 32)},
			wantErr: "needs --tls"},
		{name: "short pin", cfg: Config{LocalPort: 3000, ServerAddr: "h:1", TLS: true, ServerCertSHA256: "abcd"},
			wantErr: "64 hex"},
		{name: "pin with colons and upper case", cfg: Config{LocalPort: 3000, ServerAddr: "h:1", TLS: true,
			ServerCertSHA256: strings.TrimSuffix(strings.Repeat("AB:", 32), ":")},
			wantServer: "h:1", wantInspect: "127.0.0.1:4040"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.cfg.ServerAddr != tc.wantServer {
				t.Errorf("server = %q, want %q", tc.cfg.ServerAddr, tc.wantServer)
			}
			if tc.cfg.InspectAddr != tc.wantInspect {
				t.Errorf("inspect addr = %q, want %q", tc.cfg.InspectAddr, tc.wantInspect)
			}
		})
	}
}
