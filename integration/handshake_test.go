// Package integration: control handshake framing regression.
//
// The hello and ack are JSON lines, and the bytes after the ack's newline are
// the first mux frame. The handshake used to be parsed with json.Decoder,
// which may stop right after the closing brace and leave the newline in the
// reader handed to the mux: every frame was then read one byte off and the
// tunnel died on its first request ("frame payload 16777216 exceeds max").
// Go 1.27's decoder does that for any hello of exactly 64, 128, 256… bytes,
// which is how TestForwardAuth_LoginFlow's 64-byte hello started failing.
package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/mtufekci/munnel/internal/client"
	"github.com/mtufekci/munnel/internal/proto"
)

func helloLen(t *testing.T, sub, tok string) int {
	t.Helper()
	b, err := json.Marshal(proto.Hello{Type: proto.TypeHello, Version: proto.ControlVersion, Token: tok, Subdomain: sub})
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

func TestHandshake_ExactLengthHellos(t *testing.T) {
	local := localOK()
	defer local.Close()
	srv, _ := startServer(t, "") // open mode ignores the token, so it can pad the hello
	for _, n := range []int{62, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 1024} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			sub := fmt.Sprintf("h%d", n)
			pad := n - helloLen(t, sub, "x") + 1
			if pad < 1 {
				t.Fatalf("cannot build a %d-byte hello", n)
			}
			tok := strings.Repeat("x", pad)
			if got := helloLen(t, sub, tok); got != n {
				t.Fatalf("hello is %d bytes, want %d", got, n)
			}
			ok, _, msg := tryConnect(t, client.Config{
				LocalPort: serverPort(t, local.URL), ServerAddr: srv.ControlListener().Addr().String(),
				Subdomain: sub, Token: tok,
			})
			if !ok {
				t.Fatal(msg)
			}
			for i := 0; i < 3; i++ { // the first frames are the ones a stray byte would corrupt
				if code, _, body := doPublic(t, srv, sub, "GET", "/", nil, nil); code != 200 || string(body) != "ok" {
					t.Fatalf("request %d through a %d-byte-hello tunnel: %d %q", i, n, code, body)
				}
			}
		})
	}
}
