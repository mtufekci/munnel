package server

import (
	"html/template"
	"net"
	"strings"
)

var landingTpl = template.Must(template.New("landing").Parse(landingPage))

type landingData struct {
	Domain      string
	ControlAddr string
	Scheme      string
	ControlHost string
	HostDisplay string
}

// landingHTML renders the landing page for the bare domain.
func landingHTML(domain, controlAddr, scheme string) string {
	// Control address shown to users: swap wildcard listeners for the domain.
	ch := controlAddr
	if strings.HasPrefix(ch, ":") {
		ch = domain + ch
	} else if h, p, err := net.SplitHostPort(controlAddr); err == nil && (h == "" || h == "0.0.0.0" || h == "[::]") {
		ch = domain + ":" + p
	}
	var b strings.Builder
	_ = landingTpl.Execute(&b, landingData{
		Domain:      domain,
		ControlAddr: ch,
		Scheme:      scheme,
	})
	return b.String()
}

const landingPage = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>munnel — your localhost, on the public internet</title>
<meta name="description" content="self-hosted tunneling: expose localhost with a binary multiplexer, live terminal TUI, and request inspector.">
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0e0c0d;color:#e8e6e3;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;-webkit-font-smoothing:antialiased}
a{color:#c8b6ff;text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:46rem;margin:0 auto;padding:4rem 1.5rem 5rem}
header{display:flex;align-items:baseline;gap:.75rem}
h1{font-size:2.4rem;margin:0;letter-spacing:-.03em}
.tag{color:#a09a92}
.term{margin:2.5rem 0;background:#161213;border:1px solid #2a2320;border-radius:.75rem;padding:1.25rem 1.5rem;font-size:.9rem;line-height:1.9;box-shadow:0 20px 60px -30px rgba(200,182,255,.25)}
.term .p{color:#5eead4;user-select:none}
.term .c{color:#e8e6e3}
.term .o{color:#a09a92}
.term .u{color:#c8b6ff}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-top:2.5rem}
@media(max-width:640px){.grid{grid-template-columns:1fr}}
.card{border:1px solid #2a2320;border-radius:.75rem;padding:1.25rem;background:#121010}
.card h3{margin:0 0 .4rem;font-size:.95rem;color:#f3ede6}
.card p{margin:0;font-size:.82rem;color:#a09a92;line-height:1.6}
footer{margin-top:3.5rem;color:#57504a;font-size:.78rem}
code{background:#1c1917;padding:.12rem .4rem;border-radius:.3rem;font-size:.85em}
</style>
</head>
<body>
<div class="wrap">
<header><h1>munnel</h1><span class="tag">your localhost, on the public internet</span></header>

<div class="term">
<div><span class="p">$</span> <span class="c">munnel 3000</span></div>
<div class="o">connecting…</div>
<div><span class="o">tunnel live</span> <span class="u">{{.Scheme}}://myapp.{{.Domain}}</span> <span class="o">→ http://127.0.0.1:3000</span></div>
<div class="o">GET  /api/health   200  14ms</div>
<div class="o">POST /webhook      200  31ms</div>
</div>

<div class="grid">
<div class="card"><h3>binary multiplexer</h3><p>hundreds of concurrent streams over one TCP socket with a 9-byte frame header. zero head-of-line surprises.</p></div>
<div class="card"><h3>request inspector + replay</h3><p>live web inspector on <code>localhost:4040</code>. inspect headers and payloads, replay webhooks with one click.</p></div>
<div class="card"><h3>terminal tui</h3><p>live request stream, latency, and tunnel status directly in your shell.</p></div>
<div class="card"><h3>self-hosted</h3><p>your server, your domain, your tokens. no accounts, no rate limits, no third-party cloud.</p></div>
</div>

<div class="term">
<div><span class="p">$</span> <span class="c">munnel 3000 -s myapp --server {{.ControlAddr}}</span></div>
<div class="o"># claim a subdomain on this server</div>
</div>

<footer>powered by munnel · binary multiplexer over a single tcp connection</footer>
</div>
</body>
</html>`
