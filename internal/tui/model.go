package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/mtufekci/munnel/internal/client"
)

// Opts configure the TUI.
type Opts struct {
	ServerAddr   string
	InspectorURL string // "" when inspection is disabled
	Target       string // e.g. "http://127.0.0.1:3000"
}

type row struct {
	when    time.Time
	method  string
	path    string
	status  int
	errored bool
	errMsg  string
	ms      int64
}

type model struct {
	opts   Opts
	events <-chan client.Event
	quit   func()

	status  string // connecting | connected | reconnecting | disconnected | closed
	url     string
	sub     string
	since   time.Time
	message string

	rows     []row // newest first
	requests int
	failures int

	spin   spinner.Model
	width  int
	height int
}

type eventMsg client.Event
type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func newModel(events <-chan client.Event, opts Opts, quit func()) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = stTag
	return model{
		opts:    opts,
		events:  events,
		quit:    quit,
		status:  "connecting",
		message: "connecting to " + opts.ServerAddr + "…",
		spin:    s,
		width:   100,
		height:  24,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(tick(), m.spin.Tick, waitEvent(m.events))
}

func waitEvent(ch <-chan client.Event) tea.Cmd {
	return func() tea.Msg {
		e, ok := <-ch
		if !ok {
			return eventMsg{Kind: client.EventShuttingDown}
		}
		return eventMsg(e)
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			if m.quit != nil {
				m.quit()
			}
			return m, tea.Quit
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tickMsg:
		return m, tick()

	case eventMsg:
		e := client.Event(msg)
		switch e.Kind {
		case client.EventConnecting:
			m.status, m.message = "connecting", e.Message
		case client.EventReconnecting:
			m.status, m.message = "reconnecting", e.Message
		case client.EventConnected:
			m.status, m.url, m.sub, m.since = "connected", e.PublicURL, e.Subdomain, time.Now()
			m.message = ""
		case client.EventDisconnected:
			m.status, m.message = "disconnected", e.Message
		case client.EventShuttingDown:
			m.status = "closed"
			return m, tea.Quit
		case client.EventRequest:
			r := e.Record
			if r != nil {
				m.requests++
				if r.Errored || r.Status >= 400 {
					m.failures++
				}
				m.rows = append([]row{{
					when:    r.Time,
					method:  r.Method,
					path:    r.Path,
					status:  r.Status,
					errored: r.Errored,
					errMsg:  r.Error,
					ms:      r.Duration,
				}}, m.rows...)
				if len(m.rows) > 500 {
					m.rows = m.rows[:500]
				}
				if r.Errored && r.Error != "" {
					m.message = r.Error
				}
			}
		}
		return m, waitEvent(m.events)
	}
	return m, nil
}

func (m model) View() string {
	var b strings.Builder

	// header
	dot := m.spin.View()
	statusText := stWarn.Render(m.status)
	switch m.status {
	case "connected":
		dot = stOK.Render("●")
		statusText = stOK.Render("connected")
	case "closed":
		dot = stDim.Render("●")
	}
	title := stBrand.Render("munnel") + "  " + dot + " " + statusText
	line := fmt.Sprintf("%s  %s", title, stDim.Render("server "+m.opts.ServerAddr))
	if m.status == "connected" && m.url != "" {
		line = fmt.Sprintf("%s  %s %s %s", title,
			stTag.Render(m.url), stDim.Render("→"), stBlue.Render(m.opts.Target))
	}
	b.WriteString(stHeaderBar.Width(m.width).Render(" "+line) + "\n")

	// body: request log
	avail := m.height - lipgloss.Height(line) - 4 // header + footer + margins
	if avail < 3 {
		avail = 3
	}
	if len(m.rows) == 0 {
		if m.status == "connected" {
			b.WriteString("\n  " + stDim.Render("waiting for requests — traffic to your public URL appears here live") + "\n")
		} else {
			b.WriteString("\n  " + stDim.Render(m.message) + "\n")
		}
	} else {
		b.WriteString("\n")
		shown := m.rows
		if len(shown) > avail {
			shown = shown[:avail]
		}
		for _, r := range shown {
			b.WriteString("  " + renderRow(r, m.width-4) + "\n")
		}
	}

	// footer
	stats := stDim.Render(fmt.Sprintf("%d request%s · %d error%s · uptime %s",
		m.requests, plural(m.requests), m.failures, plural(m.failures), m.uptime()))
	links := ""
	if m.opts.InspectorURL != "" {
		links = stDim.Render("inspector ") + stTag.Render(m.opts.InspectorURL) + stDim.Render("  ·  ")
	}
	footer := " " + links + stats + stDim.Render("  ·  q quit")
	b.WriteString("\n" + stFooter.Width(m.width).Render(footer))
	return b.String()
}

func renderRow(r row, width int) string {
	ms := methodStyle(r.method).Render(fmt.Sprintf("%-7s", r.method))
	st := "  — "
	if r.errored {
		st = stErr.Render("ERR")
	} else if r.status > 0 {
		st = statusStyle(r.status, false).Render(fmt.Sprintf("%3d", r.status))
	}
	path := r.path
	maxPath := width - 30
	if maxPath < 12 {
		maxPath = 12
	}
	if len(path) > maxPath {
		path = path[:maxPath-1] + "…"
	}
	lat := stDim.Render(fmt.Sprintf("%5dms", r.ms))
	tm := stDim.Render(r.when.Format("15:04:05"))
	return fmt.Sprintf("%s %s  %s  %s  %s", tm, ms, st, padPath(path, maxPath), lat)
}

func padPath(p string, w int) string {
	if len(p) >= w {
		return p
	}
	return p + strings.Repeat(" ", w-len(p))
}

func (m model) uptime() string {
	if m.since.IsZero() || m.status != "connected" {
		return "—"
	}
	d := time.Since(m.since).Round(time.Second)
	return d.String()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
