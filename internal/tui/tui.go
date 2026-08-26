// Package tui renders munnel's live terminal dashboard: tunnel status,
// public URL, forwarding target, and a scrolling request log.
package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/mtufekci/munnel/internal/client"
)

// Run starts the interactive terminal dashboard, blocking until the user
// quits (q / ctrl+c / esc) or the event stream closes. onQuit is invoked
// before exiting so the caller can cancel the tunnel.
func Run(events <-chan client.Event, opts Opts, onQuit func()) error {
	p := tea.NewProgram(
		newModel(events, opts, onQuit),
		tea.WithAltScreen(),
	)
	_, err := p.Run()
	return err
}
