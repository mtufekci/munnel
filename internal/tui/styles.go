package tui

import "github.com/charmbracelet/lipgloss"

// Palette shared by the TUI and the (web) inspector.
var (
	cAccent = lipgloss.Color("#C8B6FF")
	cDim    = lipgloss.Color("#57504A")
	cText   = lipgloss.Color("#E8E6E3")
	cBg     = lipgloss.Color("#0E0C0D")
	cGreen  = lipgloss.Color("#5EEAD4")
	cYellow = lipgloss.Color("#FACC15")
	cRed    = lipgloss.Color("#F87171")
	cBlue   = lipgloss.Color("#93C5FD")
)

var (
	stBrand = lipgloss.NewStyle().Bold(true).Foreground(cText)
	stTag   = lipgloss.NewStyle().Foreground(cAccent)
	stDim   = lipgloss.NewStyle().Foreground(cDim)
	stOK    = lipgloss.NewStyle().Foreground(cGreen)
	stWarn  = lipgloss.NewStyle().Foreground(cYellow)
	stErr   = lipgloss.NewStyle().Foreground(cRed)
	stBlue  = lipgloss.NewStyle().Foreground(cBlue)

	stHeaderBar = lipgloss.NewStyle().
			Foreground(cText).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(lipgloss.Color("#241F1C"))

	stFooter = lipgloss.NewStyle().
			Foreground(cDim).
			BorderStyle(lipgloss.NormalBorder()).
			BorderTop(true).
			BorderForeground(lipgloss.Color("#241F1C"))

	stRowSel = lipgloss.NewStyle().Background(lipgloss.Color("#1D1826"))
)

func methodStyle(m string) lipgloss.Style {
	switch m {
	case "GET":
		return stOK.Bold(true)
	case "POST":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#A7F3D0"))
	case "PUT":
		return stBlue.Bold(true)
	case "PATCH":
		return stTag.Bold(true)
	case "DELETE":
		return stErr.Bold(true)
	}
	return lipgloss.NewStyle().Foreground(cText)
}

func statusStyle(status int, errored bool) lipgloss.Style {
	switch {
	case errored || status == 0:
		return stErr
	case status >= 500:
		return stErr
	case status >= 400:
		return stWarn
	case status >= 300:
		return stBlue
	default:
		return stOK
	}
}
