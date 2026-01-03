package main

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/charmbracelet/lipgloss"
	humanize "github.com/dustin/go-humanize"
	"github.com/mattn/go-runewidth"
)

var (
	boldRegex   = regexp.MustCompile(`\*\*(.+?)\*\*`)
	italicRegex = regexp.MustCompile(`\*(.+?)\*`)
	codeRegex   = regexp.MustCompile("`([^`]+)`")
)

func simpleMarkdown(text string) string {
	text = boldRegex.ReplaceAllString(text, "\033[1m$1\033[0m")
	text = italicRegex.ReplaceAllString(text, "\033[3m$1\033[0m")
	text = codeRegex.ReplaceAllString(text, "\033[7m$1\033[0m")
	return text
}

func highlightMention(text, username string, style lipgloss.Style) string {
	if username == "" {
		return text
	}
	allowed := "a-zA-Z0-9_-"
	re := regexp.MustCompile("(^|[^" + allowed + "])@" + regexp.QuoteMeta(username) + "([^" + allowed + "]|$)")
	repl := "$1" + style.Render("@"+username) + "$2"
	return re.ReplaceAllString(text, repl)
}

func updateUserList(m *model) {
	var content strings.Builder

	onlineStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	offlineStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	sortedOnline := slices.Sorted(maps.Keys(m.viewChatModel.memberList.onlineMembers))
	sortedOffline := slices.Sorted(maps.Keys(m.viewChatModel.memberList.offlineMembers))

	for _, v := range sortedOnline {
		line := fmt.Sprintf("@%s", m.viewChatModel.memberList.onlineMembers[v].username)
		content.WriteString(onlineStyle.Render(line) + "\n")
	}

	for _, v := range sortedOffline {
		line := fmt.Sprintf("@%s", v)
		content.WriteString(offlineStyle.Render(line) + "\n")
	}

	m.viewChatModel.userListViewport.SetContent(content.String())
}

func updateChannelList(m *model) {

	focused := m.viewChatModel.focus == FocusedBoxChannelList

	channelListText := ""

	currentChannel := lipgloss.NewStyle().Background(lipgloss.Color("240")).Foreground(lipgloss.Color("15"))
	currentChannelFocused := lipgloss.NewStyle().Background(lipgloss.Color("84")).Foreground(lipgloss.Color("240"))
	otherChannel := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	otherChannelUnread := lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	notificationCount := lipgloss.NewStyle().Foreground(lipgloss.Color("87"))
	for _, v := range m.viewChatModel.channels {
		if m.viewChatModel.channels[m.viewChatModel.currentChannel] == v {
			if focused {
				channelListText += currentChannelFocused.Render(fmt.Sprintf("# %-18s", v.channelId)) + "\n"
			} else {
				channelListText += currentChannel.Render(fmt.Sprintf("# %-18s", v.channelId)) + "\n"
			}
		} else {
			if v.unread > 0 {
				if v.unread > 9 {
					channelListText += otherChannelUnread.Render(fmt.Sprintf("# %-13s  ", v.channelId)) +
						notificationCount.Render("9+ ") + "\n"
				} else {
					channelListText += otherChannelUnread.Render(fmt.Sprintf("# %-13s   ", v.channelId)) +
						notificationCount.Render(fmt.Sprintf("%d  ", v.unread)) + "\n"
				}
			} else {
				channelListText += otherChannel.Render(fmt.Sprintf("# %-18s", v.channelId)) + "\n"
			}
		}
	}

	if m.viewChatModel.currentChannel < len(m.viewChatModel.channels) {
		channel, ok := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
		if ok {
			m.viewChatModel.channelBanner = channel.Banner
		}
	}

	m.viewChatModel.channelListViewport.SetContent(channelListText)
}

func updateChatLines(m *model) {
	messageText := ""

	botMsg := lipgloss.NewStyle().Background(lipgloss.Color("63")).Foreground(lipgloss.Color("15")).Render(" BOT ")
	adminMsg := lipgloss.NewStyle().Foreground(lipgloss.Color("78")).Render("(admin)")

	botSenderStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("121"))

	for i, v := range m.viewChatModel.messages {
		newMessage := ""
		// timestamp := m.viewChatModel.dateStyle.Render(fmt.Sprintf(" %02d:%02d UTC ", v.time.Hour(), v.time.Minute()))
		timestamp := v.time.In(m.viewChatModel.timezone)
		timeRendered := m.viewChatModel.dateStyle.Render(fmt.Sprintf(" %02d:%02d ", timestamp.Hour(), timestamp.Minute()))

		now := time.Now()
		nowDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		timestampDate := time.Date(timestamp.Year(), timestamp.Month(), timestamp.Day(), 0, 0, 0, 0, timestamp.Location())
		daysDiff := int(nowDate.Sub(timestampDate).Hours() / 24)

		// More than 1 calendar day ago
		if daysDiff > 1 {
			timeRendered = m.viewChatModel.dateStyle.Render(fmt.Sprintf(" %02d/%02d/%04d, %02d:%02d ", timestamp.Day(), timestamp.Month(), timestamp.Year(), timestamp.Hour(), timestamp.Minute()))
		} else if daysDiff == 1 {
			// Exactly 1 calendar day ago
			timeRendered = m.viewChatModel.dateStyle.Render(fmt.Sprintf(" Yesterday at %02d:%02d ", timestamp.Hour(), timestamp.Minute()))
		}

		if i == 0 || m.viewChatModel.messages[i-1].sender != v.sender || m.viewChatModel.messages[i].time.UnixMilli()-m.viewChatModel.messages[i-1].time.UnixMilli() > 300000 {
			if v.sender == m.app.config.BotUsername {
				newMessage += "\n" + botSenderStyle.Render(v.sender) + " " + botMsg + "" + timeRendered + "\n"
			} else if v.sender == m.app.config.AdminUsername {
				newMessage += "\n" + m.viewChatModel.senderStyle.Render(v.sender) + " " + adminMsg + "" + timeRendered + "\n"
			} else {
				newMessage += "\n" + m.viewChatModel.senderStyle.Render(v.sender) + timeRendered + "\n"
			}
		}
		mentionStyle := lipgloss.NewStyle().Background(lipgloss.Color("63")).Foreground(lipgloss.Color("255"))
		addedMentions := highlightMention(v.text, m.viewChatModel.id, mentionStyle)
		newMessage += simpleMarkdown(addedMentions) + "\n"
		messageText += newMessage
	}

	content := lipgloss.NewStyle().
		Width(m.viewChatModel.messageHistoryViewport.Width).
		Render(messageText)

	m.viewChatModel.messageHistoryViewport.SetContent(content)
	if m.viewChatModel.focus != FocusedBoxChatHistory {
		m.viewChatModel.messageHistoryViewport.GotoBottom()
	}
}

func FormatBanner(input string) string {
	const width = 20
	const height = 10

	input = strings.ReplaceAll(input, "\r\n", "\n")
	originalLines := strings.Split(input, "\n")

	var finalRows []string

	for _, line := range originalLines {
		runes := []rune(line)
		if len(runes) == 0 {
			finalRows = append(finalRows, "")
			continue
		}
		for len(runes) > 0 {
			if len(finalRows) >= height {
				break
			}

			chunkSize := width
			if len(runes) < width {
				chunkSize = len(runes)
			}
			chunk := make([]rune, chunkSize)
			for i := 0; i < chunkSize; i++ {
				if unicode.IsControl(runes[i]) {
					chunk[i] = ' '
				} else {
					chunk[i] = runes[i]
				}
			}

			finalRows = append(finalRows, string(chunk))
			runes = runes[chunkSize:]
		}
	}
	var sb strings.Builder
	for i := 0; i < height; i++ {
		var content string
		var contentWidth int

		if i < len(finalRows) {
			content = finalRows[i]
			contentWidth = len([]rune(content))
		}
		sb.WriteString(content)
		padding := width - contentWidth
		if padding > 0 {
			sb.WriteString(strings.Repeat(" ", padding))
		}
		if i < height-1 {
			sb.WriteRune('\n')
		}
	}

	return sb.String()
}

func getFullUserListBar(m model) string {

	banner := FormatBanner(m.viewChatModel.channelBanner)

	bannerStyle := lipgloss.NewStyle().Background(lipgloss.Color("235")).Foreground(lipgloss.Color("15"))

	return bannerStyle.Render(banner) + "\n" + fmt.Sprintf("%s users online\n", humanize.Comma(int64(len(m.viewChatModel.memberList.onlineMembers)))) +
		m.viewChatModel.userListViewport.View()
}

func RegistrationBox() BoxWithLabel {

	return BoxWithLabel{
		BoxStyleFocused: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("121")),
		BoxStyleUnfocused: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240")),
		LabelStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Bold(true).
			PaddingTop(0).
			PaddingBottom(0).
			PaddingLeft(0).
			PaddingRight(0),
	}
}

func renderChatHistoryWithSuggestions(m model) string {
	view := m.viewChatModel.messageHistoryViewport.View()
	if len(m.viewChatModel.commandSuggestions) == 0 {
		return view
	}

	lines := strings.Split(view, "\n")
	if len(lines) == 0 {
		return view
	}

	start := m.viewChatModel.commandSuggestionScroll
	if start < 0 {
		start = 0
	}
	if start >= len(m.viewChatModel.commandSuggestions) {
		start = max(0, len(m.viewChatModel.commandSuggestions)-1)
	}
	end := min(start+5, len(m.viewChatModel.commandSuggestions))
	visible := m.viewChatModel.commandSuggestions[start:end]
	if len(visible) == 0 {
		return view
	}

	width := m.viewChatModel.messageHistoryViewport.Width

	tabReserved := 4 // "TAB" plus leading space
	mainTotal := max(0, width-tabReserved)

	cmdColWidth := min(28, mainTotal/2)
	cmdNormal := lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Width(cmdColWidth).MaxWidth(cmdColWidth)
	cmdSelected := cmdNormal.Copy().Foreground(lipgloss.Color("15")).Background(lipgloss.Color("63"))

	descWidth := max(0, mainTotal-cmdColWidth)
	descNormal := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Width(descWidth).MaxWidth(descWidth)
	descSelected := descNormal.Copy().Foreground(lipgloss.Color("250")).Background(lipgloss.Color("63"))

	overlayCount := min(len(visible), len(lines))
	overlayStart := len(lines) - overlayCount

	for i := 0; i < overlayCount; i++ {
		idx := start + i
		prefix := "  "
		cmdStyle := cmdNormal
		descStyle := descNormal
		if idx == m.viewChatModel.commandSuggestionIndex {
			prefix = "> "
			cmdStyle = cmdSelected
			descStyle = descSelected
		}

		cmdText := runewidth.Truncate(prefix+visible[i].Display, cmdColWidth, "…")
		cmdText = runewidth.FillRight(cmdText, cmdColWidth)

		tabText := runewidth.FillRight("", tabReserved)
		tabStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
		if idx == m.viewChatModel.commandSuggestionIndex {
			tabText = runewidth.FillRight(" TAB", tabReserved)
			tabStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Background(lipgloss.Color("63"))
		}

		descText := ""
		if descWidth > 0 {
			descText = runewidth.Truncate(" "+visible[i].Desc, descWidth, "…")
			descText = runewidth.FillRight(descText, descWidth)
		}

		lines[overlayStart+i] = cmdStyle.Render(cmdText) + descStyle.Render(descText) + tabStyle.Render(tabText)
	}

	return strings.Join(lines, "\n")
}

func (b BoxWithLabel) Render(label, content string, width int, focused bool) string {
	var (
		// Query the box style for some of its border properties so we can
		// essentially take the top border apart and put it around the label.
		border          lipgloss.Border        = b.BoxStyleUnfocused.GetBorderStyle()
		topBorderStyler func(...string) string = lipgloss.NewStyle().Foreground(b.BoxStyleUnfocused.GetBorderTopForeground()).Render
		topLeft         string                 = topBorderStyler(border.TopLeft)
		topRight        string                 = topBorderStyler(border.TopRight)

		renderedLabel string = b.LabelStyle.Render(label)
	)

	if focused {
		border = b.BoxStyleFocused.GetBorderStyle()
		topBorderStyler = lipgloss.NewStyle().Foreground(b.BoxStyleFocused.GetBorderTopForeground()).Render
		topLeft = topBorderStyler(border.TopLeft)
		topRight = topBorderStyler(border.TopRight)
		renderedLabel = b.LabelStyle.Foreground(lipgloss.Color("121")).Render(label)
	}

	// Render top row with the label
	borderWidth := b.BoxStyleFocused.GetHorizontalBorderSize()
	cellsShort := max(0, width+borderWidth-lipgloss.Width(topLeft+topRight+renderedLabel))
	gap := strings.Repeat(border.Top, cellsShort)
	top := topLeft + renderedLabel + topBorderStyler(gap) + topRight

	// Render the rest of the box
	bottom := b.BoxStyleUnfocused.Copy().
		BorderTop(false).
		Width(width).
		Render(content)

	if focused {
		bottom = b.BoxStyleFocused.Copy().
			BorderTop(false).
			Width(width).
			Render(content)
	}

	// Stack the pieces
	return top + "\n" + bottom
}

func (m model) View() string {
	FocusedStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("121"))
	UnfocusedStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240"))
	switch m.viewMode {
	case viewChat:
		titleRegBox := RegistrationBox()

		channel := "..."
		if m.viewChatModel.currentChannel < len(m.viewChatModel.channels) {
			channel = m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId
		}
		inputBox := func() string {
			if m.viewChatModel.focus == FocusedBoxChatInput {
				return FocusedStyle.Render(m.viewChatModel.textarea.View())
			}
			return UnfocusedStyle.Render(m.viewChatModel.textarea.View())
		}()

		historyWithOverlay := renderChatHistoryWithSuggestions(m)

		chatSection := fmt.Sprintf(
			"%s\n%s",
			titleRegBox.Render(
				fmt.Sprintf("#%s (@%s)", channel, m.viewChatModel.id),
				historyWithOverlay,
				m.viewChatModel.messageHistoryViewport.Width+1,
				m.viewChatModel.focus == FocusedBoxChatHistory),
			inputBox,
		)

		channelList := func() string {
			if m.viewChatModel.sidebarsEnabled {
				return UnfocusedStyle.Render(m.viewChatModel.channelListViewport.View())
			} else {
				return ""
			}
		}()

		userList := func() string {
			if m.viewChatModel.sidebarsEnabled {
				if m.viewChatModel.focus == FocusedBoxUserList {
					return FocusedStyle.Render(getFullUserListBar(m))
				} else {
					return UnfocusedStyle.Render(getFullUserListBar(m))
				}
			} else {
				return ""
			}
		}()

		return m.viewChatModel.alert.Render(
			lipgloss.JoinHorizontal(lipgloss.Bottom, channelList, chatSection, userList))
	case viewRegistration:

		usernameBox := m.viewRegistrationModel.usernameInput.View()
		passwordBox := m.viewRegistrationModel.passwordInput.View()
		passwordConfirmBox := m.viewRegistrationModel.passwordConfirmInput.View()
		createBox := m.viewRegistrationModel.confirmViewport.View()

		createUnfocused := lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240")).
			Foreground(lipgloss.Color("240"))
		createFocused := lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("121")).
			Foreground(lipgloss.Color("121"))

		titleRegBox := RegistrationBox()
		return m.viewChatModel.alert.Render(lipgloss.JoinVertical(lipgloss.Right,
			m.app.config.RegistrationHeader,
			titleRegBox.Render("username", usernameBox, 26, m.viewRegistrationModel.FocusedBox == RegistrationUsernameFocused),
			titleRegBox.Render("password", passwordBox, 26, m.viewRegistrationModel.FocusedBox == RegistrationPasswordFocused),
			titleRegBox.Render("confirm", passwordConfirmBox, 26, m.viewRegistrationModel.FocusedBox == RegistrationPasswordConfirmFocused),
			func() string {
				if m.viewRegistrationModel.FocusedBox == RegistrationContinueButtonFocused {
					return createFocused.Render(createBox)
				} else {
					return createUnfocused.Render(createBox)
				}
			}(),
			lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render(m.viewRegistrationModel.feedbackViewport.View()),
			lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("Use arrow keys/tab+enter  "),
		))

	default:
		return "Error!"

	}
}
