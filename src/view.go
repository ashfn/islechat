package main

import (
	"strings"
	"unicode"
	humanize "github.com/dustin/go-humanize"
	"github.com/charmbracelet/lipgloss"
	"fmt"
)

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

	return bannerStyle.Render(banner)+ "\n"+ fmt.Sprintf("%s users online\n", humanize.Comma(int64(len(m.viewChatModel.memberList.onlineMembers)))) + 
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

func (b BoxWithLabel) Render(label, content string, width int, focused bool) string {
	var (
		// Query the box style for some of its border properties so we can
		// essentially take the top border apart and put it around the label.
		border          lipgloss.Border     = b.BoxStyleUnfocused.GetBorderStyle()
		topBorderStyler func(...string) string = lipgloss.NewStyle().Foreground(b.BoxStyleUnfocused.GetBorderTopForeground()).Render
		topLeft         string              = topBorderStyler(border.TopLeft)
		topRight        string              = topBorderStyler(border.TopRight)

		renderedLabel string = b.LabelStyle.Render(label)
	)

	if(focused){
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
	
	if(focused){
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
	switch(m.viewMode){
		case viewChat:
			chatSection := fmt.Sprintf(
				"%s\n%s",
				func() string {
					if m.viewChatModel.focus==FocusedBoxChatHistory {
						return FocusedStyle.PaddingLeft(1).Render(m.viewChatModel.messageHistoryViewport.View())
					} else {
						return UnfocusedStyle.PaddingLeft(1).Render(m.viewChatModel.messageHistoryViewport.View())
					}
				}(),
				func() string {
					if m.viewChatModel.focus==FocusedBoxChatInput {
						return FocusedStyle.Render(m.viewChatModel.textarea.View())
					} else {
						return UnfocusedStyle.Render(m.viewChatModel.textarea.View())
					}
				}(),
			);

			channelList := func() string {
				return UnfocusedStyle.Render(m.viewChatModel.channelListViewport.View())
			}()

			userList := func() string {
					if m.viewChatModel.focus==FocusedBoxUserList {
						return FocusedStyle.Render(getFullUserListBar(m))
					} else {
						return UnfocusedStyle.Render(getFullUserListBar(m))
					}
				}();
			
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
				titleRegBox.Render("username", usernameBox, 26, m.viewRegistrationModel.FocusedBox==RegistrationUsernameFocused),
				titleRegBox.Render("password", passwordBox, 26, m.viewRegistrationModel.FocusedBox==RegistrationPasswordFocused),
				titleRegBox.Render("confirm", passwordConfirmBox, 26, m.viewRegistrationModel.FocusedBox==RegistrationPasswordConfirmFocused),
				func() string {
					if m.viewRegistrationModel.FocusedBox==RegistrationContinueButtonFocused {
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