package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"slices"

	// "slices"
	"strings"

	// "strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/activeterm"
	"github.com/charmbracelet/wish/bubbletea"
	"github.com/charmbracelet/wish/logging"
	"github.com/muesli/termenv"

	// "github.com/charmbracelet/glamour"

	humanize "github.com/dustin/go-humanize"

	"regexp"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"golang.org/x/crypto/bcrypt"
)

const (
	host = "localhost"
	port = "22223"
)

// app contains a wish server and the list of running programs.
type app struct {
	*ssh.Server
    progs map[string]*tea.Program
	db *gorm.DB 
	messages map[string]*[]chatMsg

	// Only stores in logged in users to prevent the same user logging in from multiple shells 
	// Map from username -> session
	// will also include 
	sessions map[string]*userSession

	// Map from channel ids to channel object
	channels map[string]*Channel
	channelOnlineMembers map[string]*[]*userSession
}

type User struct {
	gorm.Model
	ID string `gorm:"primaryKey"`
	Password string
	Channels []Channel `gorm:"many2many:user_channels;"`
}

type Message struct {
	gorm.Model
	SenderID  string    `gorm:"index"`
    Sender    User      `gorm:"foreignKey:SenderID"`
    Content   string    `gorm:"type:text"`
    ChannelID string    `gorm:"index"`
    Channel   Channel   `gorm:"foreignKey:ChannelID"`
	Time time.Time
}

type Invite struct {
	gorm.Model
	User User
	UserID string
	Channel Channel
	ChannelID string
}

type Channel struct {
	ID string
	Owner User
	OwnerID string
	Banner string
	Public bool
	ReadOnly bool
}




// A session for a LOGGED IN user
type userSession struct {

	prog *tea.Program
	// Used so we dont distribute the message to absolutely everyone
	username string
	currentChannelId string

}

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
    return string(bytes), err
}

// VerifyPassword verifies if the given password matches the stored hash.
func VerifyPassword(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

// send dispatches a message to all running programs.
func (a *app) sendMessage(msg chatMsg) {

	err := gorm.G[Message](a.db).Create(context.Background(), &Message{
		SenderID: msg.sender,
		Content: msg.text,
		Time: msg.time,
		ChannelID: msg.channel,
	})
	*a.messages[msg.channel] = append(*a.messages[msg.channel], msg)
	if(err==nil){
		for _, p := range a.progs {
			go p.Send(msg)
		}
	}else{
		// Handle error or some shit
	}
}

func (a *app) updateUserlists() {
	users := make([]string, len(a.progs))
	i := 0
	for k := range a.progs {
		users[i] = k
		i++
	}
	for _, p := range a.progs {
		go p.Send(userlist(users))
	}
}

func VPDisableScrolling(v *viewport.Model) {
	v.KeyMap.Up.SetEnabled(false)
	v.KeyMap.Down.SetEnabled(false)
	v.KeyMap.HalfPageUp.SetEnabled(false)
	v.KeyMap.HalfPageDown.SetEnabled(false)
	v.KeyMap.PageUp.SetEnabled(false)
	v.KeyMap.PageDown.SetEnabled(false)
}

func VPEnableScrolling(v *viewport.Model) {
	v.KeyMap.Up.SetEnabled(true)
	v.KeyMap.Down.SetEnabled(true)
	v.KeyMap.HalfPageUp.SetEnabled(true)
	v.KeyMap.HalfPageDown.SetEnabled(true)
	v.KeyMap.PageUp.SetEnabled(true)
	v.KeyMap.PageDown.SetEnabled(true)
}

func newApp(db *gorm.DB) *app {
	a := new(app)
	a.db = db



	// r, err := glamour.NewTermRenderer(
	// 	// glamour.WithStylePath("theme.json"),
	// 	glamour.WithStandardStyle("dark"),
	// )

	// if err != nil {
	// 	panic(err)
	// }

	// a.glamourRenderer = r

	a.messages = make(map[string]*[]chatMsg)
	a.channels = make(map[string]*Channel)

	channels, err := gorm.G[Channel](db).Find(context.Background())

	for _,v := range channels{
		temp := make([]chatMsg, 0)
		a.messages[v.ID] = &temp
		a.channels[v.ID] = &v
	}

	var msgs []Message
	db.Raw(`
		SELECT *
		FROM (
			SELECT *,
				ROW_NUMBER() OVER (PARTITION BY channel_id ORDER BY time DESC) as rn
			FROM messages
		) sub
		WHERE rn <= 50
		ORDER BY channel_id, time DESC
	`).Scan(&msgs)

	slices.Reverse(msgs)

	for _,v := range msgs {
		*a.messages[v.ChannelID] = append(*a.messages[v.ChannelID], chatMsg{
			sender: v.SenderID,
			text: v.Content,
			time: v.Time,
			channel: v.ChannelID,
		})
	}

	a.progs = make(map[string]*tea.Program)
	s, err := wish.NewServer(
		wish.WithAddress(net.JoinHostPort(host, port)),
		wish.WithHostKeyPath(".ssh/id_ed25519"),
		wish.WithPasswordAuth(func(ctx ssh.Context, password string) bool {
			username := ctx.User()

			user, err := gorm.G[User](db).
				Where("ID = ?", username).
				First(context.Background())

			if(err==nil){
				// We found the user
				// check password
				if(VerifyPassword(password, user.Password)){
					// Password was correct, we are good to go
					ctx.SetValue("auth_status", "ok")
					return true
				}else{
					// We don't know if they got the password wrong or were trying to make an account with that username
					// So we just send them to the register page
					ctx.SetValue("auth_status", "fail")
					ctx.SetValue("password", password)
					return true
				}
			}else{
				// Account doesnt exist so we will send them to the register page with the details they entered
				// Pre filled 
				ctx.SetValue("auth_status", "fail")
				ctx.SetValue("password", password)
				return true
			}

		}),
		wish.WithMiddleware(
			func(next ssh.Handler) ssh.Handler {
				return func(sess ssh.Session) {
					// sess.Context().
				}
			},
			bubbletea.MiddlewareWithProgramHandler(a.ProgramHandler, termenv.ANSI256),
			activeterm.Middleware(),
			logging.Middleware(),
		),
	)
	if err != nil {
		log.Error("Could not start server", "error", err)
	}

	a.Server = s
	return a
}

func (a *app) Start() {
	var err error
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	log.Info("Starting SSH server", "host", host, "port", port)
	go func() {
		if err = a.ListenAndServe(); err != nil {
			log.Error("Could not start server", "error", err)
			done <- nil
		}
	}()

	<-done
	log.Info("Stopping SSH server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer func() { cancel() }()
	if err := a.Shutdown(ctx); err != nil {
		log.Error("Could not stop server", "error", err)
	}
}

func (a *app) ProgramHandler(s ssh.Session) *tea.Program {



	model := initialModel(a, 120, 30, s)
	model.app = a
	model.viewChatModel.id = s.User()

	updateChatLines(&model)
	updateChannelList(&model)
	updateRegistrationTextFocuses(&model)

	//tea.WithMouseAllMotion()
	// tea.WithMouseCellMotion()
    opts := append([]tea.ProgramOption{}, bubbletea.MakeOptions(s)...)
    p := tea.NewProgram(model, opts...)
	a.progs[s.User()] = p
	a.updateUserlists()

	return p
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&Message{}, &Channel{}, &User{}, &Invite{})


	db.Clauses(clause.OnConflict{DoNothing: true}).Create(&[]Channel{
		{ID: "global"},}) 

	// db.AutoMigrate(&Product{})

	app := newApp(db)


	app.Start()
}

type (
	errMsg  error
	chatMsg struct {
		sender   string
		text string
		time time.Time
		channel string
	}
	userlist []string
)

type FocusedBox int

const (
	FocusedBoxChatInput FocusedBox = iota
	FocusedBoxChatHistory
	FocusedBoxUserList
	FocusedBoxChannelList
	FocusedTypesLength = 4
)

type RegistrationFocusedBox int

const (
	RegistrationUsernameFocused RegistrationFocusedBox = iota
	RegistrationPasswordFocused
	RegistrationPasswordConfirmFocused
	RegistrationContinueButtonFocused
	RegistrationFocusedTypesLength = 4
)

type viewMode int

const (
    viewRegistration viewMode = iota
    viewChat
)

type userChannelState struct {
	channelId string
	unread int
}


type viewRegistrationModel struct {
	FocusedBox RegistrationFocusedBox
	usernameInput textinput.Model
	passwordInput textinput.Model
	passwordConfirmInput textinput.Model
	confirmViewport viewport.Model
	feedbackViewport viewport.Model
}

type viewChatModel struct {
	messageHistoryViewport    viewport.Model
	userListViewport viewport.Model
	channelListViewport viewport.Model
	messages    []chatMsg
	channels []userChannelState
	currentChannel int
	id          string
	textarea    textarea.Model
	senderStyle lipgloss.Style
	dateStyle lipgloss.Style
	err         error
	users userlist
	focus FocusedBox
	windowHeight int
	windowWidth int
}

type model struct {
	*app

	viewMode viewMode
	viewChatModel viewChatModel
	viewRegistrationModel viewRegistrationModel
}

type channelList []userChannelState

func getNewChannelListViewport(a *app, width int, height int, focus FocusedBox) viewport.Model {
	cvp := viewport.New(20, max(0,height-2))

	if(focus==FocusedBoxChannelList){
		VPEnableScrolling(&cvp)
	}else{
		VPDisableScrolling(&cvp)
	}
	return cvp
}

func getNewUserListViewport(a *app, width int, height int, focus FocusedBox) viewport.Model {
	uvp := viewport.New(20, max(0,height-12))
	if(focus==FocusedBoxUserList){
		VPEnableScrolling(&uvp)
	}else{
		VPDisableScrolling(&uvp)
	}
	return uvp
}

func getNewMessageHistoryViewport(a *app, width int, height int, focus FocusedBox) viewport.Model {
	mvp := viewport.New(max(0,width-48), max(0,height-7))
	if(focus==FocusedBoxChatHistory){
		VPEnableScrolling(&mvp)
	}else{
		VPDisableScrolling(&mvp)
	}
	return mvp
}
func centerString(str string, width int) string {
	spaces := int(float64(width-len(str)) / 2)
	return strings.Repeat(" ", spaces) + str + strings.Repeat(" ", width-(spaces+len(str)))
}
func initialModel(a *app, width int, height int, sess ssh.Session) model {

	ta := textarea.New()
	ta.Placeholder = "Send a message..."
	ta.Focus()
	ta.Cursor.SetMode(cursor.CursorStatic)

	ta.Prompt = ""
	ta.CharLimit = 2000

	ta.SetWidth(width-47)
	ta.SetHeight(3)

	// Remove cursor line styling
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()

	ta.ShowLineNumbers = false

	mvp := getNewMessageHistoryViewport(a, width, height, FocusedBoxChatInput)
	uvp := getNewUserListViewport(a, width, height, FocusedBoxChatInput)
	cvp := getNewChannelListViewport(a, width, height, FocusedBoxChatInput)

	ta.KeyMap.InsertNewline.SetEnabled(false)

	previousMsgs := *a.messages["global"]

	// previousMsgs := []chatMsg{}
	// msgs,err := gorm.G[Message](a.db).
	// 	Order("time DESC").   // newest first
	// 	Limit(100).            // last 30 rows
	// 	Find(context.Background())

	// if(err==nil){
	// 	for _,v := range msgs{
	// 		previousMsgs = append(previousMsgs, chatMsg{
	// 			sender: v.Sender,
	// 			text: v.Content,
	// 			time: v.Time,
	// 		})
	// 	}
	// }

	// slices.Reverse(previousMsgs)

	channelList := make([]userChannelState, 0)

	for c, _ := range a.messages {
		channelList = append(channelList, userChannelState{
			channelId: c,
			unread: 0,
		})
	}

	// Registration parts

	usernameInput := textinput.New()
	usernameInput.Placeholder = "your_username"
	usernameInput.CharLimit = 10
	usernameInput.Width = 24
	usernameInput.Prompt="@"

	passwordInput := textinput.New()
	passwordInput.Placeholder = "Enter a password"
	passwordInput.CharLimit = 25
	passwordInput.Width = 25
	passwordInput.EchoMode=textinput.EchoPassword
	passwordInput.Prompt=""

	
	passwordConfirmInput := textinput.New()
	passwordConfirmInput.Placeholder = ""
	passwordConfirmInput.CharLimit = 25
	passwordConfirmInput.Width = 25
	passwordConfirmInput.EchoMode=textinput.EchoPassword
	passwordConfirmInput.Prompt=""

	confirmViewport := viewport.New(26,1)
	confirmViewport.SetContent(centerString("Create account", 26))
	
	feedbackViewport := viewport.New(27,1)
	feedbackViewport.SetContent("")

	if(sess.Context().Value("auth_status")=="ok"){
		return model{

			viewMode: viewChat,

			viewChatModel: viewChatModel{
				id: sess.User(),
				textarea:    ta,
				messages:    previousMsgs,
				messageHistoryViewport:    mvp,
				userListViewport: uvp,
				channelListViewport: cvp,
				senderStyle: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5")),
				dateStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("238")),
				currentChannel: 0,
				channels: channelList,
				err:         nil,
				users: make([]string, 0),
				focus: FocusedBoxChatInput,	
			},
			viewRegistrationModel: viewRegistrationModel{
				usernameInput: usernameInput,
				passwordInput: passwordInput,
				passwordConfirmInput: passwordConfirmInput,
				confirmViewport: confirmViewport,
			},
		}
	}else{
		usernameInput.SetValue(sess.User())
		pass,ok := sess.Context().Value("password").(string)
		if(ok){
			passwordInput.SetValue(pass)
		}

		return model{

			viewMode: viewRegistration,

			viewChatModel: viewChatModel{
				textarea:    ta,
				messages:    previousMsgs,
				messageHistoryViewport:    mvp,
				userListViewport: uvp,
				channelListViewport: cvp,
				senderStyle: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5")),
				dateStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("238")),
				currentChannel: 0,
				channels: channelList,
				err:         nil,
				users: make([]string, 0),
				focus: FocusedBoxChatInput,
			},
			viewRegistrationModel: viewRegistrationModel{
				FocusedBox: RegistrationPasswordConfirmFocused,
				usernameInput: usernameInput,
				passwordInput: passwordInput,
				passwordConfirmInput: passwordConfirmInput,
				confirmViewport: confirmViewport,
				feedbackViewport: feedbackViewport,
			},
		}
	}


}

func (m model) Init() tea.Cmd {
	// return textarea.Blink
	return nil
}
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

func updateUserList(m *model){
	userListText := ""
	for _, v := range m.viewChatModel.users {
		userListText+=fmt.Sprintf("@%s", v)+"\n"
	}
	m.viewChatModel.userListViewport.SetContent(userListText)
}

func updateChannelList(m *model){

	focused := m.viewChatModel.focus == FocusedBoxChannelList

	channelListText := ""

	currentChannel := lipgloss.NewStyle().Background(lipgloss.Color("240")).Foreground(lipgloss.Color("15"))
	currentChannelFocused := lipgloss.NewStyle().Background(lipgloss.Color("84")).Foreground(lipgloss.Color("240"))
	otherChannel := lipgloss.NewStyle().Foreground(lipgloss.Color("15"))

	for _, v := range m.viewChatModel.channels {
		if(m.viewChatModel.channels[m.viewChatModel.currentChannel]==v){
			if(focused){
				channelListText+=currentChannelFocused.Render(fmt.Sprintf("# %-18s", v.channelId))+"\n"
			}else{
				channelListText+=currentChannel.Render(fmt.Sprintf("# %-18s", v.channelId))+"\n"
			}
		}else{
			channelListText+=otherChannel.Render(fmt.Sprintf("# %-18s", v.channelId))+"\n"
		}
	}

	m.viewChatModel.channelListViewport.SetContent(channelListText)
}

func updateChatLines(m *model) {
	messageText := ""

	botMsg := lipgloss.NewStyle().Background(lipgloss.Color("63")).Foreground(lipgloss.Color("15")).Render(" BOT ")
	botSenderStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("121"))

	for i, v := range m.viewChatModel.messages {
		newMessage := ""
		if(i==0 || m.viewChatModel.messages[i-1].sender!=v.sender){
			if(v.sender=="islebot"){
				newMessage+="\n"+botSenderStyle.Render(v.sender)+" "+botMsg+""+m.viewChatModel.dateStyle.Render(fmt.Sprintf(" %02d:%02d ", v.time.Hour(), v.time.Minute()))+"\n"
			}else{
				newMessage+="\n"+m.viewChatModel.senderStyle.Render(v.sender)+m.viewChatModel.dateStyle.Render(fmt.Sprintf(" %02d:%02d ", v.time.Hour(), v.time.Minute()))+"\n"
			}
		}
		// // out, err := m.app.glamourRenderer.Render(v.text)
		// if err != nil {
		// 	newMessage+=v.text
		// 	panic(err)
		// }else{
		// 	newMessage+=out
		// }
		newMessage+=simpleMarkdown(v.text)+"\n"
		messageText+=newMessage
	}

	content := lipgloss.NewStyle().
		Width(m.viewChatModel.messageHistoryViewport.Width).
		Render(messageText)

	m.viewChatModel.messageHistoryViewport.SetContent(content)
	if(m.viewChatModel.focus!=FocusedBoxChatHistory){
		m.viewChatModel.messageHistoryViewport.GotoBottom()
	}
}

func reloadMessagesChannelSwitch(m *model){
	m.viewChatModel.messages = *m.app.messages[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	updateChatLines(m)
}

func updateRegistrationTextFocuses(m *model){
	switch m.viewRegistrationModel.FocusedBox {
		case RegistrationUsernameFocused:
			m.viewRegistrationModel.usernameInput.Focus()
			m.viewRegistrationModel.passwordInput.Blur()
			m.viewRegistrationModel.passwordConfirmInput.Blur()
		case RegistrationPasswordFocused:
			m.viewRegistrationModel.usernameInput.Blur()
			m.viewRegistrationModel.passwordInput.Focus()
			m.viewRegistrationModel.passwordConfirmInput.Blur()
		case RegistrationPasswordConfirmFocused:
			m.viewRegistrationModel.usernameInput.Blur()
			m.viewRegistrationModel.passwordInput.Blur()
			m.viewRegistrationModel.passwordConfirmInput.Focus()
		case RegistrationContinueButtonFocused:
			m.viewRegistrationModel.usernameInput.Blur()
			m.viewRegistrationModel.passwordInput.Blur()
			m.viewRegistrationModel.passwordConfirmInput.Blur()
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
			tiCmd tea.Cmd
			mvpCmd tea.Cmd
			uvpCmd tea.Cmd
		)
	switch m.viewMode {

		case viewChat:
			m.viewChatModel.textarea, tiCmd = m.viewChatModel.textarea.Update(msg)
			switch msg := msg.(type) {

			case tea.KeyMsg:
				// Update viewports for keyboard input
				m.viewChatModel.messageHistoryViewport, mvpCmd = m.viewChatModel.messageHistoryViewport.Update(msg)
				m.viewChatModel.userListViewport, uvpCmd = m.viewChatModel.userListViewport.Update(msg)

				switch msg.Type {
				case tea.KeyCtrlC, tea.KeyEsc:
					delete(m.app.progs, m.viewChatModel.id)
					m.app.updateUserlists()
					return m, tea.Quit
				case tea.KeyEnter:
					if m.viewChatModel.textarea.Value() != "" {

						if(m.viewChatModel.textarea.Value()[0]=='/'){
							// Its a command!
							command := strings.Split(m.viewChatModel.textarea.Value()[1:], " ")
							if(len(command)>0){
								switch strings.ToLower(command[0]){
									case "ping":
										m.viewChatModel.messages = append(m.viewChatModel.messages, chatMsg{
											sender: "islebot",
											text: "pong",
											time: time.Now(),
											channel: m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId,
										})
										updateChatLines(&m)
									case "c","chan","channel":

										m.viewChatModel.messages = append(m.viewChatModel.messages, chatMsg{
											sender: "islebot",
											text: "You are currently in the #global channel",
											time: time.Now(),
											channel: m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId,
										})
										updateChatLines(&m)

									default:
										m.viewChatModel.messages = append(m.viewChatModel.messages, chatMsg{
											sender: "islebot",
											text: "I dont know that command. Try /help",
											time: time.Now(),
											channel: m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId,
										})
										updateChatLines(&m)
								}
								// if(strings.ToLower(comm))
								// if(command[0])
							}
						}else{
							m.app.sendMessage(chatMsg{
								sender: m.viewChatModel.id,
								text:   m.viewChatModel.textarea.Value(),
								time:   time.Now(),
								channel: m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId,
							})
						}
						m.viewChatModel.textarea.Reset()
					}
				case tea.KeyTab:
					m.viewChatModel.focus++
					m.viewChatModel.focus %= FocusedTypesLength

					switch m.viewChatModel.focus {
						case FocusedBoxChatHistory:
							m.viewChatModel.textarea.Blur()
							VPDisableScrolling(&m.viewChatModel.userListViewport)
							VPDisableScrolling(&m.viewChatModel.channelListViewport)
							VPEnableScrolling(&m.viewChatModel.messageHistoryViewport)
						case FocusedBoxChatInput:
							m.viewChatModel.textarea.Focus()
							m.viewChatModel.messageHistoryViewport.GotoBottom()
							VPDisableScrolling(&m.viewChatModel.messageHistoryViewport)
							VPDisableScrolling(&m.viewChatModel.channelListViewport)
							VPDisableScrolling(&m.viewChatModel.userListViewport)
						case FocusedBoxUserList:
							m.viewChatModel.textarea.Blur()
							VPDisableScrolling(&m.viewChatModel.messageHistoryViewport)
							VPDisableScrolling(&m.viewChatModel.channelListViewport)
							VPEnableScrolling(&m.viewChatModel.userListViewport)
						case FocusedBoxChannelList:
							m.viewChatModel.textarea.Blur()
							VPDisableScrolling(&m.viewChatModel.messageHistoryViewport)
							VPDisableScrolling(&m.viewChatModel.userListViewport)
							VPEnableScrolling(&m.viewChatModel.channelListViewport)
					}
					updateChannelList(&m)
				}
				if msg.Type == tea.KeyUp || (msg.Type == tea.KeyRunes && msg.Runes[0] == 'k') {
					if(m.viewChatModel.focus==FocusedBoxChannelList){
						if(m.viewChatModel.currentChannel>0){
							m.viewChatModel.currentChannel--
							updateChannelList(&m)
							reloadMessagesChannelSwitch(&m)
						}
					}
				}
				if msg.Type == tea.KeyDown || (msg.Type == tea.KeyRunes && msg.Runes[0] == 'j') {
					if(m.viewChatModel.focus==FocusedBoxChannelList){
						if(m.viewChatModel.currentChannel<len(m.viewChatModel.channels)-1){
							m.viewChatModel.currentChannel++
							updateChannelList(&m)
							reloadMessagesChannelSwitch(&m)

						}
					}
				}
			
			

			case tea.WindowSizeMsg:
				// m.windowHeight = msg.Height
				// m.windowWidth = msg.Width
				m.viewChatModel.channelListViewport = getNewChannelListViewport(m.app, msg.Width, msg.Height, m.viewChatModel.focus)
				m.viewChatModel.userListViewport = getNewUserListViewport(m.app, msg.Width, msg.Height, m.viewChatModel.focus)
				m.viewChatModel.messageHistoryViewport = getNewMessageHistoryViewport(m.app, msg.Width, msg.Height, m.viewChatModel.focus)
				m.viewChatModel.textarea.SetWidth(max(0,msg.Width-47))
				updateChannelList(&m)
				updateChatLines(&m)
				updateUserList(&m)
			
			case chatMsg:
				if(msg.channel==m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId){
					m.viewChatModel.messages = append(m.viewChatModel.messages, msg)
					updateChatLines(&m)
				}
			case channelList:
				m.viewChatModel.channels = msg
				updateChannelList(&m)
			
			case userlist:
				m.viewChatModel.users = msg
				updateUserList(&m)
			
			case tea.QuitMsg:
				delete(m.app.progs, m.viewChatModel.id)
				m.app.updateUserlists()

			case errMsg:
				m.viewChatModel.err = msg
				return m, nil
			}
		case viewRegistration:
			m.viewRegistrationModel.usernameInput, tiCmd = m.viewRegistrationModel.usernameInput.Update(msg)
			m.viewRegistrationModel.passwordInput, tiCmd = m.viewRegistrationModel.passwordInput.Update(msg)
			m.viewRegistrationModel.passwordConfirmInput, tiCmd = m.viewRegistrationModel.passwordConfirmInput.Update(msg)

			switch msg := msg.(type) {

			case tea.KeyMsg:
				if(msg.Type == tea.KeyCtrlC || msg.Type==tea.KeyEsc){
					delete(m.app.progs, m.viewChatModel.id)
					m.app.updateUserlists()
					return m, tea.Quit
				}
				if(msg.Type == tea.KeyEnter || msg.Type == tea.KeyTab || msg.Type == tea.KeyDown){
					if(m.viewRegistrationModel.FocusedBox<RegistrationContinueButtonFocused){
						// Just go down
						m.viewRegistrationModel.FocusedBox++
					}else{
						if(msg.Type == tea.KeyTab || msg.Type == tea.KeyDown){
							m.viewRegistrationModel.FocusedBox=0
						}else{

							newUsername := m.viewRegistrationModel.usernameInput.Value()
							newPassword := m.viewRegistrationModel.passwordInput.Value()
							newPasswordConfirm := m.viewRegistrationModel.passwordConfirmInput.Value()

							if(len(newUsername)<3 || len(newUsername)>10){
								m.viewRegistrationModel.feedbackViewport.SetContent("Username must be 3-10 chars")
								return m,nil
							}

							if(newPassword!=newPasswordConfirm){
								m.viewRegistrationModel.feedbackViewport.SetContent("Passwords aren't identical")
								return m,nil
							}

							hashedPass,err := HashPassword(newPassword)

							if(err!=nil){
								m.viewRegistrationModel.feedbackViewport.SetContent("Error creating account (1)")
								return m,nil
							}

							err = gorm.G[User](m.db).Create(context.Background(), &User{
								ID: newUsername,
								Password: hashedPass,
								Channels: []Channel{*m.channels["global"]},
							})

							if(err!=nil){
								// m.viewRegistrationModel.feedbackViewport.SetContent("Error creating account (2)")
								m.viewRegistrationModel.feedbackViewport.SetContent("Username already exists")
								return m,nil
							}else{
								// Account was created?
								m.viewMode=viewChat

							}

							// m.viewRegistrationModel.feedbackViewport.SetContent("test")
							// return (m, )
							// Sign up!
						}
					}
				}
				if(msg.Type == tea.KeyShiftTab || msg.Type == tea.KeyUp){
					if(m.viewRegistrationModel.FocusedBox>0){
						// Just go down
						m.viewRegistrationModel.FocusedBox--
					}else{
						if(msg.Type == tea.KeyShiftTab){
							m.viewRegistrationModel.FocusedBox = RegistrationContinueButtonFocused
						}
					}
					// Cant go higher than username box
				}
				updateRegistrationTextFocuses(&m)
			case tea.QuitMsg:
				delete(m.app.progs, m.viewChatModel.id)
				m.app.updateUserlists()
			case tea.WindowSizeMsg:
				// m.windowHeight = msg.Height
				// m.windowWidth = msg.Width
				m.viewChatModel.channelListViewport = getNewChannelListViewport(m.app, msg.Width, msg.Height, m.viewChatModel.focus)
				m.viewChatModel.userListViewport = getNewUserListViewport(m.app, msg.Width, msg.Height, m.viewChatModel.focus)
				m.viewChatModel.messageHistoryViewport = getNewMessageHistoryViewport(m.app, msg.Width, msg.Height, m.viewChatModel.focus)
				m.viewChatModel.textarea.SetWidth(max(0,msg.Width-47))
				updateChannelList(&m)
				updateChatLines(&m)
				updateUserList(&m)
			
			case errMsg:
				m.viewChatModel.err = msg
				return m, nil
			}
	}


    return m, tea.Batch(tiCmd, mvpCmd, uvpCmd)
}



func getFullUserListBar(m model) string {
	banner := `⠀⣠⣴⣦⣽⣿⣾⣿⣷⣟⣋⡁⠀⠀ 
⠀⢀⣬⣽⣿⣿⣿⣿⣿⣿⣿⠿⠗⠀ 
⠠⠛⠋⢩⣿⡟⣿⣏⠙⠻⢿⣷⠀⠀ 
⠀⠀⠀⡿⠋⠀⡟⢻⡀⠀⠀⠈⠃⠀ 
⠀⠀⠀⠀⠀⠘⠁⢸⡇⠀⠀⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀isle.chat 
⠀⠀⠀⠀⠀⠀⠀⣾⡇⠀⠀#global 
⠀⠀⠀⠀⠀⠀⣀⣿⡇⠀⠀⠀⠀⠀ 
⠀⢀⣄⣶⣿⣿⣟⣻⣻⣯⣕⣒⣄⡀  `
	bannerStyle := lipgloss.NewStyle().Background(lipgloss.Color("235")).Foreground(lipgloss.Color("15"))

	return bannerStyle.Render(banner)+ "\n"+ fmt.Sprintf("%s users online\n", humanize.Comma(int64(len(m.viewChatModel.users)))) + 
	 m.viewChatModel.userListViewport.View()
}

type BoxWithLabel struct {
	BoxStyleFocused   lipgloss.Style
	BoxStyleUnfocused   lipgloss.Style
	LabelStyle lipgloss.Style
}

func RegistrationBox() BoxWithLabel {

	return BoxWithLabel{
		BoxStyleFocused: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("121")),
		BoxStyleUnfocused: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240")),

		// You could, of course, also set background and foreground colors here 
		// as well.
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
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
					// if m.focus==FocusedBoxChannelList {
					// 	return FocusedStyle.Render(m.channelListViewport.View())
					// } else {
					// 	return UnfocusedStyle.Render(m.channelListViewport.View())
					// }
				return UnfocusedStyle.Render(m.viewChatModel.channelListViewport.View())
			}()

			userList := func() string {
					if m.viewChatModel.focus==FocusedBoxUserList {
						return FocusedStyle.Render(getFullUserListBar(m))
					} else {
						return UnfocusedStyle.Render(getFullUserListBar(m))
					}
				}();
			
			return lipgloss.JoinHorizontal(lipgloss.Bottom, channelList, chatSection, userList)
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

			

			return lipgloss.JoinVertical(lipgloss.Right, 
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
			)

		default:
			return "Error!"

	}
}