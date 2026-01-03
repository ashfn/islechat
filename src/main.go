package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"slices"

	"strings"

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
	"syscall"
	"time"

	"github.com/muesli/termenv"

	"go.dalton.dog/bubbleup"

	"github.com/BurntSushi/toml"

	"regexp"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"golang.org/x/crypto/bcrypt"
)

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
		SenderID:  msg.sender,
		Content:   msg.text,
		Time:      msg.time,
		ChannelID: msg.channel,
	})
	if err == nil {
		a.mu.Lock()
		a.messages[msg.channel] = append(a.messages[msg.channel], msg)
		a.mu.Unlock()
		a.mu.RLock()

		for _, p := range a.channelMemberListCache[msg.channel].onlineMembers {
			go p.prog.Send(msg)
		}

		a.mu.RUnlock()
	} else {
		log.Errorf("Error sending msg in %s", msg.channel)

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

func newApp(db *gorm.DB, config serverConfig) *app {
	a := new(app)
	a.db = db
	a.config = config

	a.timezoneEstimator = timezoneEstimator{available: false}
	a.timezoneEstimator.setupGeoipDatabase()

	a.mu.Lock()
	a.messages = make(map[string][]chatMsg)
	a.channels = make(map[string]*Channel)
	// a.channelMembers = make(map[string]map[string]*userSession)
	a.sessionUsernames = make(map[string]string)
	a.channelMemberListCache = make(map[string]*channelMemberList)

	// channels, err := gorm.G[Channel](db).Find(context.Background())
	var channels []Channel
	err := db.Preload("Users", func(db *gorm.DB) *gorm.DB {
		return db.Select("id")
	}).Find(&channels).Error

	if err != nil {
		log.Errorf("Error fetching channels: %v", err)
	}

	for _, v := range channels {
		temp := make([]chatMsg, 0)
		a.messages[v.ID] = temp
		a.channels[v.ID] = &v
		// a.channelMembers[v.ID] = make(map[string]*userSession)

		a.channelMemberListCache[v.ID] = &channelMemberList{
			onlineMembers:      make(map[string]*userSession),
			publicChannel:      v.Public,
			offlineMembers:     make(map[string]string),
			offlineMemberCount: len(v.Users),
		}
		if !v.Public {
			for _, u := range v.Users {
				a.channelMemberListCache[v.ID].offlineMembers[u.ID] = u.ID
			}
		}
	}

	var msgs []Message
	db.Raw(`
		SELECT *
		FROM (
			SELECT *,
				ROW_NUMBER() OVER (PARTITION BY channel_id ORDER BY time DESC) as rn
			FROM messages
		) sub
		WHERE rn <= 200
		ORDER BY channel_id, time DESC
	`).Scan(&msgs)

	slices.Reverse(msgs)

	for _, v := range msgs {
		a.messages[v.ChannelID] = append(a.messages[v.ChannelID], chatMsg{
			sender:  v.SenderID,
			text:    v.Content,
			time:    v.Time,
			channel: v.ChannelID,
		})
	}

	a.sessions = make(map[string]*userSession)

	a.mu.Unlock()

	s, err := wish.NewServer(
		wish.WithAddress(net.JoinHostPort(a.config.Host, a.config.Port)),
		wish.WithHostKeyPath(".ssh/id_ed25519"),
		wish.WithPasswordAuth(func(ctx ssh.Context, password string) bool {
			username := ctx.User()

			user, err := gorm.G[User](db).
				Where("ID = ?", username).
				First(context.Background())

			if err == nil {
				// We found the user
				// check password
				if VerifyPassword(password, user.Password) {
					// Password was correct, we are good to go

					a.mu.Lock()
					_, ok := a.sessions[ctx.User()]
					if !ok {
						a.sessionUsernames[ctx.SessionID()] = ctx.User()
					}
					a.mu.Unlock()
					if !ok {
						ctx.SetValue("auth_status", "ok")
					} else {
						ctx.SetValue("auth_status", "fail")
						ctx.SetValue("auth_msg", "You are already loggedin elsewhere")
					}
					return true
				} else {
					// We don't know if they got the password wrong or were trying to make an account with that username
					// So we just send them to the register page
					ctx.SetValue("auth_status", "fail")
					ctx.SetValue("password", password)
					ctx.SetValue("auth_msg", "Username taken")
					return true
				}
			} else {
				// Account doesnt exist so we will send them to the register page with the details they entered
				// Pre filled
				ctx.SetValue("auth_status", "fail")
				ctx.SetValue("password", password)
				ctx.SetValue("auth_msg", "")
				return true
			}

		}),
		wish.WithMiddleware(
			a.CleanupMiddleware,
			bubbletea.MiddlewareWithProgramHandler(a.ProgramHandler, termenv.TrueColor),
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
	log.Info("Starting SSH server", "host", a.config.Host, "port", a.config.Port)
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
func (a *app) CleanupMiddleware(next ssh.Handler) ssh.Handler {
	return func(s ssh.Session) {
		defer func() {

			username, ok := a.sessionUsernames[s.Context().SessionID()]
			if !ok {

				// User wasn't logged in
				// Just clean them up from the sessions list
				a.mu.Lock()
				delete(a.sessions, s.Context().SessionID())
				delete(a.sessionUsernames, s.Context().SessionID())
				a.mu.Unlock()
			} else {

				// Update channel list for all their channels
				updateChannelMemberList(updateChannelMemberListParameters{
					app:    a,
					userId: username,
					change: UserChannelOffline,
				})
				a.mu.Lock()
				delete(a.sessions, username)
				a.mu.Unlock()
			}
		}()
	}
}

func (a *app) ProgramHandler(s ssh.Session) *tea.Program {

	tz := a.timezoneEstimator.estimateTimezone(s)

	log.Infof("%s", tz.String())

	model := initialModel(a, 120, 30, s)
	model.app = a

	// Only fetch channels if theyre actually authed

	// Load timezone
	// We can pull in other settings here in future and encapsulate them in a settings object
	if s.Context().Value("auth_status") == "ok" {
		user, err := gorm.G[User](a.db).
			Where("ID = ?", s.User()).
			First(context.Background())

		if err != nil {
			log.Fatal("Err getting user")
		}
		tz, err := time.LoadLocation(user.Timezone)

		if err == nil {
			model.viewChatModel.timezone = tz
		}

	}

	updateChatLines(&model)
	updateChannelList(&model)
	updateRegistrationTextFocuses(&model)

	if s.Context().Value("auth_status") == "fail" {
		msg := s.Context().Value("auth_msg").(string)
		model.viewRegistrationModel.feedbackViewport.SetContent(msg)
	}

	opts := append([]tea.ProgramOption{}, bubbletea.MakeOptions(s)...)
	p := tea.NewProgram(model, opts...)

	if s.Context().Value("auth_status") == "ok" {

		// Add session to db
		a.mu.Lock()
		a.sessions[s.User()] = &userSession{
			prog:             p,
			loggedIn:         true,
			username:         s.User(),
			currentChannelId: "global",
			inferredTimezone: tz,
			joinedChannels:   []string{},
		}
		a.mu.Unlock()
		go p.Send(channelList(channelList{
			channels:  joinedHandleChannels(&model),
			firstjoin: false,
		}))
	} else {
		// We give it a temporary 'username' using the session id

		a.mu.Lock()
		a.sessions[s.Context().SessionID()] = &userSession{
			prog:             p,
			loggedIn:         false,
			username:         "",
			inferredTimezone: tz,
			currentChannelId: "",
		}
		a.mu.Unlock()
	}

	return p
}

func main() {
	f := "config.toml"
	if _, err := os.Stat(f); err != nil {
		f = "config.toml"
	}

	var config serverConfig
	_, err := toml.DecodeFile(f, &config)

	if err != nil {
		log.Error("Could not parse invalid configuration.")
		// Set defaults
		config = serverConfig{
			Host:                 "0.0.0.0",
			Port:                 "2222",
			ServerName:           "isle.chat",
			AdminUsername:        "admin",
			BotUsername:          "islebot",
			GlobalBanner:         `                              ⢶⣄              ⠉⠛⢓⣶⣦⢿⣦⣴⡖⠛⠋          ⠚⠋⠁⢠⣿⠃⠉⠉⠛⠒⠂  isle.chat⢀⣾⠇        v0.0.0   ⣼⡟         #global ⢰⣿⠁          ⢀⣠⣤⣤⣴⣶⣶⣾⣯⣤⣤⣤⣤⣤⣀⣀   ⠰⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠦                     `,
			AnnouncementChannel:  "news",
			DefaultBanner:        `                              ⢶⣄              ⠉⠛⢓⣶⣦⢿⣦⣴⡖⠛⠋          ⠚⠋⠁⢠⣿⠃⠉⠉⠛⠒⠂  isle.chat⢀⣾⠇        v0.0.0   ⣼⡟         default ⢰⣿⠁          ⢀⣠⣤⣤⣴⣶⣶⣾⣯⣤⣤⣤⣤⣤⣀⣀   ⠰⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠦                     `,
			WelcomeMessage:       "A new user joined for the first time! Welcome @%s. Run /help for information and arrow keys to navigate",
			FilterPublicMessages: false,
			RegistrationHeader:   "isle.chat registration   ",
			DatabaseMode:         "sqlite",
			PostgresHost:         "localhost",
			PostgresUser:         "islechat",
			PostgresPassword:     "password",
			PostgresDBName:       "islechat",
			PostgresPort:         "5432",
			PostgresSSL:          "disable",
		}

		// Create default config file
		f, err := os.Create("config.toml")
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		if err := toml.NewEncoder(f).Encode(config); err != nil {
			log.Fatal(err)
		}

		log.Fatal("Default config.toml created.")
	}
	var db *gorm.DB

	if config.DatabaseMode == "sqlite" {
		db, err = gorm.Open(sqlite.Open("islechat.db"), &gorm.Config{})
	} else {
		dburl := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
			config.PostgresHost,
			config.PostgresUser,
			config.PostgresPassword,
			config.PostgresDBName,
			config.PostgresPort,
			config.PostgresSSL,
		)
		db, err = gorm.Open(postgres.Open(dburl), &gorm.Config{})
	}

	if err != nil {
		log.Errorf("%s", err)
		panic("failed to connect database")
	}

	db.AutoMigrate(&Message{}, &Channel{}, &User{}, &Invite{})

	db.Clauses(clause.OnConflict{DoNothing: true}).Create(&[]User{
		{
			ID:       config.BotUsername,
			Password: "",
			Channels: make([]Channel, 0),
		}})
	db.Clauses(clause.OnConflict{DoNothing: true}).Create(&[]Channel{
		{
			ID:      "global",
			OwnerID: config.BotUsername,
			Banner:  `                              ⢶⣄              ⠉⠛⢓⣶⣦⢿⣦⣴⡖⠛⠋          ⠚⠋⠁⢠⣿⠃⠉⠉⠛⠒⠂  isle.chat⢀⣾⠇        v0.0.0   ⣼⡟         #global ⢰⣿⠁          ⢀⣠⣤⣤⣴⣶⣶⣾⣯⣤⣤⣤⣤⣤⣀⣀   ⠰⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠦                     `,
			Public:  true,
		}})

	app := newApp(db, config)

	app.Start()
}

func getNewChannelListViewport(a *app, width int, height int, focus FocusedBox) viewport.Model {
	cvp := viewport.New(20, max(0, height-2))

	if focus == FocusedBoxChannelList {
		VPEnableScrolling(&cvp)
	} else {
		VPDisableScrolling(&cvp)
	}
	return cvp
}

func getNewUserListViewport(a *app, width int, height int, focus FocusedBox) viewport.Model {
	uvp := viewport.New(20, max(0, height-13))
	if focus == FocusedBoxUserList {
		VPEnableScrolling(&uvp)
	} else {
		VPDisableScrolling(&uvp)
	}
	return uvp
}

func getNewMessageHistoryViewport(a *app, width int, height int, focus FocusedBox) viewport.Model {
	mvp := viewport.New(max(0, width-48), max(0, height-7))
	if width < 71 {
		mvp = viewport.New(max(0, width-3), max(0, height-7))
	}
	if focus == FocusedBoxChatHistory {
		VPEnableScrolling(&mvp)
	} else {
		VPDisableScrolling(&mvp)
	}
	return mvp
}
func centerString(str string, width int) string {
	spaces := int(float64(width-len(str)) / 2)
	return strings.Repeat(" ", spaces) + str + strings.Repeat(" ", width-(spaces+len(str)))
}

func beep() tea.Cmd {
	return tea.Printf("\a")
}

// For only when a user joins the main area (From logging in or just signing up)
func joinedHandleChannels(m *model) []userChannelState {
	// Update the users channel list from the DB
	// Update the user list for everyone in their channels

	channels := make([]userChannelState, 0)

	var channelIDs []string

	channels = append(channels, userChannelState{
		channelId: "global",
		unread:    0,
	})

	// We query the join table specifically to get the IDs for this User
	err := m.app.db.Table("user_channels").
		Where("user_id = ?", m.viewChatModel.id).
		Order("channel_id DESC").
		Pluck("channel_id", &channelIDs).Error

	if err != nil {
		log.Error(err)
		return []userChannelState{}
	}

	// Adding the channels for the user
	for _, channel := range channelIDs {
		if channel != "global" {
			channels = append(channels, userChannelState{
				channelId: channel,
				unread:    0,
			})
		}
	}

	// Adding the user to online member list for their channels
	m.app.mu.Lock()
	for _, channel := range channelIDs {

		m.app.sessions[m.viewChatModel.id].joinedChannels = append(m.app.sessions[m.viewChatModel.id].joinedChannels, channel)
	}

	m.app.mu.Unlock()

	updateChannelMemberList(updateChannelMemberListParameters{
		app:    m.app,
		userId: m.viewChatModel.id,
		change: UserChannelOnline,
	})

	return channels
}

func initialModel(a *app, width int, height int, sess ssh.Session) model {

	ta := textarea.New()
	ta.Placeholder = "Send a message..."
	ta.Focus()
	ta.Cursor.SetMode(cursor.CursorStatic)

	ta.Prompt = ""
	ta.CharLimit = 2000

	ta.SetWidth(width - 47)
	ta.SetHeight(3)

	// Remove cursor line styling
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()

	ta.ShowLineNumbers = false

	mvp := getNewMessageHistoryViewport(a, width, height, FocusedBoxChatInput)
	uvp := getNewUserListViewport(a, width, height, FocusedBoxChatInput)
	cvp := getNewChannelListViewport(a, width, height, FocusedBoxChatInput)

	ta.KeyMap.InsertNewline.SetEnabled(false)

	previousMsgs := a.messages["global"]
	channelList := make([]userChannelState, 0)
	usernameInput := textinput.New()
	usernameInput.Placeholder = "your_username"
	usernameInput.CharLimit = 10
	usernameInput.Width = 24
	usernameInput.Prompt = "@"

	passwordInput := textinput.New()
	passwordInput.Placeholder = "Enter a password"
	passwordInput.CharLimit = 50
	passwordInput.Width = 25
	passwordInput.EchoMode = textinput.EchoPassword
	passwordInput.Prompt = ""

	passwordConfirmInput := textinput.New()
	passwordConfirmInput.Placeholder = ""
	passwordConfirmInput.CharLimit = 50
	passwordConfirmInput.Width = 25
	passwordConfirmInput.EchoMode = textinput.EchoPassword
	passwordConfirmInput.Prompt = ""

	confirmViewport := viewport.New(26, 1)
	confirmViewport.SetContent(centerString("Create account", 26))

	feedbackViewport := viewport.New(27, 1)
	feedbackViewport.SetContent("")

	if sess.Context().Value("auth_status") == "ok" {

		// Add session to db
		return model{

			viewMode: viewChat,

			viewChatModel: viewChatModel{
				id:                     sess.User(),
				textarea:               ta,
				messages:               previousMsgs,
				messageHistoryViewport: mvp,
				userListViewport:       uvp,
				channelListViewport:    cvp,
				senderStyle:            lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5")),
				dateStyle:              lipgloss.NewStyle().Foreground(lipgloss.Color("238")),
				currentChannel:         0,
				channels:               channelList,
				channelBanner: `⠀⣠⣴⣦⣽⣿⣾⣿⣷⣟⣋⡁⠀⠀ 
								⠀⢀⣬⣽⣿⣿⣿⣿⣿⣿⣿⠿⠗⠀ 
								⠠⠛⠋⢩⣿⡟⣿⣏⠙⠻⢿⣷⠀⠀ 
								⠀⠀⠀⡿⠋⠀⡟⢻⡀⠀⠀⠈⠃⠀ 
								⠀⠀⠀⠀⠀⠘⠁⢸⡇⠀⠀⠀⠀⠀ 
								⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀isle.chat 
								⠀⠀⠀⠀⠀⠀⠀⣾⡇⠀loading..
								⠀⠀⠀⠀⠀⠀⣀⣿⡇⠀⠀⠀⠀⠀ 
								⠀⢀⣄⣶⣿⣿⣟⣻⣻⣯⣕⣒⣄⡀  `,
				err:        nil,
				memberList: a.channelMemberListCache["global"],
				focus:      FocusedBoxChatInput,
				alert:      *bubbleup.NewAlertModel(40, false, 2),
				timezone:   time.UTC,
			},
			viewRegistrationModel: viewRegistrationModel{
				usernameInput:        usernameInput,
				passwordInput:        passwordInput,
				passwordConfirmInput: passwordConfirmInput,
				confirmViewport:      confirmViewport,
			},
		}
	} else {
		usernameInput.SetValue(sess.User())
		pass, ok := sess.Context().Value("password").(string)
		if ok {
			passwordInput.SetValue(pass)
		}

		return model{

			viewMode: viewRegistration,
			viewChatModel: viewChatModel{
				id:                     sess.Context().SessionID(),
				textarea:               ta,
				messages:               previousMsgs,
				messageHistoryViewport: mvp,
				userListViewport:       uvp,
				channelListViewport:    cvp,
				senderStyle:            lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5")),
				dateStyle:              lipgloss.NewStyle().Foreground(lipgloss.Color("238")),
				currentChannel:         0,
				channels:               channelList,
				err:                    nil,
				channelBanner: `⠀⣠⣴⣦⣽⣿⣾⣿⣷⣟⣋⡁⠀⠀ 
								⠀⢀⣬⣽⣿⣿⣿⣿⣿⣿⣿⠿⠗⠀ 
								⠠⠛⠋⢩⣿⡟⣿⣏⠙⠻⢿⣷⠀⠀ 
								⠀⠀⠀⡿⠋⠀⡟⢻⡀⠀⠀⠈⠃⠀ 
								⠀⠀⠀⠀⠀⠘⠁⢸⡇⠀⠀⠀⠀⠀ 
								⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀isle.chat 
								⠀⠀⠀⠀⠀⠀⠀⣾⡇⠀loading..
								⠀⠀⠀⠀⠀⠀⣀⣿⡇⠀⠀⠀⠀⠀ 
								⠀⢀⣄⣶⣿⣿⣟⣻⣻⣯⣕⣒⣄⡀  `,
				memberList: a.channelMemberListCache["global"],
				focus:      FocusedBoxChatInput,
				alert:      *bubbleup.NewAlertModel(40, false, 2),
				timezone:   time.UTC,
			},
			viewRegistrationModel: viewRegistrationModel{
				FocusedBox:           RegistrationPasswordConfirmFocused,
				usernameInput:        usernameInput,
				passwordInput:        passwordInput,
				passwordConfirmInput: passwordConfirmInput,
				confirmViewport:      confirmViewport,
				feedbackViewport:     feedbackViewport,
			},
		}
	}

}

func (m model) Init() tea.Cmd {
	return m.viewChatModel.alert.Init()
}

func reloadMessagesChannelSwitch(m *model) {
	m.viewChatModel.messages = m.app.messages[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	updateChatLines(m)
}

// Adds a user to a channel, adding them to the database and updating
// all the state and user lists
func addUserToChannel(app *app, user string, channel string) bool {
	// err := gorm.G[User](app.db).Where("id = ?", user).Update(context.Background(), "name", "hello")

	dbuser := User{ID: user}

	// 2. Use the Association API to append the channel
	// This automatically handles the 'user_channels' join table
	err := app.db.Model(&dbuser).Association("Channels").Append(&Channel{ID: channel})

	if err != nil {
		// Error was encountered and user couldn't be added
		return false
	}

	app.mu.Lock()
	app.sessions[user].joinedChannels = append(app.sessions[user].joinedChannels, channel)
	// app.channelMembers[channel][user]=app.sessions[user]
	app.mu.Unlock()

	// updateChannelMemberList(app, channel)

	// Update the user's channel list

	return true
}

// Adds a user to a channel, adding them to the database and updating
// User must be online!?
func removeUserFromChannel(app *app, user string, channel string) bool {

	dbuser := User{ID: user}

	err := app.db.Model(&dbuser).Association("Channels").Delete(&Channel{ID: channel})

	if err != nil {
		// Error was encountered and user couldn't be added
		return false
	}

	app.mu.Lock()
	userSession, ok := app.sessions[user]
	if ok {
		joinedChannels := userSession.joinedChannels
		newJoinedChannels := make([]string, 0)
		for _, v := range joinedChannels {
			if v != channel {
				newJoinedChannels = append(newJoinedChannels, v)
			}
		}
		app.sessions[user].joinedChannels = newJoinedChannels
	}

	app.mu.Unlock()

	return true
}

func updateRegistrationTextFocuses(m *model) {
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

// The sole purpose of this is pushing the channel member list changes to
// anyone in those channels, it doesnt handle the other state stuff
func updateChannelMemberList(params updateChannelMemberListParameters) {
	if params.app == nil || params.userId == "" {
		// invalid
		log.Error("Invalid update channel member list call")
		return
	}

	// If no channel was provided we will do it for all their channels
	if params.channelId == "" {
		// Basically need to do the same as below but for every channel they are in

		// we will be lazy AF and call this function for each of the channels theyre in
		params.app.mu.Lock()
		channels := params.app.sessions[params.userId].joinedChannels
		params.app.mu.Unlock()

		for _, v := range channels {
			updateChannelMemberList(updateChannelMemberListParameters{
				params.app,
				params.userId,
				params.change,
				v,
			})
		}

	} else {
		params.app.mu.Lock()
		isPublic := params.app.channels[params.channelId].Public

		// We only need to update that one channel

		if params.change == UserChannelJoin || params.change == UserChannelOnline {

			params.app.channelMemberListCache[params.channelId].onlineMembers[params.userId] = params.app.sessions[params.userId]

			if params.change == UserChannelOnline {
				delete(params.app.channelMemberListCache[params.channelId].offlineMembers, params.userId)
				params.app.channelMemberListCache[params.channelId].offlineMemberCount--
			}
		} else {
			delete(params.app.channelMemberListCache[params.channelId].onlineMembers, params.userId)

			if params.change == UserChannelOffline {
				params.app.channelMemberListCache[params.channelId].offlineMemberCount++
				if !isPublic {
					params.app.channelMemberListCache[params.channelId].offlineMembers[params.userId] = params.userId
				}
			}
		}

		online := params.app.channelMemberListCache[params.channelId].onlineMembers
		state := params.app.channelMemberListCache[params.channelId]
		params.app.mu.Unlock()

		for _, v := range online {
			if v.currentChannelId == params.channelId {
				go v.prog.Send(channelMemberListMsg(state))
			}
		}
	}
}

func sendIslebotMessage(m *model, msg string) {
	m.viewChatModel.messages = append(m.viewChatModel.messages, chatMsg{
		sender:  m.app.config.BotUsername,
		text:    msg,
		time:    time.Now(),
		channel: m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId,
	})
	updateChatLines(m)
}

func sendIslebotMessagePermanent(app *app, message string, channel string) {

	app.sendMessage(chatMsg{
		sender:  app.config.BotUsername,
		text:    message,
		time:    time.Now(),
		channel: channel,
	})
}

func BannerWidth(s string) int {
	width := 0
	for _, r := range s {
		if r >= 0x2800 && r <= 0x28FF {
			width++
		} else if r < 128 {
			width++
		}
	}
	return width
}

func updatedChatFocus(m *model) {
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
	updateChannelList(m)
}

func applyMentionAutocomplete(m *model, username string) {
	if username == "" {
		return
	}
	value := m.viewChatModel.textarea.Value()
	allowed := "a-zA-Z0-9_-"
	re := regexp.MustCompile("(^|[^" + allowed + "])@([" + allowed + "]{0,10})$")
	loc := re.FindStringSubmatchIndex(value)
	if loc == nil {
		return
	}
	queryStart := loc[4]
	queryEnd := loc[5]
	if queryStart < 0 || queryEnd < 0 || queryStart > len(value) || queryEnd > len(value) {
		return
	}

	newValue := value[:queryStart] + username
	if !strings.HasSuffix(newValue, " ") {
		newValue += " "
	}
	m.viewChatModel.textarea.SetValue(newValue)
	m.viewChatModel.textarea.CursorEnd()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		tiCmd    tea.Cmd
		mvpCmd   tea.Cmd
		uvpCmd   tea.Cmd
		alertCmd tea.Cmd
		beepCmd  tea.Cmd
	)

	switch m.viewMode {

	case viewChat:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			// If suggestions are open, use up/down to scroll them
			if m.viewChatModel.focus == FocusedBoxChatInput &&
				(msg.Type == tea.KeyUp || msg.Type == tea.KeyDown) &&
				m.viewChatModel.commandSuggestionMode != "" &&
				len(m.viewChatModel.commandSuggestions) > 0 {

				if msg.Type == tea.KeyUp {
					if m.viewChatModel.commandSuggestionIndex > 0 {
						m.viewChatModel.commandSuggestionIndex--
					}
				} else {
					if m.viewChatModel.commandSuggestionIndex < len(m.viewChatModel.commandSuggestions)-1 {
						m.viewChatModel.commandSuggestionIndex++
					}
				}

				// Keep selection within the 5-row window
				if m.viewChatModel.commandSuggestionIndex < m.viewChatModel.commandSuggestionScroll {
					m.viewChatModel.commandSuggestionScroll = m.viewChatModel.commandSuggestionIndex
				}
				if m.viewChatModel.commandSuggestionIndex >= m.viewChatModel.commandSuggestionScroll+5 {
					m.viewChatModel.commandSuggestionScroll = m.viewChatModel.commandSuggestionIndex - 4
				}
				return m, nil
			}

			// Update viewports for keyboard input
			m.viewChatModel.messageHistoryViewport, mvpCmd = m.viewChatModel.messageHistoryViewport.Update(msg)
			m.viewChatModel.userListViewport, uvpCmd = m.viewChatModel.userListViewport.Update(msg)

			switch msg.Type {
			case tea.KeyCtrlC, tea.KeyEsc:
				return m, tea.Quit
			case tea.KeyEnter:
				if m.viewChatModel.textarea.Value() != "" {

					if m.viewChatModel.textarea.Value()[0] == '/' {

						commandString := m.viewChatModel.textarea.Value()[1:]
						// Its a command!
						command := strings.Fields(commandString)
						handleCmd(&m, command)
					} else {
						if m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId == m.config.AnnouncementChannel && m.viewChatModel.id != m.config.AdminUsername {
							sendIslebotMessage(&m, "Sorry you can't post in this channel")
						} else {
							m.app.sendMessage(chatMsg{
								sender:  m.viewChatModel.id,
								text:    m.viewChatModel.textarea.Value(),
								time:    time.Now(),
								channel: m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId,
							})
						}

					}
					m.viewChatModel.textarea.Reset()
					m.viewChatModel.commandSuggestions = nil
					m.viewChatModel.commandSuggestionInput = ""
					m.viewChatModel.commandSuggestionIndex = 0
					m.viewChatModel.commandSuggestionScroll = 0
					m.viewChatModel.commandSuggestionMode = ""
					// keep suggestions cleared
				}
			case tea.KeyTab:
				// If suggestions are open, Tab autocompletes the selected one
				if m.viewChatModel.focus == FocusedBoxChatInput &&
					m.viewChatModel.commandSuggestionMode != "" &&
					len(m.viewChatModel.commandSuggestions) > 0 {

					idx := m.viewChatModel.commandSuggestionIndex
					if idx >= 0 && idx < len(m.viewChatModel.commandSuggestions) {
						sugg := m.viewChatModel.commandSuggestions[idx]
						switch m.viewChatModel.commandSuggestionMode {
						case "command":
							m.viewChatModel.textarea.SetValue(sugg.Insert)
							m.viewChatModel.textarea.CursorEnd()
						case "mention":
							applyMentionAutocomplete(&m, sugg.Insert)
						}
						updateCommandSuggestions(&m)
					}
					return m, nil
				}

				m.viewChatModel.focus++
				m.viewChatModel.focus %= FocusedTypesLength
				updatedChatFocus(&m)

			}

			// Handle additional controls from in the chat box (Left and up)

			if msg.Type == tea.KeyUp || (msg.Type == tea.KeyRunes && msg.Runes[0] == 'k') {
				if m.viewChatModel.focus == FocusedBoxChannelList {
					if m.viewChatModel.currentChannel > 0 {
						m.viewChatModel.currentChannel--
						m.app.mu.Lock()
						m.app.sessions[m.viewChatModel.id].currentChannelId = m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId
						m.viewChatModel.memberList = m.app.channelMemberListCache[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
						m.viewChatModel.channels[m.viewChatModel.currentChannel].unread = 0
						m.app.mu.Unlock()
						updateChannelList(&m)
						updateUserList(&m)
						reloadMessagesChannelSwitch(&m)
					}
				}
				// Also allow going up from chat to chat history if your on the first line
				if m.viewChatModel.focus == FocusedBoxChatInput && msg.Type == tea.KeyUp && m.viewChatModel.textarea.Line() == 0 {
					m.viewChatModel.focus = FocusedBoxChatHistory
					updatedChatFocus(&m)
				}
			}
			if msg.Type == tea.KeyDown || (msg.Type == tea.KeyRunes && msg.Runes[0] == 'j') {
				if m.viewChatModel.focus == FocusedBoxChannelList {
					if m.viewChatModel.currentChannel < len(m.viewChatModel.channels)-1 {
						m.viewChatModel.currentChannel++
						m.app.mu.Lock()
						m.app.sessions[m.viewChatModel.id].currentChannelId = m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId
						m.viewChatModel.memberList = m.app.channelMemberListCache[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
						m.viewChatModel.channels[m.viewChatModel.currentChannel].unread = 0
						m.app.mu.Unlock()
						updateChannelList(&m)
						updateUserList(&m)
						reloadMessagesChannelSwitch(&m)

					}
				}

				// Also allow going down from view history to chat if your at the bottom
				// Also allow using j key (We dont allow k in the chat box incase they want to type that it would be annoying)
				if m.viewChatModel.focus == FocusedBoxChatHistory && m.viewChatModel.messageHistoryViewport.AtBottom() {
					m.viewChatModel.focus = FocusedBoxChatInput
					updatedChatFocus(&m)
				}
			}

			// Allow using right arrow key or l to go from channel list to chat box
			if msg.Type == tea.KeyRight || (msg.Type == tea.KeyRunes && msg.Runes[0] == 'l') {
				if m.viewChatModel.focus == FocusedBoxChannelList {
					m.viewChatModel.focus = FocusedBoxChatHistory
					updatedChatFocus(&m)
				} else if m.viewChatModel.focus == FocusedBoxChatHistory {
					m.viewChatModel.focus = FocusedBoxUserList
					updatedChatFocus(&m)
				} else if msg.Type == tea.KeyRight && m.viewChatModel.focus == FocusedBoxChatInput {
					info := m.viewChatModel.textarea.LineInfo()
					// Only change focus if the cursor is at the end of the line
					// And at the last line
					if info.CharOffset >= info.CharWidth-1 && info.RowOffset == info.Height-1 {
						m.viewChatModel.focus = FocusedBoxUserList
						updatedChatFocus(&m)
					}
				}
			}

			// Allow using left arrow key or h to go from user list to chat box
			if msg.Type == tea.KeyLeft || (msg.Type == tea.KeyRunes && msg.Runes[0] == 'h') {
				if m.viewChatModel.focus == FocusedBoxUserList {
					m.viewChatModel.focus = FocusedBoxChatHistory
					updatedChatFocus(&m)
				} else if m.viewChatModel.focus == FocusedBoxChatHistory {
					m.viewChatModel.focus = FocusedBoxChannelList
					updatedChatFocus(&m)
				} else if msg.Type == tea.KeyLeft && m.viewChatModel.focus == FocusedBoxChatInput {
					info := m.viewChatModel.textarea.LineInfo()
					if info.RowOffset == 0 && info.CharOffset == 0 {
						m.viewChatModel.focus = FocusedBoxChannelList
						updatedChatFocus(&m)
					}
				}
			}

		case newBannerMsg:
			m.viewChatModel.channelBanner = string(msg)
			updateUserList(&m)

		case tea.WindowSizeMsg:
			m.viewChatModel.channelListViewport = getNewChannelListViewport(m.app, msg.Width, msg.Height, m.viewChatModel.focus)
			m.viewChatModel.userListViewport = getNewUserListViewport(m.app, msg.Width, msg.Height, m.viewChatModel.focus)
			m.viewChatModel.messageHistoryViewport = getNewMessageHistoryViewport(m.app, msg.Width, msg.Height, m.viewChatModel.focus)
			if msg.Width < 71 {
				m.viewChatModel.sidebarsEnabled = false
				m.viewChatModel.textarea.SetWidth(max(0, msg.Width-2))
			} else {
				m.viewChatModel.sidebarsEnabled = true
				m.viewChatModel.textarea.SetWidth(max(0, msg.Width-47))
			}
			updateChannelList(&m)
			updateChatLines(&m)
			updateUserList(&m)

		case chatMsg:
			if msg.channel == m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId {
				m.viewChatModel.messages = append(m.viewChatModel.messages, msg)
				if strings.Contains(msg.text, "@"+m.viewChatModel.id) {
					beepCmd = beep()
				}
			} else {
				for i, v := range m.viewChatModel.channels {
					if v.channelId == msg.channel {
						m.viewChatModel.channels[i].unread++
					}
				}
			}
			updateChannelList(&m)
			updateChatLines(&m)
		case channelList:
			m.viewChatModel.channels = msg.channels
			if msg.firstjoin {
				sendIslebotMessagePermanent(m.app, fmt.Sprintf("A new user joined for the first time! Welcome @%s. Run /help for information. Your timezone was set to %s, change it with /tz", m.viewChatModel.id, m.viewChatModel.timezone.String()), "global")

			}
			updateChannelList(&m)

		case channelMemberListMsg:
			m.viewChatModel.memberList = msg
			updateUserList(&m)

		case removedFromChannelMsg:
			removedChannel := string(msg)

			currentChannel := m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId

			var removedChannelId int
			for id, ch := range m.viewChatModel.channels {
				if ch.channelId == removedChannel {
					removedChannelId = id
				}
			}

			m.viewChatModel.channels = append(m.viewChatModel.channels[:removedChannelId], m.viewChatModel.channels[removedChannelId+1:]...)

			if currentChannel == removedChannel {
				m.viewChatModel.currentChannel = 0
				m.app.mu.Lock()
				m.app.sessions[m.viewChatModel.id].currentChannelId = "global"
				m.viewChatModel.memberList = m.app.channelMemberListCache[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
				m.app.mu.Unlock()
			} else {
				// Just go to the same channel as before but update the currentChannel id as it might be affected by the array change
				for id, ch := range m.viewChatModel.channels {
					if ch.channelId == currentChannel {
						m.viewChatModel.currentChannel = id
					}
				}
			}

			updateChannelList(&m)
			updateUserList(&m)
			reloadMessagesChannelSwitch(&m)

		case errMsg:
			m.viewChatModel.err = msg
			return m, nil
		}

		// Put it down here so we can do the other stuff first
		m.viewChatModel.textarea, tiCmd = m.viewChatModel.textarea.Update(msg)
		updateCommandSuggestions(&m)

	case viewRegistration:
		m.viewRegistrationModel.usernameInput, tiCmd = m.viewRegistrationModel.usernameInput.Update(msg)
		m.viewRegistrationModel.passwordInput, tiCmd = m.viewRegistrationModel.passwordInput.Update(msg)
		m.viewRegistrationModel.passwordConfirmInput, tiCmd = m.viewRegistrationModel.passwordConfirmInput.Update(msg)

		switch msg := msg.(type) {

		case tea.KeyMsg:
			if msg.Type == tea.KeyCtrlC || msg.Type == tea.KeyEsc {
				return m, tea.Quit
			}
			if msg.Type == tea.KeyEnter || msg.Type == tea.KeyTab || msg.Type == tea.KeyDown {
				if m.viewRegistrationModel.FocusedBox < RegistrationContinueButtonFocused {
					// Just go down
					m.viewRegistrationModel.FocusedBox++
				} else {
					if msg.Type == tea.KeyTab || msg.Type == tea.KeyDown {
						m.viewRegistrationModel.FocusedBox = 0
					} else {

						newUsername := m.viewRegistrationModel.usernameInput.Value()
						newPassword := m.viewRegistrationModel.passwordInput.Value()
						newPasswordConfirm := m.viewRegistrationModel.passwordConfirmInput.Value()

						if len(newUsername) < 3 || len(newUsername) > 10 {
							m.viewRegistrationModel.feedbackViewport.SetContent("Username must be 3-10 chars")
							return m, nil
						}

						re := regexp.MustCompile(`^[a-zA-Z0-9_-]{1,10}$`)
						if !re.MatchString(newUsername) {
							m.viewRegistrationModel.feedbackViewport.SetContent("Username contains bad chars")
							return m, nil
						}

						if newUsername == m.app.config.BotUsername {
							m.viewRegistrationModel.feedbackViewport.SetContent("You cannot have this username")
							return m, nil
						}

						if newPassword != newPasswordConfirm {
							m.viewRegistrationModel.feedbackViewport.SetContent("Passwords aren't identical")
							return m, nil
						}

						hashedPass, err := HashPassword(newPassword)

						if err != nil {
							m.viewRegistrationModel.feedbackViewport.SetContent("Error creating account (1)")
							return m, nil
						}

						tz := m.app.sessions[m.viewChatModel.id].inferredTimezone

						err = gorm.G[User](m.db).Create(context.Background(), &User{
							ID:       newUsername,
							Password: hashedPass,
							Channels: []Channel{*m.app.channels["global"]},
							Timezone: tz.String(),
						})

						if err != nil {
							m.viewRegistrationModel.feedbackViewport.SetContent("Username already exists")
							return m, nil
						} else {

							// delete old session create new session
							log.Info(fmt.Sprintf("id: %s", m.viewChatModel.id))
							m.app.mu.Lock()
							prog := m.app.sessions[m.viewChatModel.id].prog
							delete(m.app.sessions, m.viewChatModel.id)
							m.app.sessions[newUsername] = &userSession{
								prog:             prog,
								loggedIn:         true,
								username:         newUsername,
								currentChannelId: "global",
								inferredTimezone: tz,
								joinedChannels:   []string{},
							}
							// Set username in sessionUsernames so session closing can be handled
							m.app.sessionUsernames[m.viewChatModel.id] = newUsername
							m.app.mu.Unlock()
							m.viewChatModel.id = newUsername
							// Add user to global channel
							addUserToChannel(m.app, newUsername, "global")
							m.viewMode = viewChat
							m.viewChatModel.timezone = tz
							return m, tea.Batch(
								func() tea.Msg {
									return channelList(channelList{
										channels:  joinedHandleChannels(&m),
										firstjoin: true,
									})
								},
							)
							// Account was created
						}
					}
				}
			}
			if msg.Type == tea.KeyShiftTab || msg.Type == tea.KeyUp {
				if m.viewRegistrationModel.FocusedBox > 0 {
					// Just go down
					m.viewRegistrationModel.FocusedBox--
				} else {
					if msg.Type == tea.KeyShiftTab {
						m.viewRegistrationModel.FocusedBox = RegistrationContinueButtonFocused
					}
				}
				// Cant go higher than username box
			}
			updateRegistrationTextFocuses(&m)
		case tea.WindowSizeMsg:
			m.viewChatModel.channelListViewport = getNewChannelListViewport(m.app, msg.Width, msg.Height, m.viewChatModel.focus)
			m.viewChatModel.userListViewport = getNewUserListViewport(m.app, msg.Width, msg.Height, m.viewChatModel.focus)
			m.viewChatModel.messageHistoryViewport = getNewMessageHistoryViewport(m.app, msg.Width, msg.Height, m.viewChatModel.focus)
			if msg.Width < 71 {
				m.viewChatModel.sidebarsEnabled = false
				m.viewChatModel.textarea.SetWidth(max(0, msg.Width-2))
			} else {
				m.viewChatModel.sidebarsEnabled = true
				m.viewChatModel.textarea.SetWidth(max(0, msg.Width-47))
			}
			updateChannelList(&m)
			updateChatLines(&m)
			updateUserList(&m)

		case errMsg:
			m.viewChatModel.err = msg
			return m, nil
		}
	}

	outAlert, outCmd := m.viewChatModel.alert.Update(msg)
	m.viewChatModel.alert = outAlert.(bubbleup.AlertModel)

	return m, tea.Batch(tiCmd, mvpCmd, uvpCmd, outCmd, alertCmd, beepCmd)
}
