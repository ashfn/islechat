package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"slices"

	"strings"

	"unicode"
	"sync"
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

    "go.dalton.dog/bubbleup"

	"github.com/BurntSushi/toml"

	humanize "github.com/dustin/go-humanize"

	"regexp"

	"gorm.io/driver/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"golang.org/x/crypto/bcrypt"
)

type app struct {
	*ssh.Server

	config serverConfig
	db *gorm.DB 
	messages map[string][]chatMsg

	// Only stores logged in users to prevent the same user logging in from multiple shells 
	// Map from username -> session OR 
	//         sessionId -> session (if not logged in)

	// will also include 
	sessions map[string]*userSession

	mu sync.RWMutex

	// Map from channel ids to channel object
	channels map[string]*Channel


	// Cached channel memberlists
	channelMemberListCache map[string]*channelMemberList

	// Map between session ids and logged-in usernames
	// Used for handling session disconnects
	// If the user isn't logged in the username will be nil
	sessionUsernames map[string]string

}

type serverConfig struct {
	Host string
	Port string
	ServerName string
	AdminUsername string
	BotUsername string
	GlobalBanner string
	AnnouncementChannel string
	DefaultBanner string
	WelcomeMessage string
	FilterPublicMessages bool
	RegistrationHeader string

	// either "sqlite" or "postgres"
	DatabaseMode string

	PostgresHost string
	PostgresUser string
	PostgresPassword string
	PostgresDBName string
	PostgresPort string
	PostgresSSL string

}

// A session for a user
type userSession struct {

	prog *tea.Program
	loggedIn bool

	// Used so we dont distribute the message to absolutely everyone
	// Will be nil if not logged in (on registration page)
	username string
	currentChannelId string
	joinedChannels []string

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
	User User
	UserID string `gorm:"primaryKey"`
	Channel Channel
	ChannelID string `gorm:"primaryKey"`
}

type Channel struct {
	ID string
	Owner User
	OwnerID string
	Banner string
	Public bool
	ReadOnly bool
	Users []User `gorm:"many2many:user_channels;"`
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
	if(err==nil){
		a.mu.Lock()
		a.messages[msg.channel] = append(a.messages[msg.channel], msg)
		a.mu.Unlock()
		a.mu.RLock()

		for _, p := range a.channelMemberListCache[msg.channel].onlineMembers {
			if(p.loggedIn){
				log.Info("MSG-SENT")
				go p.prog.Send(msg)
			}
		}

		a.mu.RUnlock()
	}else{
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
	a.config=config

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

	for _,v := range channels{
		temp := make([]chatMsg, 0)
		a.messages[v.ID] = temp
		a.channels[v.ID] = &v
		// a.channelMembers[v.ID] = make(map[string]*userSession)

		a.channelMemberListCache[v.ID] = &channelMemberList{
			onlineMembers: make(map[string]*userSession),
			publicChannel: v.Public,
			offlineMembers: make(map[string]string),
			offlineMemberCount: len(v.Users),
		}
		if(!v.Public){
			for _,u := range v.Users {
				a.channelMemberListCache[v.ID].offlineMembers[u.ID]=u.ID
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
		WHERE rn <= 50
		ORDER BY channel_id, time DESC
	`).Scan(&msgs)

	slices.Reverse(msgs)

	for _,v := range msgs {
		a.messages[v.ChannelID] = append(a.messages[v.ChannelID], chatMsg{
			sender: v.SenderID,
			text: v.Content,
			time: v.Time,
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



			if(err==nil){
				// We found the user
				// check password
				if(VerifyPassword(password, user.Password)){
					// Password was correct, we are good to go
					
					a.mu.Lock()
					_, ok := a.sessions[ctx.User()]
					if(!ok){
						a.sessionUsernames[ctx.SessionID()]=ctx.User()
					}
					a.mu.Unlock()
					if(!ok){
						ctx.SetValue("auth_status", "ok")
					}else{
						ctx.SetValue("auth_status", "fail")
						ctx.SetValue("auth_msg", "You are already logged in")
					}
					return true
				}else{
					// We don't know if they got the password wrong or were trying to make an account with that username
					// So we just send them to the register page
					ctx.SetValue("auth_status", "fail")
					ctx.SetValue("password", password)
					ctx.SetValue("auth_msg", "Username taken")
					return true
				}
			}else{
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
			if(!ok){

				// User wasn't logged in
				// Just clean them up from the sessions list
				a.mu.Lock()
				delete(a.sessions, s.Context().SessionID())
				delete(a.sessionUsernames, s.Context().SessionID())
				a.mu.Unlock()
			}else{


				// Update channel list for all their channels
				updateChannelMemberList(updateChannelMemberListParameters{
					app: a,
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



	model := initialModel(a, 120, 30, s)
	model.app = a

	// Only fetch channels if theyre actually authed


	updateChatLines(&model)
	updateChannelList(&model)
	updateRegistrationTextFocuses(&model)

	if(s.Context().Value("auth_status")=="fail"){
		msg := s.Context().Value("auth_msg").(string)
		model.viewRegistrationModel.feedbackViewport.SetContent(msg)
	}

    opts := append([]tea.ProgramOption{}, bubbletea.MakeOptions(s)...)
    p := tea.NewProgram(model, opts...)


	if(s.Context().Value("auth_status")=="ok"){

		// Add session to db
		a.mu.Lock()
		a.sessions[s.User()]=&userSession{
			prog: p,
			loggedIn: true,
			username: s.User(),
			currentChannelId: "global",
			joinedChannels: []string{},
		}
		a.mu.Unlock()
		go p.Send(channelList(channelList{
			channels: joinedHandleChannels(&model),
			firstjoin: false,
		}))
	}else{
		// We give it a temporary 'username' using the session id

		a.mu.Lock()
		a.sessions[s.Context().SessionID()]=&userSession{
			prog: p,
			loggedIn: false,
			username: "",
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

	if(err!=nil){
		log.Error("Could not parse invalid configuration.")
        // Set defaults
        config = serverConfig{
			Host: "0.0.0.0",
			Port: "2222",
			ServerName: "isle.chat",
			AdminUsername: "admin",
			BotUsername: "islebot",
			GlobalBanner: `                              ⢶⣄              ⠉⠛⢓⣶⣦⢿⣦⣴⡖⠛⠋          ⠚⠋⠁⢠⣿⠃⠉⠉⠛⠒⠂  isle.chat⢀⣾⠇        v0.0.0   ⣼⡟         #global ⢰⣿⠁          ⢀⣠⣤⣤⣴⣶⣶⣾⣯⣤⣤⣤⣤⣤⣀⣀   ⠰⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠦                     `,
			AnnouncementChannel: "news",
			DefaultBanner: `                              ⢶⣄              ⠉⠛⢓⣶⣦⢿⣦⣴⡖⠛⠋          ⠚⠋⠁⢠⣿⠃⠉⠉⠛⠒⠂  isle.chat⢀⣾⠇        v0.0.0   ⣼⡟         default ⢰⣿⠁          ⢀⣠⣤⣤⣴⣶⣶⣾⣯⣤⣤⣤⣤⣤⣀⣀   ⠰⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠦                     `,
			WelcomeMessage: "A new user joined for the first time! Welcome @%s. Run /help for information and arrow keys to navigate",
			FilterPublicMessages: false,
			RegistrationHeader: "isle.chat registration   ",
			DatabaseMode: "sqlite",
			PostgresHost: "localhost",
			PostgresUser: "islechat",
			PostgresPassword: "password",
			PostgresDBName: "islechat",
			PostgresPort: "5432",
			PostgresSSL: "disable",
				
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
	
	if(config.DatabaseMode=="sqlite"){
		db, err = gorm.Open(sqlite.Open("islechat.db"), &gorm.Config{})
	}else{
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
			ID: config.BotUsername,
			Password: "",
			Channels: make([]Channel, 0),
		},}) 
	db.Clauses(clause.OnConflict{DoNothing: true}).Create(&[]Channel{
		{
			ID: "global",
			OwnerID: config.BotUsername,
			Banner: `                              ⢶⣄              ⠉⠛⢓⣶⣦⢿⣦⣴⡖⠛⠋          ⠚⠋⠁⢠⣿⠃⠉⠉⠛⠒⠂  isle.chat⢀⣾⠇        v0.0.0   ⣼⡟         #global ⢰⣿⠁          ⢀⣠⣤⣤⣴⣶⣶⣾⣯⣤⣤⣤⣤⣤⣀⣀   ⠰⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠦                     `,
			Public: true,
		},}) 

	app := newApp(db, config)


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
	channelBanner string
	id          string
	textarea    textarea.Model
	senderStyle lipgloss.Style
	dateStyle lipgloss.Style
	err         error
	memberList *channelMemberList
	focus FocusedBox
	windowHeight int
	windowWidth int
	alert   bubbleup.AlertModel
}

type model struct {
	*app

	viewMode viewMode
	viewChatModel viewChatModel
	viewRegistrationModel viewRegistrationModel
}

type channelList struct {
	channels []userChannelState
	firstjoin bool
}


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
	uvp := viewport.New(20, max(0,height-13))
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



// For only when a user joins the main area (From logging in or just signing up)
func joinedHandleChannels(m *model) []userChannelState  {
	// Update the users channel list from the DB
	// Update the user list for everyone in their channels

	channels := make([]userChannelState, 0)

	var channelIDs []string

	channels = append(channels, userChannelState{
		channelId: "global",
		unread: 0,
	})

	// We query the join table specifically to get the IDs for this User
	err := m.app.db.Table("user_channels").
		Where("user_id = ?", m.viewChatModel.id).
		Order("channel_id DESC").
		Pluck("channel_id", &channelIDs).Error


	if(err!=nil){
		log.Error(err)
		return []userChannelState{}
	}

	// Adding the channels for the user
	for _, channel := range channelIDs {
		if(channel!="global"){
			channels = append(channels, userChannelState{
				channelId: channel,
				unread: 0,
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
		app: m.app,
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

	ta.SetWidth(width-47)
	ta.SetHeight(3)

	// Remove cursor line styling
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()

	ta.ShowLineNumbers = false

	mvp := getNewMessageHistoryViewport(a, width, height, FocusedBoxChatInput)
	uvp := getNewUserListViewport(a, width, height, FocusedBoxChatInput)
	cvp := getNewChannelListViewport(a, width, height, FocusedBoxChatInput)

	ta.KeyMap.InsertNewline.SetEnabled(false)
	a.mu.RLock()
	previousMsgs := a.messages["global"]
	msgsCopy := make([]chatMsg, len(previousMsgs))
	copy(msgsCopy, previousMsgs)	
	a.mu.RUnlock()
	channelList := make([]userChannelState, 0)
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


		
		// Add session to db
		return model{

			viewMode: viewChat,

			viewChatModel: viewChatModel{
				id: sess.User(),
				textarea:    ta,
				messages:    msgsCopy,
				messageHistoryViewport:    mvp,
				userListViewport: uvp,
				channelListViewport: cvp,
				senderStyle: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5")),
				dateStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("238")),
				currentChannel: 0,
				channels: channelList,
				channelBanner: `⠀⣠⣴⣦⣽⣿⣾⣿⣷⣟⣋⡁⠀⠀ 
								⠀⢀⣬⣽⣿⣿⣿⣿⣿⣿⣿⠿⠗⠀ 
								⠠⠛⠋⢩⣿⡟⣿⣏⠙⠻⢿⣷⠀⠀ 
								⠀⠀⠀⡿⠋⠀⡟⢻⡀⠀⠀⠈⠃⠀ 
								⠀⠀⠀⠀⠀⠘⠁⢸⡇⠀⠀⠀⠀⠀ 
								⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀isle.chat 
								⠀⠀⠀⠀⠀⠀⠀⣾⡇⠀loading..
								⠀⠀⠀⠀⠀⠀⣀⣿⡇⠀⠀⠀⠀⠀ 
								⠀⢀⣄⣶⣿⣿⣟⣻⣻⣯⣕⣒⣄⡀  `,
				err:         nil,
				memberList: a.channelMemberListCache["global"],
				focus: FocusedBoxChatInput,	
				alert: *bubbleup.NewAlertModel(40, false, 2),
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
				id: sess.Context().SessionID(),
				textarea:    ta,
				messages:    msgsCopy,
				messageHistoryViewport:    mvp,
				userListViewport: uvp,
				channelListViewport: cvp,
				senderStyle: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5")),
				dateStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("238")),
				currentChannel: 0,
				channels: channelList,
				err:         nil,
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
				focus: FocusedBoxChatInput,
				alert: *bubbleup.NewAlertModel(40, false, 2),

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
	return m.viewChatModel.alert.Init()
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
	var content strings.Builder
    
    onlineStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	offlineStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))


    for _, v := range m.viewChatModel.memberList.onlineMembers {
        line := fmt.Sprintf("@%s", v.username)
        content.WriteString(onlineStyle.Render(line) + "\n")
    }

    for _, v := range m.viewChatModel.memberList.offlineMembers {
        line := fmt.Sprintf("@%s", v)
        content.WriteString(offlineStyle.Render(line) + "\n")
    }

    m.viewChatModel.userListViewport.SetContent(content.String())
}

func updateChannelList(m *model){

	focused := m.viewChatModel.focus == FocusedBoxChannelList

	channelListText := ""

	currentChannel := lipgloss.NewStyle().Background(lipgloss.Color("240")).Foreground(lipgloss.Color("15"))
	currentChannelFocused := lipgloss.NewStyle().Background(lipgloss.Color("84")).Foreground(lipgloss.Color("240"))
	otherChannel := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	otherChannelUnread := lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	notificationCount := lipgloss.NewStyle().Foreground(lipgloss.Color("87"))
	for _, v := range m.viewChatModel.channels {
		if(m.viewChatModel.channels[m.viewChatModel.currentChannel]==v){
			if(focused){
				channelListText+=currentChannelFocused.Render(fmt.Sprintf("# %-18s", v.channelId))+"\n"
			}else{
				channelListText+=currentChannel.Render(fmt.Sprintf("# %-18s", v.channelId))+"\n"
			}
		}else{
			if(v.unread>0){
				if(v.unread>9){
					channelListText+=otherChannelUnread.Render(fmt.Sprintf("# %-13s  ", v.channelId))+
					notificationCount.Render("9+ ")+"\n"
				}else{
					channelListText+=otherChannelUnread.Render(fmt.Sprintf("# %-13s   ", v.channelId))+
					notificationCount.Render(fmt.Sprintf("%d  ", v.unread))+"\n"
				}
			}else{
				channelListText+=otherChannel.Render(fmt.Sprintf("# %-18s", v.channelId))+"\n"
			}
		}
	}

	if(m.viewChatModel.currentChannel<len(m.viewChatModel.channels)){
		channel, ok := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
		if(ok){
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
		time := m.viewChatModel.dateStyle.Render(fmt.Sprintf(" %02d:%02d UTC ", v.time.Hour(), v.time.Minute()))
		if(i==0 || m.viewChatModel.messages[i-1].sender!=v.sender){
			if(v.sender==m.app.config.BotUsername){
				newMessage+="\n"+botSenderStyle.Render(v.sender)+" "+botMsg+""+time+"\n"
			}else if(v.sender==m.app.config.AdminUsername){
				newMessage+="\n"+m.viewChatModel.senderStyle.Render(v.sender)+" "+adminMsg+""+time+"\n"
			}else{
				newMessage+="\n"+m.viewChatModel.senderStyle.Render(v.sender)+time+"\n"
			}
		}
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
	channelId := m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId
	
	m.app.mu.RLock()
	originalMsgs := m.app.messages[channelId]
	m.viewChatModel.messages = make([]chatMsg, len(originalMsgs))
	copy(m.viewChatModel.messages, originalMsgs)
	m.app.mu.RUnlock()
	
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

	if(err!=nil){
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
func removeUserFromChannel(app *app, user string, channel string) bool {

	dbuser := User{ID: user}

	err := app.db.Model(&dbuser).Association("Channels").Delete(&Channel{ID: channel})

	if(err!=nil){
		// Error was encountered and user couldn't be added
		return false
	}

	app.mu.Lock()
	joinedChannels := app.sessions[user].joinedChannels
	newJoinedChannels := make([]string, 0)
	for _, v := range joinedChannels{
		if(v!=channel){
			newJoinedChannels = append(newJoinedChannels, v)
		}
	}
	app.sessions[user].joinedChannels = newJoinedChannels
	app.mu.Unlock()

	return true	
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

type memberList []*userSession

type channelMemberList struct {
	// Store user lists as a map for O(1) insert/remove
	// user id -> user session
	onlineMembers map[string]*userSession
	// This will be empty if the channel is public as 
	// public channels won't list offline members, they 
	// will just display the count
	publicChannel bool
	offlineMembers map[string]string
	offlineMemberCount int

}

type channelMemberListMsg *channelMemberList

// times the user list needs to be updated
// [] user joined from login
//  -> update all the channels theyre in
// [] user joined from registration
//  -> update the general channel
// [] user joined channel
//  -> only update that channel
// [] user left channel
//  -> only update that channel
// [] user disconnected
//  -> update all the channels theyre in

type UserChannelDelta int

const (
	UserChannelJoin UserChannelDelta = iota
	UserChannnelLeave
	UserChannelOffline
	UserChannelOnline
)


type updateChannelMemberListParameters struct {
	app *app
	userId string
	change UserChannelDelta
	channelId string
}



// The sole purpose of this is pushing the channel member list changes to 
// anyone in those channels, it doesnt handle the other state stuff
func updateChannelMemberList(params updateChannelMemberListParameters){
	if(params.app==nil || params.userId==""){
		// invalid
		log.Error("Invalid update channel member list call")
		return
	}

	// If no channel was provided we will do it for all their channels
	if(params.channelId==""){
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

	}else{
		params.app.mu.Lock()
		isPublic := params.app.channels[params.channelId].Public

		// We only need to update that one channel

		if(params.change==UserChannelJoin || params.change == UserChannelOnline){

			params.app.channelMemberListCache[params.channelId].onlineMembers[params.userId]=params.app.sessions[params.userId]

			if(params.change == UserChannelOnline){
				delete(params.app.channelMemberListCache[params.channelId].offlineMembers, params.userId)
				params.app.channelMemberListCache[params.channelId].offlineMemberCount--
			}
		}else{
			delete(params.app.channelMemberListCache[params.channelId].onlineMembers, params.userId)

			if(params.change == UserChannelOffline){
				params.app.channelMemberListCache[params.channelId].offlineMemberCount++
				if(!isPublic){
					params.app.channelMemberListCache[params.channelId].offlineMembers[params.userId]=params.userId
				}
			}
		}

		online := params.app.channelMemberListCache[params.channelId].onlineMembers
		state := params.app.channelMemberListCache[params.channelId]
		params.app.mu.Unlock()

		for _, v := range online {
			if(v.currentChannelId==params.channelId){
				go v.prog.Send(channelMemberListMsg(state))
			}
		}
	}
}

func sendIslebotMessage(m *model, msg string){
	localMsg := chatMsg{
		sender: m.app.config.BotUsername,
		text: msg,
		time: time.Now(),
		channel: m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId,
	}
	m.viewChatModel.messages = append(m.viewChatModel.messages, localMsg)
	updateChatLines(m)
}

func sendIslebotMessagePermanent(app *app, message string, channel string){

	app.sendMessage(chatMsg{
		sender: app.config.BotUsername,
		text: message,
		time: time.Now(),
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

func updatedChatFocus(m *model){
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

type newBannerMsg string

// func updateWindowTitle

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
			tiCmd tea.Cmd
			mvpCmd tea.Cmd
			uvpCmd tea.Cmd
			alertCmd tea.Cmd
		)
	switch m.viewMode {

		case viewChat:
			switch msg := msg.(type) {

			case tea.KeyMsg:
				// Update viewports for keyboard input
				m.viewChatModel.messageHistoryViewport, mvpCmd = m.viewChatModel.messageHistoryViewport.Update(msg)
				m.viewChatModel.userListViewport, uvpCmd = m.viewChatModel.userListViewport.Update(msg)

				switch msg.Type {
				case tea.KeyCtrlC, tea.KeyEsc:
					return m, tea.Quit
				case tea.KeyEnter:
					if m.viewChatModel.textarea.Value() != "" {

						if(m.viewChatModel.textarea.Value()[0]=='/'){
							// Its a command!
							command := strings.Split(m.viewChatModel.textarea.Value()[1:], " ")
							if(len(command)>0){
								switch strings.ToLower(command[0]){
									case "ping":
										myCustomAlert := bubbleup.AlertDefinition{
											Key: "invitenotif",
											Prefix: "",
											ForeColor: "#17b27eff",
											Style: lipgloss.NewStyle().
											BorderStyle(lipgloss.NormalBorder()).
											Background(lipgloss.Color("235")).
											Foreground(lipgloss.Color("15")).
											BorderForeground(lipgloss.Color("121")),
										}
										m.viewChatModel.alert.RegisterNewAlertType(myCustomAlert)
										sendIslebotMessage(&m, "pong")
										alertCmd = m.viewChatModel.alert.NewAlertCmd("invitenotif", "You have been invited to #0123456789")
									case "chan":

										chanHelpMsg :=  `Commands:
  /chan create <name>
  /chan public
  /chan private
  /chan invite <user>
  /chan uninvite <user>
  /chan join <name>
  /chan leave
  /chan banner <text>
 For updates join #`+m.app.config.AnnouncementChannel

										if(len(command)>1){
											switch command[1]{
												case "create":
													if(len(command)==3){
														newChannelName := strings.ToLower(command[2])

														// Check if the name exists
														channel,ok := m.app.channels[newChannelName]

														if(ok){
															//
															if(channel.Public){
																sendIslebotMessage(&m, fmt.Sprintf("Sorry but the channel #%s already exists, it was created by @%s. The channel is public so you can join with /chan join %s", newChannelName, channel.OwnerID, newChannelName))
															}else{
																sendIslebotMessage(&m, fmt.Sprintf("Sorry but the channel #%s already exists, it was created by @%s. The channel is private so you can join once invited", newChannelName, channel.OwnerID))
															}
														}else{

															// Validate the name
															match, _ := regexp.MatchString("^[a-zA-Z0-9_-]{1,10}$", newChannelName)

															if(match){
																// Name was OK
																newChannel := Channel{
																	ID: newChannelName,
																	OwnerID: m.viewChatModel.id,
																	Banner: "Default channel banner :(",
																	Public: true,
																	ReadOnly: false,
																}
																err := gorm.G[Channel](m.db).Create(context.Background(), &newChannel)

																if(err!=nil){
																	sendIslebotMessage(&m, "Sorry but there was an error whilst creating the channel")
																}else{

																	// New channel was made
																	m.app.mu.Lock()
																	m.app.messages[newChannelName]=make([]chatMsg, 0)
																	m.app.channelMemberListCache[newChannelName]=&channelMemberList{
																		onlineMembers: make(map[string]*userSession),
																		publicChannel: true,
																		offlineMembers: make(map[string]string),
																		offlineMemberCount: 0,
																	}
																	m.app.channels[newChannelName] = &newChannel
																	m.app.mu.Unlock()

																	// chan id might change so save it first then find it and change it

																	oldCurChan := m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId
																	addUserToChannel(m.app, m.viewChatModel.id, newChannelName)

																	for i, c := range m.viewChatModel.channels {
																		if(c.channelId==oldCurChan){
																			m.viewChatModel.currentChannel = i
																		}
																	}

																	m.viewChatModel.channels = append(m.viewChatModel.channels, userChannelState{
																		channelId: newChannelName,
																		unread: 0,
																	})

																	updateChannelMemberList(updateChannelMemberListParameters{
																		app: m.app,
																		userId: m.viewChatModel.id,
																		change: UserChannelJoin,
																		channelId: newChannelName,	
																	})

																	updateChannelList(&m)
																}
															}else{
																sendIslebotMessage(&m, "Invalid name. Please use 1–10 letters, numbers, underscores, or hyphens.")
															}
														}
													}else{
														sendIslebotMessage(&m, "Usage: /chan create [name]")
													}
												case "join":

													if(len(command)==3){
														m.app.mu.RLock()
														channel, ok := m.app.channels[command[2]]
														m.app.mu.RUnlock()
														if(ok){
															channelName := command[2]
															userId := m.viewChatModel.id
															if(channel.Public){
																m.app.mu.RLock()
																_, ok := m.app.channelMemberListCache[channelName].onlineMembers[userId]
																m.app.mu.RUnlock()
																if(!ok){
																	addUserToChannel(m.app, userId, channelName)
																	updateChannelMemberList(updateChannelMemberListParameters{
																		app: m.app,
																		userId: userId,
																		change: UserChannelJoin,
																		channelId: channelName,
																	})
																	m.viewChatModel.channels = append(m.viewChatModel.channels, userChannelState{
																		channelId: channelName,
																		unread: 0,
																	})
																	updateChannelList(&m)
																}else{
																	sendIslebotMessage(&m, fmt.Sprintf("You are already a member of #%s. You can leave it with /chan leave %s", channelName, channelName))
																}
															}else{
																_, err := gorm.G[Invite](m.db).
																		Where("user_id = ?", m.viewChatModel.id).
																		Where("channel_id = ?", channelName).
																		First(context.Background())
																if(err==nil){
																	_, err := gorm.G[Invite](m.db).
																		Where("user_id = ?", m.viewChatModel.id).
																		Where("channel_id = ?", channelName).
																		Delete(context.Background())

																	if(err==nil){
																		addUserToChannel(m.app, userId, channelName)
																		updateChannelMemberList(updateChannelMemberListParameters{
																			app: m.app,
																			userId: userId,
																			change: UserChannelJoin,
																			channelId: channelName,
																		})
																		m.viewChatModel.channels = append(m.viewChatModel.channels, userChannelState{
																			channelId: channelName,
																			unread: 0,
																		})
																		updateChannelList(&m)
																		sendIslebotMessagePermanent(m.app,  fmt.Sprintf("@%s joined the channel", m.viewChatModel.id), channelName)
																	}else{
																		sendIslebotMessage(&m, fmt.Sprintf("Sorry an error occured joining #%s", channelName))
																	}
																}else{
																	sendIslebotMessage(&m, fmt.Sprintf("The channel #%s is private and you can only join if you are invited. The owner can invite you with /chan invite %s", channelName, userId))
																}
															}

														}else{
															sendIslebotMessage(&m, "Couldn't find a channel with that name. You can create it with /chan create <name>")
														}
													}else{
														sendIslebotMessage(&m, "Usage: /chan join [name]")
													}
												case "invite":
													if(len(command) == 3){
														targetUser := command[2]
														m.app.mu.RLock()
														channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
														m.app.mu.RUnlock()
														if(channel.OwnerID==m.viewChatModel.id){
															if(!channel.Public){

																m.app.mu.RLock()
																_, onlineok := m.app.channelMemberListCache[channel.ID].onlineMembers[targetUser]
																_, offlineok := m.app.channelMemberListCache[channel.ID].offlineMembers[targetUser]
																m.app.mu.RUnlock()
																if(!onlineok && !offlineok){
																	// Check user exists
																	_, err := gorm.G[User](m.db).
																		Where("ID = ?", targetUser).
																		First(context.Background())

																	if(err==nil){
																		err := gorm.G[Invite](m.db).Create(context.Background(), &Invite{
																			UserID: targetUser,
																			ChannelID: channel.ID,
																		})
																		if(err==nil){
																			sendIslebotMessage(&m, fmt.Sprintf("The invite was sent to @%s, they can now join with /chan join %s", targetUser, channel.ID))
																		}else{
																			sendIslebotMessage(&m, fmt.Sprintf("The user @%s could not be invited to #%s. Either they are already invited or they do not exist", targetUser, channel.ID))
																		}
																	}else{
																		sendIslebotMessage(&m, fmt.Sprintf("No user could be found: @%s", targetUser))
																	}
																}else{
																	sendIslebotMessage(&m, fmt.Sprintf("The user @%s is already a member of #%s", targetUser, channel.ID))
																}
															}else{
																sendIslebotMessage(&m, fmt.Sprintf("This channel is public. Anyone can join with /chan join %s", channel.ID))
															}
														}else{
															sendIslebotMessage(&m, "You are not the owner of this channel")
														}
													}else{
														sendIslebotMessage(&m, "Usage: /chan invite [user]")
													}
												case "uninvite":
													if(len(command) == 3){
														targetUser := command[2]
														m.app.mu.RLock()
														channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
														m.app.mu.RUnlock()
														if(channel.OwnerID==m.viewChatModel.id){

															_, err := gorm.G[Invite](m.db).
																Where("user_id = ?", targetUser).
																Where("channel_id = ?", channel.ID).
																First(context.Background())

															if(err == nil){
																_, err := gorm.G[Invite](m.db).
																	Where("user_id = ?", targetUser).
																	Where("channel_id = ?", channel.ID).
																	Delete(context.Background())
																if(err == nil){
																	sendIslebotMessage(&m, fmt.Sprintf("The user @%s was uninvited from #%s", targetUser, channel.ID))
																}else{
																	sendIslebotMessage(&m, "Sorry but an error occured whilst revoking the invite")
																}
															}else{
																sendIslebotMessage(&m, "That user does not have an invite to this channel")
															}
														}else{
															sendIslebotMessage(&m, "You are not the owner of this channel")
														}
													}else{
														sendIslebotMessage(&m, "Usage: /chan uninvite [user]")
													}
												case "public":
													if(len(command) == 2){
														m.app.mu.RLock()
														channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
														m.app.mu.RUnlock()
														if(channel.OwnerID==m.viewChatModel.id){
															if(!channel.Public){
																// Update all the meta info and the DB
																_, err := gorm.G[Channel](m.app.db).Where("id = ?", channel.ID).
																	Update(context.Background(), "public", true)
																
																if(err==nil){
																	_, err := gorm.G[Invite](m.db).
																		Where("channel_id = ?", channel.ID).
																		Delete(context.Background())
																	if(err!=nil){
																		sendIslebotMessage(&m, fmt.Sprintf("Whilst making #%s public, invites could not be deleted", channel.ID))
																	}
																	sendIslebotMessage(&m, fmt.Sprintf("#%s is now public", channel.ID))
																	m.app.mu.Lock()
																	m.app.channels[channel.ID].Public = true
																	m.app.channelMemberListCache[channel.ID].offlineMemberCount = len(m.app.channelMemberListCache[channel.ID].offlineMembers)
																	m.app.channelMemberListCache[channel.ID].offlineMembers=make(map[string]string)
																	m.app.mu.Unlock()


																	m.app.mu.RLock()
																	// Update member list for everyone in it
																	for _, v := range m.app.channelMemberListCache[channel.ID].onlineMembers {
																		if(v.currentChannelId==channel.ID){
																			go v.prog.Send(channelMemberListMsg(m.app.channelMemberListCache[channel.ID]))
																		}
																	}
																	m.app.mu.RUnlock()
																}else{
																	sendIslebotMessage(&m, fmt.Sprintf("Sorry but an error occured whilst processing your command"))
																}
															}else{
																sendIslebotMessage(&m, fmt.Sprintf("This channel is already public. Anyone can join with /chan join %s", channel.ID))
															}
														}else{
															sendIslebotMessage(&m, "You are not the owner of this channel")
														}
													}else{
														sendIslebotMessage(&m, "Usage: /chan public")
													}
												case "private":
													if(len(command) == 2){
														m.app.mu.RLock()
														channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
														m.app.mu.RUnlock()
														if(channel.OwnerID==m.viewChatModel.id){
															if(channel.Public){
																var count int64
																err := m.db.
																	WithContext(context.Background()).
																	Table("user_channels").
																	Where("channel_id = ?", channel.ID).
																	Count(&count).
																	Error
																
																if(err==nil && count <= 300){
																	var ids []string
																	err := m.app.db.
																		Table("user_channels").
																		Where("channel_id = ?", channel.ID).
																		Pluck("user_id", &ids).
																		Error
																	if(err==nil){
																		_, err := gorm.G[Channel](m.app.db).Where("id = ?", channel.ID).
																			Update(context.Background(), "public", false)
																		if(err==nil){
																			m.app.mu.Lock()
																			m.app.channels[channel.ID].Public = false
																			for _, v := range ids {
																				m.app.channelMemberListCache[channel.ID].offlineMembers[v]=v
																			}
																			// No need to change offline count should be the exact same
																			for k, _ := range m.app.channelMemberListCache[channel.ID].onlineMembers {
																				delete(m.app.channelMemberListCache[channel.ID].offlineMembers, k)
																			}
																			for _, v := range m.app.channelMemberListCache[channel.ID].onlineMembers {
																				if(v.currentChannelId==channel.ID){
																					go v.prog.Send(channelMemberListMsg(m.app.channelMemberListCache[channel.ID]))
																				}
																			}
																			m.app.mu.Unlock()
																			sendIslebotMessage(&m, fmt.Sprintf("#%s is now private", channel.ID))
																		}else{
																			sendIslebotMessage(&m, "Sorry but an error occured whilst turning the channel private")
																		}
																		
																	}else{
																		sendIslebotMessage(&m, "Sorry but an error occured whilst turning the channel private")
																	}

																}else{
																	sendIslebotMessage(&m, fmt.Sprintf("Sorry but you cannot make a channel with over 300 members private"))
																}
															}else{
																sendIslebotMessage(&m, fmt.Sprintf("This channel is already private. You can invite members with /chan invite [user]"))
															}
														}else{
															sendIslebotMessage(&m, "You are not the owner of this channel")
														}
													}else{
														sendIslebotMessage(&m, "Usage: /chan private")
													}
												case "banner": 
													m.app.mu.RLock()
													channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
													m.app.mu.RUnlock()
													if(channel.OwnerID==m.viewChatModel.id){
														if(len(m.viewChatModel.textarea.Value())>12){
															banner := m.viewChatModel.textarea.Value()[13:]
															blen := BannerWidth(banner)
															if(blen>=2 && blen<=200){
																_, err := gorm.G[Channel](m.app.db).Where("id = ?", channel.ID).
																	Update(context.Background(), "banner", banner)
																if(err==nil){
																	m.app.mu.Lock()
																	m.app.channels[channel.ID].Banner=banner
																	m.app.mu.Unlock()

																	m.app.mu.RLock()
																	// Update user banners
																	for _, v := range m.app.channelMemberListCache[channel.ID].onlineMembers {
																		if(v.currentChannelId==channel.ID){
																			go v.prog.Send(newBannerMsg(banner))
																		}
																	}
																	m.app.mu.RUnlock()
																}else{
																	sendIslebotMessage(&m, "Sorry but an error occured whilst editing the banner")
																}
															}else{
																sendIslebotMessage(&m, "Banner is too small/large! Design one at https://isle.chat/banner")
															}
														}else{
															sendIslebotMessage(&m, "Use /banner <text> \nYou can design your banner at https://isle.chat/banner")
														}
														
													}else{
														sendIslebotMessage(&m, "You are not the owner of this channel")
													}
												case "leave":
													m.app.mu.RLock()
													channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
													m.app.mu.RUnlock()
													if(channel.OwnerID!=m.viewChatModel.id){
														if(channel.ID!="global"){

															removeUserFromChannel(m.app, m.viewChatModel.id, channel.ID)
															updateChannelMemberList(updateChannelMemberListParameters{
																app: m.app,
																userId: m.viewChatModel.id,
																change: UserChannnelLeave,
																channelId: channel.ID,
															})
															id := m.viewChatModel.currentChannel
															m.viewChatModel.channels = append(m.viewChatModel.channels[:id], m.viewChatModel.channels[id+1:]...)
															m.viewChatModel.currentChannel=0
															m.app.mu.Lock()
															m.app.sessions[m.viewChatModel.id].currentChannelId="global"
															m.viewChatModel.memberList=m.app.channelMemberListCache[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
															m.app.mu.Unlock()
															updateChannelList(&m)
															updateUserList(&m)
															reloadMessagesChannelSwitch(&m)
															if(!channel.Public){
																sendIslebotMessagePermanent(m.app, fmt.Sprintf("@%s left the channel", m.viewChatModel.id), channel.ID)
															}
														}else{
															sendIslebotMessage(&m, "You cannot leave #global")
														}
													}else{
														sendIslebotMessage(&m, "You are the owner of this channel. You cannot leave it but you can delete it with /chan delete")
													}
												case "delete":
													m.app.mu.RLock()
													channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
													m.app.mu.RUnlock()
													if(channel.OwnerID==m.viewChatModel.id){
														if(channel.ID!="global"){

															removeUserFromChannel(m.app, m.viewChatModel.id, channel.ID)
															updateChannelMemberList(updateChannelMemberListParameters{
																app: m.app,
																userId: m.viewChatModel.id,
																change: UserChannnelLeave,
																channelId: channel.ID,
															})
															id := m.viewChatModel.currentChannel
															m.viewChatModel.channels = append(m.viewChatModel.channels[:id], m.viewChatModel.channels[id+1:]...)
															m.viewChatModel.currentChannel=0
															m.app.mu.Lock()
															m.app.sessions[m.viewChatModel.id].currentChannelId="global"
															m.viewChatModel.memberList=m.app.channelMemberListCache[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
															m.app.mu.Unlock()
															updateChannelList(&m)
															updateUserList(&m)
															reloadMessagesChannelSwitch(&m)
															if(!channel.Public){
																sendIslebotMessagePermanent(m.app, fmt.Sprintf("@%s left the channel", m.viewChatModel.id), channel.ID)
															}
														}else{
															sendIslebotMessage(&m, "You cannot delete #global")
														}
													}else{
														sendIslebotMessage(&m, "You are not the owner of this channel.")
													}
												default:
													sendIslebotMessage(&m, chanHelpMsg)
											}
										}else{
											sendIslebotMessage(&m, chanHelpMsg)
										}
									case "help":
										sendIslebotMessage(&m, 
`Commands:
  /chan create <name>
  /chan public
  /chan private
  /chan invite <user>
  /chan uninvite <user>
  /chan join <name>
  /chan leave
  /chan banner <text>
 For updates join #`+m.app.config.AnnouncementChannel)
									default:
										m.viewChatModel.messages = append(m.viewChatModel.messages, chatMsg{
											sender: m.config.BotUsername,
											text: "I dont know that command. Try /help",
											time: time.Now(),
											channel: m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId,
										})
										updateChatLines(&m)
								}
							}
						}else{
							if(m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId == m.config.AnnouncementChannel && m.viewChatModel.id!=m.config.AdminUsername){
								sendIslebotMessage(&m, "Sorry you can't post in this channel")
							}else{
								m.app.sendMessage(chatMsg{
									sender: m.viewChatModel.id,
									text:   m.viewChatModel.textarea.Value(),
									time:   time.Now(),
									channel: m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId,
								})
							}

						}
						m.viewChatModel.textarea.Reset()
					}
				case tea.KeyTab:
					m.viewChatModel.focus++
					m.viewChatModel.focus %= FocusedTypesLength
					updatedChatFocus(&m)

				}

				// Handle additional controls from in the chat box (Left and up)

				if msg.Type == tea.KeyUp || (msg.Type == tea.KeyRunes && msg.Runes[0] == 'k') {
					if(m.viewChatModel.focus==FocusedBoxChannelList){
						if(m.viewChatModel.currentChannel>0){
							m.viewChatModel.currentChannel--
							m.app.mu.Lock()
							m.app.sessions[m.viewChatModel.id].currentChannelId=m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId
							m.viewChatModel.memberList=m.app.channelMemberListCache[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
							m.viewChatModel.channels[m.viewChatModel.currentChannel].unread=0
							m.app.mu.Unlock()
							updateChannelList(&m)
							updateUserList(&m)
							reloadMessagesChannelSwitch(&m)
						}
					}
					// Also allow going up from chat to chat history if your on the first line
					if(m.viewChatModel.focus==FocusedBoxChatInput && msg.Type == tea.KeyUp && m.viewChatModel.textarea.Line()==0){
						m.viewChatModel.focus = FocusedBoxChatHistory
						updatedChatFocus(&m)
					}
				}
				if msg.Type == tea.KeyDown || (msg.Type == tea.KeyRunes && msg.Runes[0] == 'j') {
					if(m.viewChatModel.focus==FocusedBoxChannelList){
						if(m.viewChatModel.currentChannel<len(m.viewChatModel.channels)-1){
							m.viewChatModel.currentChannel++
							m.app.mu.Lock()
							m.app.sessions[m.viewChatModel.id].currentChannelId=m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId
							m.viewChatModel.memberList=m.app.channelMemberListCache[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
							m.viewChatModel.channels[m.viewChatModel.currentChannel].unread=0
							m.app.mu.Unlock()
							updateChannelList(&m)
							updateUserList(&m)
							reloadMessagesChannelSwitch(&m)

						}
					}

					// Also allow going down from view history to chat if your at the bottom
					// Also allow using j key (We dont allow k in the chat box incase they want to type that it would be annoying)
					if(m.viewChatModel.focus==FocusedBoxChatHistory && m.viewChatModel.messageHistoryViewport.AtBottom()){
						m.viewChatModel.focus = FocusedBoxChatInput
						updatedChatFocus(&m)
					}
				}

				// Allow using right arrow key or l to go from channel list to chat box
				if msg.Type == tea.KeyRight || (msg.Type == tea.KeyRunes && msg.Runes[0] == 'l') {
					if(m.viewChatModel.focus==FocusedBoxChannelList){
						m.viewChatModel.focus = FocusedBoxChatHistory
						updatedChatFocus(&m)
					}else if(m.viewChatModel.focus == FocusedBoxChatHistory){
						m.viewChatModel.focus = FocusedBoxUserList
						updatedChatFocus(&m)
					}else if(msg.Type == tea.KeyRight && m.viewChatModel.focus == FocusedBoxChatInput){
						info := m.viewChatModel.textarea.LineInfo()
						// Only change focus if the cursor is at the end of the line
						if(info.CharOffset>=info.CharWidth-1){
							m.viewChatModel.focus = FocusedBoxUserList
							updatedChatFocus(&m)
						}
					}
				}

				// Allow using left arrow key or h to go from user list to chat box
				if msg.Type == tea.KeyLeft || (msg.Type == tea.KeyRunes && msg.Runes[0] == 'h') {
					if(m.viewChatModel.focus==FocusedBoxUserList){
						m.viewChatModel.focus = FocusedBoxChatHistory
						updatedChatFocus(&m)
					}else if(m.viewChatModel.focus == FocusedBoxChatHistory){
						m.viewChatModel.focus = FocusedBoxChannelList
						updatedChatFocus(&m)
					}else if(msg.Type == tea.KeyLeft && m.viewChatModel.focus == FocusedBoxChatInput){
						info := m.viewChatModel.textarea.LineInfo()
						if(info.RowOffset==0 && info.CharOffset==0){
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
				m.viewChatModel.textarea.SetWidth(max(0,msg.Width-47))
				updateChannelList(&m)
				updateChatLines(&m)
				updateUserList(&m)
			
			case chatMsg:
				if(msg.channel==m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId){
					m.viewChatModel.messages = append(m.viewChatModel.messages, msg)
				}else{
					for i,v := range m.viewChatModel.channels{
						if(v.channelId==msg.channel){
							m.viewChatModel.channels[i].unread++
						}
					}
				}
				updateChannelList(&m)
				updateChatLines(&m)
			case channelList:
				m.viewChatModel.channels = msg.channels
				if(msg.firstjoin){
					sendIslebotMessagePermanent(m.app, fmt.Sprintf("A new user joined for the first time! Welcome @%s. Run /help for information", m.viewChatModel.id), "global")

				}
				updateChannelList(&m)
			
			case channelMemberListMsg:
				m.viewChatModel.memberList=msg
				updateUserList(&m)
		

			case errMsg:
				m.viewChatModel.err = msg
				return m, nil
			}
			// Put it down here so we can do the other stuff first
			m.viewChatModel.textarea, tiCmd = m.viewChatModel.textarea.Update(msg)



		case viewRegistration:
			m.viewRegistrationModel.usernameInput, tiCmd = m.viewRegistrationModel.usernameInput.Update(msg)
			m.viewRegistrationModel.passwordInput, tiCmd = m.viewRegistrationModel.passwordInput.Update(msg)
			m.viewRegistrationModel.passwordConfirmInput, tiCmd = m.viewRegistrationModel.passwordConfirmInput.Update(msg)

			switch msg := msg.(type) {

			case tea.KeyMsg:
				if(msg.Type == tea.KeyCtrlC || msg.Type==tea.KeyEsc){
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

							re := regexp.MustCompile(`^[a-zA-Z0-9_-]{1,10}$`)
							if (!re.MatchString(newUsername)) {
								m.viewRegistrationModel.feedbackViewport.SetContent("Username contains bad chars")
								return m,nil
							}

							if(newUsername==m.app.config.BotUsername){
								m.viewRegistrationModel.feedbackViewport.SetContent("You cannot have this username")
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

							_, err = gorm.G[User](m.db).
								Where("LOWER(id) = ?", strings.ToLower(newUsername)).
								First(context.Background())

							if(err==nil){
								m.viewRegistrationModel.feedbackViewport.SetContent("Username already exists")
								return m,nil
							}

							err = gorm.G[User](m.db).Create(context.Background(), &User{
								ID: newUsername,
								Password: hashedPass,
								Channels: []Channel{},
							})

							if(err!=nil){
								m.viewRegistrationModel.feedbackViewport.SetContent("Username already exists")
								return m,nil
							}else{

								// delete old session create new session
								log.Info(fmt.Sprintf("id: %s", m.viewChatModel.id))
								m.app.mu.Lock()
								prog := m.app.sessions[m.viewChatModel.id].prog
								delete(m.app.sessions, m.viewChatModel.id)
								m.app.sessions[newUsername]=&userSession{
									prog: prog,
									loggedIn: true,
									username: newUsername,
									currentChannelId: "global",
									joinedChannels: []string{},
								}
								// Set username in sessionUsernames so session closing can be handled
								m.app.sessionUsernames[m.viewChatModel.id]=newUsername
								m.app.mu.Unlock()
								m.viewChatModel.id = newUsername
								// Add user to global channel
								addUserToChannel(m.app, newUsername, "global")
								m.viewMode=viewChat

								return m, tea.Batch(
									func() tea.Msg {
										return channelList(channelList{
													channels: joinedHandleChannels(&m),
													firstjoin: true,
												})
									},
								)
								// Account was created
							}
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
			case tea.WindowSizeMsg:
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

	outAlert, outCmd := m.viewChatModel.alert.Update(msg)
	m.viewChatModel.alert = outAlert.(bubbleup.AlertModel)

    return m, tea.Batch(tiCmd, mvpCmd, uvpCmd, outCmd, alertCmd)
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

	return bannerStyle.Render(banner)+ "\n"+ fmt.Sprintf("%s users online\n", humanize.Comma(int64(len(m.viewChatModel.memberList.onlineMembers)))) + 
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