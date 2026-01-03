package main

import (
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/ssh"
	"go.dalton.dog/bubbleup"
	"gorm.io/gorm"
	"sync"
	"time"
)

// Database models
type User struct {
	gorm.Model
	ID                     string `gorm:"primaryKey"`
	Password               string
	Channels               []Channel `gorm:"many2many:user_channels;"`
	Timezone               string    `gorm:"default:UTC"`
	LastLoginAt            time.Time
	LastSeenAt             time.Time
	LastNotificationSeenAt time.Time
}

type Message struct {
	gorm.Model
	SenderID  string  `gorm:"index"`
	Sender    User    `gorm:"foreignKey:SenderID"`
	Content   string  `gorm:"type:text"`
	ChannelID string  `gorm:"index"`
	Channel   Channel `gorm:"foreignKey:ChannelID"`
	Time      time.Time
}

type Invite struct {
	User      User
	UserID    string `gorm:"primaryKey"`
	Channel   Channel
	ChannelID string    `gorm:"primaryKey"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

type Notification struct {
	gorm.Model
	UserID string `gorm:"index"`
	Text   string `gorm:"type:text"`
}

type Ban struct {
	User      User
	UserID    string `gorm:"primaryKey"`
	Channel   Channel
	ChannelID string    `gorm:"primaryKey"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

type Channel struct {
	ID       string
	Owner    User
	OwnerID  string
	Banner   string
	Public   bool
	ReadOnly bool
	Users    []User `gorm:"many2many:user_channels;"`
}

// Configuration
type serverConfig struct {
	Host                 string
	Port                 string
	ServerName           string
	AdminUsername        string
	BotUsername          string
	GlobalBanner         string
	AnnouncementChannel  string
	DefaultBanner        string
	WelcomeMessage       string
	FilterPublicMessages bool
	RegistrationHeader   string
	DatabaseMode         string
	PostgresHost         string
	PostgresUser         string
	PostgresPassword     string
	PostgresDBName       string
	PostgresPort         string
	PostgresSSL          string
}

type app struct {
	*ssh.Server

	config   serverConfig
	db       *gorm.DB
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

	// Cached bans per channel
	bans map[string]map[string]struct{}

	// Map between session ids and logged-in usernames
	// Used for handling session disconnects
	// If the user isn't logged in the username will be nil
	sessionUsernames map[string]string

	timezoneEstimator timezoneEstimator
}

// Session types
type userSession struct {
	prog             *tea.Program
	loggedIn         bool
	username         string
	currentChannelId string
	inferredTimezone *time.Location
	joinedChannels   []string
}

// Message types
type chatMsg struct {
	sender  string
	text    string
	time    time.Time
	channel string
}

type errMsg error
type userlist []string

// UI focus types
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

// Channel state
type userChannelState struct {
	channelId string
	unread    int
}

// Notification state
type userNotification struct {
	id    string
	label string
	count int
	kind  string
}

// View models
type viewRegistrationModel struct {
	FocusedBox           RegistrationFocusedBox
	usernameInput        textinput.Model
	passwordInput        textinput.Model
	passwordConfirmInput textinput.Model
	confirmViewport      viewport.Model
	feedbackViewport     viewport.Model
}

type viewChatModel struct {
	messageHistoryViewport  viewport.Model
	userListViewport        viewport.Model
	channelListViewport     viewport.Model
	messages                []chatMsg
	channels                []userChannelState
	currentChannel          int
	channelListCursor       int
	channelBanner           string
	id                      string
	textarea                textarea.Model
	senderStyle             lipgloss.Style
	dateStyle               lipgloss.Style
	err                     error
	memberList              *channelMemberList
	focus                   FocusedBox
	windowHeight            int
	windowWidth             int
	alert                   bubbleup.AlertModel
	timezone                *time.Location
	sidebarsEnabled         bool
	commandSuggestions      []cmdSuggestion
	commandSuggestionInput  string
	commandSuggestionIndex  int
	commandSuggestionScroll int
	commandSuggestionMode   string
	notifications           []userNotification
	notificationUnread      int
	lastNotificationSeenAt  time.Time
	lastSeenAt              time.Time
	viewingNotifications    bool
}

type model struct {
	*app
	viewMode              viewMode
	viewChatModel         viewChatModel
	viewRegistrationModel viewRegistrationModel
}

// Channel list message
type channelList struct {
	channels  []userChannelState
	firstjoin bool
}

type notificationUpdate struct {
	notifications []userNotification
	unread        int
}

// Member list types
type memberList []*userSession

type channelMemberList struct {
	onlineMembers      map[string]*userSession
	publicChannel      bool
	offlineMembers     map[string]string
	offlineMemberCount int
}

type channelMemberListMsg *channelMemberList

type UserChannelDelta int

const (
	UserChannelJoin UserChannelDelta = iota
	UserChannnelLeave
	UserChannelOffline
	UserChannelOnline
)

type updateChannelMemberListParameters struct {
	app       *app
	userId    string
	change    UserChannelDelta
	channelId string
}

type newBannerMsg string

// The string is the id of the channel the user was removed from
type removedFromChannelMsg string

// BoxWithLabel for registration UI
type BoxWithLabel struct {
	BoxStyleFocused   lipgloss.Style
	BoxStyleUnfocused lipgloss.Style
	LabelStyle        lipgloss.Style
}
