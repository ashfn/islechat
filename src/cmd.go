package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"

	"gorm.io/gorm"
)

type cmdSuggestion struct {
	Display string
	Insert  string
	Desc    string
}

type cmdNode struct {
	Name    string
	Aliases []string
	Desc    string
	ArgHint string
	Help    func(m *model) string
	Run     func(m *model, args []string)

	Children map[string]*cmdNode // keyed by lower-case Name
}

func (n *cmdNode) add(child *cmdNode) {
	if n.Children == nil {
		n.Children = make(map[string]*cmdNode)
	}
	n.Children[strings.ToLower(child.Name)] = child
}

func (n *cmdNode) match(token string) (*cmdNode, bool) {
	if n == nil {
		return nil, false
	}
	lower := strings.ToLower(token)
	if child, ok := n.Children[lower]; ok {
		return child, true
	}
	for _, child := range n.Children {
		for _, a := range child.Aliases {
			if lower == strings.ToLower(a) {
				return child, true
			}
		}
	}
	return nil, false
}

func (n *cmdNode) childMatchesPrefix(prefix string) []*cmdNode {
	prefix = strings.ToLower(prefix)
	out := make([]*cmdNode, 0)
	for _, child := range n.Children {
		name := strings.ToLower(child.Name)
		if strings.HasPrefix(name, prefix) {
			out = append(out, child)
			continue
		}
		for _, a := range child.Aliases {
			if strings.HasPrefix(strings.ToLower(a), prefix) {
				out = append(out, child)
				break
			}
		}
	}
	slices.SortFunc(out, func(a, b *cmdNode) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

var rootCommands = buildCommandGraph()

var tzNamesOnce sync.Once
var tzNamesCache []string

func timezoneNames() []string {
	tzNamesOnce.Do(func() {
		roots := []string{
			"/usr/share/zoneinfo",
			"/usr/share/lib/zoneinfo",
		}

		seen := make(map[string]struct{})
		out := make([]string, 0)

		for _, root := range roots {
			info, err := os.Stat(root)
			if err != nil || !info.IsDir() {
				continue
			}

			err = fs.WalkDir(os.DirFS(root), ".", func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					name := d.Name()
					if name == "posix" || name == "right" {
						return filepath.SkipDir
					}
					return nil
				}

				name := filepath.ToSlash(p)
				base := filepath.Base(name)
				if strings.HasPrefix(base, ".") {
					return nil
				}
				switch base {
				case "localtime", "posixrules", "zone.tab", "zone1970.tab", "leapseconds", "tzdata.zi":
					return nil
				}
				if strings.HasSuffix(name, ".tab") {
					return nil
				}

				if _, ok := seen[name]; ok {
					return nil
				}
				seen[name] = struct{}{}
				out = append(out, name)
				return nil
			})
			_ = err
		}

		slices.Sort(out)
		if len(out) == 0 {
			out = []string{"UTC"}
		}
		tzNamesCache = out
	})
	return tzNamesCache
}

func mentionSuggestions(m *model, query string) []cmdSuggestion {
	queryLower := strings.ToLower(query)
	allowed := "a-zA-Z0-9_-"
	_ = allowed

	channelID := ""
	if m.viewChatModel.currentChannel < len(m.viewChatModel.channels) {
		channelID = m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId
	}

	m.app.mu.RLock()
	channel := m.app.channels[channelID]
	memberList := m.app.channelMemberListCache[channelID]
	m.app.mu.RUnlock()

	if channel == nil || memberList == nil {
		return nil
	}

	// Only online users
	candidates := make(map[string]string) // username -> status
	for _, sess := range memberList.onlineMembers {
		if sess == nil || sess.username == "" {
			continue
		}
		candidates[sess.username] = "online"
	}

	type scored struct {
		name  string
		score int
	}

	scoredUsers := make([]scored, 0, len(candidates))
	for name := range candidates {
		lower := strings.ToLower(name)
		score := 0
		if queryLower != "" {
			if strings.HasPrefix(lower, queryLower) {
				score = 0
			} else if strings.Contains(lower, queryLower) {
				score = 1
			} else {
				continue
			}
		}
		scoredUsers = append(scoredUsers, scored{name: name, score: score})
	}

	slices.SortFunc(scoredUsers, func(a, b scored) int {
		if a.score != b.score {
			return a.score - b.score
		}
		return strings.Compare(a.name, b.name)
	})

	out := make([]cmdSuggestion, 0, len(scoredUsers))
	for _, s := range scoredUsers {
		status := candidates[s.name]
		desc := "User"
		switch status {
		case "online":
			desc = "Online"
		case "offline":
			desc = "Offline"
		}
		out = append(out, cmdSuggestion{Display: "@" + s.name, Insert: s.name, Desc: desc})
	}
	return out
}

func timezoneSuggestions(m *model, base, prefix string) []cmdSuggestion {
	names := timezoneNames()
	prefixLower := strings.ToLower(prefix)

	matches := make([]string, 0, 50)

	if prefixLower == "" {
		// Keep the "no typing yet" case useful.
		preferred := []string{"UTC"}
		if m != nil && m.viewChatModel.timezone != nil {
			preferred = append([]string{m.viewChatModel.timezone.String()}, preferred...)
		}
		common := []string{"America/New_York", "America/Los_Angeles", "Europe/London", "Europe/Paris", "Asia/Tokyo", "Australia/Sydney"}
		preferred = append(preferred, common...)
		seen := make(map[string]struct{})
		for _, p := range preferred {
			if p == "" {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			matches = append(matches, p)
			if len(matches) >= 10 {
				break
			}
		}
	}

	q := strings.ToLower(prefix)
	q = strings.ReplaceAll(q, " ", "_")

	type tzMatch struct {
		name  string
		score int
	}

	matched := make([]tzMatch, 0, 50)
	for _, name := range names {
		lower := strings.ToLower(name)
		score := 0
		if q != "" {
			baseName := strings.ToLower(filepath.Base(name))
			switch {
			case strings.HasPrefix(lower, q):
				score = 0
			case strings.HasPrefix(baseName, q):
				score = 1
			case strings.Contains(lower, "/"+q):
				score = 2
			case strings.Contains(lower, q):
				score = 3
			default:
				continue
			}
		}
		matched = append(matched, tzMatch{name: name, score: score})
	}

	slices.SortFunc(matched, func(a, b tzMatch) int {
		if a.score != b.score {
			return a.score - b.score
		}
		return strings.Compare(a.name, b.name)
	})

	for _, m := range matched {
		matches = append(matches, m.name)
		if len(matches) >= 50 {
			break
		}
	}

	out := make([]cmdSuggestion, 0, len(matches))
	for _, name := range matches {
		cmd := base + " " + name
		out = append(out, cmdSuggestion{Display: cmd, Insert: cmd, Desc: "Timezone"})
	}
	return out
}

func buildCommandGraph() *cmdNode {
	root := &cmdNode{}

	chanHelp := func(m *model) string {
		return "Commands:\n" +
			"/whois <user>\n" +
			"/chan kick <user>\n" +
			"/chan ban <user>\n" +
			"/chan unban <user>\n" +
			"/chan create <name>\n" +
			"/chan public\n" +
			"/chan private\n" +
			"/chan invite <user>\n" +
			"/chan uninvite <user>\n" +
			"/chan join <name>\n" +
			"/chan leave\n" +
			"/chan banner <text>\n" +
			"/chan delete\n" +
			"For updates join #" + m.app.config.AnnouncementChannel
	}

	chanNode := &cmdNode{
		Name: "chan",
		Desc: "Channel tools",
		Help: chanHelp,
		Run: func(m *model, _ []string) {
			sendIslebotMessage(m, chanHelp(m))
		},
	}
	chanNode.add(&cmdNode{Name: "create", Desc: "Create a channel", ArgHint: "<name>", Run: runChanCreate})
	chanNode.add(&cmdNode{Name: "public", Desc: "Make current channel public", Run: runChanPublic})
	chanNode.add(&cmdNode{Name: "private", Desc: "Make current channel private", Run: runChanPrivate})
	chanNode.add(&cmdNode{Name: "invite", Desc: "Invite a user", ArgHint: "<user>", Run: runChanInvite})
	chanNode.add(&cmdNode{Name: "uninvite", Desc: "Revoke an invite", ArgHint: "<user>", Run: runChanUninvite})
	chanNode.add(&cmdNode{Name: "join", Desc: "Join a channel", ArgHint: "<name>", Run: runChanJoin})
	chanNode.add(&cmdNode{Name: "leave", Desc: "Leave current channel", Run: runChanLeave})
	chanNode.add(&cmdNode{Name: "banner", Desc: "Set channel banner", ArgHint: "<text>", Run: runChanBanner})
	chanNode.add(&cmdNode{Name: "delete", Desc: "Delete current channel", Run: runChanDelete})
	chanNode.add(&cmdNode{Name: "kick", Desc: "Kick user from channel", ArgHint: "<user>", Run: runChanKick})
	chanNode.add(&cmdNode{Name: "ban", Desc: "Ban user from channel", ArgHint: "<user>", Run: runChanBan})
	chanNode.add(&cmdNode{Name: "unban", Desc: "Unban user from channel", ArgHint: "<user>", Run: runChanUnban})
	root.add(chanNode)

	root.add(&cmdNode{
		Name: "help",
		Desc: "Show help",
		Run: func(m *model, _ []string) {
			sendIslebotMessage(m, chanHelp(m))
		},
	})

	root.add(&cmdNode{Name: "whois", Desc: "Show user info", ArgHint: "<user>", Run: runWhois})

	tzNode := &cmdNode{
		Name:    "tz",
		Aliases: []string{"timezone"},
		Desc:    "Show/set your timezone",
		ArgHint: "<timezone>",
		Run:     runTimezone,
	}
	root.add(tzNode)

	return root
}

func handleCmd(m *model, command []string) {
	if len(command) == 0 {
		return
	}

	root := rootCommands
	node := root
	args := command
	for len(args) > 0 {
		child, ok := node.match(args[0])
		if !ok {
			break
		}
		node = child
		args = args[1:]
		if len(args) == 0 {
			break
		}
	}

	// If we ended on a node that can run, run it with remaining args.
	if node != nil && node.Run != nil {
		node.Run(m, args)
		return
	}

	// If we ended on a node with help, show it.
	if node != nil && node.Help != nil {
		sendIslebotMessage(m, node.Help(m))
		return
	}

	m.viewChatModel.messages = append(m.viewChatModel.messages, chatMsg{
		sender:  m.config.BotUsername,
		text:    "I dont know that command. Try /help",
		time:    time.Now(),
		channel: m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId,
	})
	updateChatLines(m)
}

func updateCommandSuggestions(m *model) {
	input := m.viewChatModel.textarea.Value()

	suggestions := []cmdSuggestion(nil)
	mode := ""

	if strings.HasPrefix(input, "/") {
		suggestions = suggestCommands(m, input)
		mode = "command"
	} else {
		// Mention autocomplete (end-of-input token)
		allowed := "a-zA-Z0-9_-"
		re := regexp.MustCompile("(^|[^" + allowed + "])@([" + allowed + "]{0,10})$")
		sub := re.FindStringSubmatch(input)
		if len(sub) == 3 {
			suggestions = mentionSuggestions(m, sub[2])
			mode = "mention"
		}
	}

	if len(suggestions) == 0 {
		m.viewChatModel.commandSuggestions = nil
		m.viewChatModel.commandSuggestionInput = input
		m.viewChatModel.commandSuggestionIndex = 0
		m.viewChatModel.commandSuggestionScroll = 0
		m.viewChatModel.commandSuggestionMode = ""
		return
	}
	if len(suggestions) > 50 {
		suggestions = suggestions[:50]
	}

	sameInput := input == m.viewChatModel.commandSuggestionInput
	sameMode := mode == m.viewChatModel.commandSuggestionMode
	sameSuggestions := sameInput && sameMode && cmdSuggestionsEqual(m.viewChatModel.commandSuggestions, suggestions)

	m.viewChatModel.commandSuggestions = suggestions
	m.viewChatModel.commandSuggestionInput = input
	m.viewChatModel.commandSuggestionMode = mode

	if !sameSuggestions {
		m.viewChatModel.commandSuggestionIndex = 0
		m.viewChatModel.commandSuggestionScroll = 0
		return
	}

	// Clamp index/scroll in case list size changed.
	if m.viewChatModel.commandSuggestionIndex >= len(m.viewChatModel.commandSuggestions) {
		m.viewChatModel.commandSuggestionIndex = max(0, len(m.viewChatModel.commandSuggestions)-1)
	}
	if m.viewChatModel.commandSuggestionScroll >= len(m.viewChatModel.commandSuggestions) {
		m.viewChatModel.commandSuggestionScroll = max(0, len(m.viewChatModel.commandSuggestions)-1)
	}
}

func cmdSuggestionsEqual(a, b []cmdSuggestion) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Display != b[i].Display {
			return false
		}
		if a[i].Insert != b[i].Insert {
			return false
		}
		if a[i].Desc != b[i].Desc {
			return false
		}
	}
	return true
}

func normalizeUserPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.TrimPrefix(prefix, "@")
	return prefix
}

func isCurrentChannelOwner(m *model) bool {
	if m == nil || m.app == nil {
		return false
	}
	m.app.mu.RLock()
	defer m.app.mu.RUnlock()
	if m.viewChatModel.currentChannel >= len(m.viewChatModel.channels) {
		return false
	}
	channelID := m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId
	channel := m.app.channels[channelID]
	if channel == nil {
		return false
	}
	return channel.OwnerID == m.viewChatModel.id
}

func userArgSuggestions(m *model, base, prefix string) []cmdSuggestion {
	prefix = normalizeUserPrefix(prefix)
	prefixLower := strings.ToLower(prefix)

	out := make([]cmdSuggestion, 0, 50)
	seen := make(map[string]struct{})

	kickBanOnly := strings.HasPrefix(base, "/chan kick") || strings.HasPrefix(base, "/chan ban")
	unbanOnly := strings.HasPrefix(base, "/chan unban")

	candidatesMap := make(map[string]string)
	if m != nil && m.app != nil {
		if kickBanOnly {
			m.app.mu.RLock()
			if m.viewChatModel.currentChannel < len(m.viewChatModel.channels) {
				channelID := m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId
				if ml, ok := m.app.channelMemberListCache[channelID]; ok {
					for name, sess := range ml.onlineMembers {
						if sess == nil || name == "" {
							continue
						}
						candidatesMap[name] = "Online"
					}
					for name := range ml.offlineMembers {
						if name == "" {
							continue
						}
						if _, exists := candidatesMap[name]; !exists {
							candidatesMap[name] = "Offline"
						}
					}
				}
				var members []string
				_ = m.app.db.WithContext(context.Background()).
					Table("user_channels").
					Where("channel_id = ?", channelID).
					Pluck("user_id", &members).Error
				for _, name := range members {
					if name == "" {
						continue
					}
					if _, exists := candidatesMap[name]; !exists {
						candidatesMap[name] = "Offline"
					}
				}
			}
			m.app.mu.RUnlock()
		} else if unbanOnly {
			m.app.mu.RLock()
			if m.viewChatModel.currentChannel < len(m.viewChatModel.channels) {
				channelID := m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId
				var banned []string
				_ = m.app.db.WithContext(context.Background()).
					Table("bans").
					Where("channel_id = ?", channelID).
					Pluck("user_id", &banned).Error
				for _, name := range banned {
					if name == "" {
						continue
					}
					if sess, ok := m.app.sessions[name]; ok && sess != nil && sess.loggedIn {
						candidatesMap[name] = "Banned (online)"
					} else {
						candidatesMap[name] = "Banned"
					}
				}
			}
			m.app.mu.RUnlock()
		} else {
			m.app.mu.RLock()
			for name, sess := range m.app.sessions {
				if sess == nil || !sess.loggedIn || name == "" {
					continue
				}
				candidatesMap[name] = "Online"
			}
			m.app.mu.RUnlock()
		}
	}

	candidates := make([]string, 0, len(candidatesMap))
	for name := range candidatesMap {
		candidates = append(candidates, name)
	}
	sort.Strings(candidates)

	for _, username := range candidates {
		lower := strings.ToLower(username)
		if prefixLower != "" {
			if strings.HasPrefix(lower, prefixLower) {
				// keep
			} else if strings.Contains(lower, prefixLower) {
				// keep
			} else {
				continue
			}
		}
		cmd := base + " " + username
		if _, ok := seen[cmd]; ok {
			continue
		}
		seen[cmd] = struct{}{}
		desc := candidatesMap[username]
		if desc == "" {
			desc = "User"
		}
		out = append(out, cmdSuggestion{Display: cmd, Insert: cmd, Desc: desc})
		if len(out) >= 50 {
			break
		}
	}

	return out
}

func joinChannelSuggestions(m *model, base, prefix string) []cmdSuggestion {
	prefix = strings.TrimSpace(prefix)
	prefixLower := strings.ToLower(prefix)

	joined := make(map[string]struct{})
	if m != nil {
		for _, ch := range m.viewChatModel.channels {
			if ch.channelId == "" {
				continue
			}
			joined[ch.channelId] = struct{}{}
		}
	}

	seen := make(map[string]struct{})
	out := make([]cmdSuggestion, 0, 50)

	add := func(channelID, desc string) {
		if channelID == "" {
			return
		}
		lower := strings.ToLower(channelID)
		if prefixLower != "" {
			if !strings.HasPrefix(lower, prefixLower) && !strings.Contains(lower, prefixLower) {
				return
			}
		}
		if _, ok := joined[channelID]; ok {
			return
		}
		if m != nil && m.app != nil {
			if isUserBannedFromChannel(m.app, m.viewChatModel.id, channelID) {
				return
			}
		}
		cmd := base + " " + channelID
		if _, ok := seen[cmd]; ok {
			return
		}
		seen[cmd] = struct{}{}
		out = append(out, cmdSuggestion{Display: cmd, Insert: cmd, Desc: desc})
	}

	// Suggested channels you're invited to.
	if m != nil && m.app != nil {
		var invited []string
		_ = m.app.db.WithContext(context.Background()).
			Table("invites").
			Where("user_id = ?", m.viewChatModel.id).
			Pluck("channel_id", &invited).Error
		slices.Sort(invited)
		for _, id := range invited {
			add(id, "Invited")
			if len(out) >= 50 {
				return out
			}
		}
	}

	// Public channels (handy to discover).
	if m != nil && m.app != nil {
		public := make([]string, 0)
		m.app.mu.RLock()
		for id, ch := range m.app.channels {
			if ch == nil || !ch.Public {
				continue
			}
			public = append(public, id)
		}
		m.app.mu.RUnlock()
		slices.Sort(public)
		for _, id := range public {
			add(id, "Public")
			if len(out) >= 50 {
				return out
			}
		}
	}

	if len(out) > 50 {
		out = out[:50]
	}

	return out
}

func suggestCommands(m *model, input string) []cmdSuggestion {
	// Input is the raw textarea value, including leading '/'.
	raw := strings.TrimPrefix(input, "/")
	trailingSpace := strings.HasSuffix(raw, " ")
	tokens := strings.Fields(raw)
	if trailingSpace {
		tokens = append(tokens, "")
	}
	if len(tokens) == 0 {
		return suggestionsForChildren(m, rootCommands, nil, "")
	}

	node := rootCommands
	path := make([]string, 0)

	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		last := i == len(tokens)-1

		if !last {
			child, ok := node.match(tok)
			if !ok {
				// If this node expects args (e.g. banner text), keep suggesting using the full arg tail.
				if node.ArgHint != "" && len(node.Children) == 0 {
					base := "/" + strings.Join(path, " ")
					if node.Name == "tz" {
						prefix := ""
						if len(tokens) > i {
							prefix = tokens[i]
						}
						return timezoneSuggestions(m, base, prefix)
					}

					argTail := strings.Join(tokens[i:], " ")
					display := base
					if argTail != "" {
						display = base + " " + argTail
					}
					return []cmdSuggestion{{Display: display, Insert: display, Desc: node.Desc}}
				}
				return nil
			}
			node = child
			path = append(path, child.Name)
			continue
		}

		// Last token: we can suggest within this node.
		if tok == "" {
			// If this node expects args, suggest its arg hint (or a richer list).
			if node.ArgHint != "" && len(node.Children) == 0 {
				base := "/" + strings.Join(path, " ")
				if node.Name == "tz" {
					return timezoneSuggestions(m, base, "")
				}
				if node.Name == "join" {
					return joinChannelSuggestions(m, base, "")
				}
				if node.ArgHint == "<user>" {
					return userArgSuggestions(m, base, "")
				}
				display := base + " " + node.ArgHint
				insert := base + " "
				return []cmdSuggestion{{Display: display, Insert: insert, Desc: node.Desc}}
			}
			return suggestionsForChildren(m, node, path, "")
		}

		// If this token exactly matches a child and that child has children,
		// show the next level (Minecraft-style).
		if child, ok := node.match(tok); ok {
			if strings.EqualFold(tok, child.Name) {
				if len(child.Children) > 0 {
					return suggestionsForChildren(m, child, append(path, child.Name), "")
				}
				return nil

			}
			for _, a := range child.Aliases {
				if strings.EqualFold(tok, a) {
					if len(child.Children) > 0 {
						return suggestionsForChildren(m, child, append(path, child.Name), "")
					}
					return nil
				}
			}
		}

		// If we are in args for a leaf command, suggest based on the typed arg.
		if node.ArgHint != "" && len(node.Children) == 0 {
			base := "/" + strings.Join(path, " ")
			if node.Name == "tz" {
				return timezoneSuggestions(m, base, tok)
			}
			if node.Name == "join" {
				return joinChannelSuggestions(m, base, tok)
			}
			if node.ArgHint == "<user>" {
				return userArgSuggestions(m, base, tok)
			}
			display := base + " " + tok
			return []cmdSuggestion{{Display: display, Insert: display, Desc: node.Desc}}
		}

		return suggestionsForChildren(m, node, path, tok)
	}

	return nil
}

func suggestionsForChildren(m *model, node *cmdNode, path []string, prefix string) []cmdSuggestion {
	if node == nil || len(node.Children) == 0 {
		return nil
	}

	children := node.childMatchesPrefix(prefix)
	out := make([]cmdSuggestion, 0, len(children))
	seen := make(map[string]struct{}, len(children))
	for _, child := range children {
		if (child.Name == "kick" || child.Name == "ban" || child.Name == "unban") && !isCurrentChannelOwner(m) {
			continue
		}

		full := append([]string{}, path...)
		full = append(full, child.Name)
		cmd := "/" + strings.Join(full, " ")
		if _, ok := seen[cmd]; ok {
			continue
		}
		seen[cmd] = struct{}{}

		display := cmd
		if child.ArgHint != "" {
			display = cmd + " " + child.ArgHint
		}

		insert := cmd
		if child.ArgHint != "" || len(child.Children) > 0 {
			insert = cmd + " "
		}

		out = append(out, cmdSuggestion{Display: display, Insert: insert, Desc: child.Desc})
	}
	return out
}

func runChanCreate(m *model, args []string) {
	if len(args) != 1 {
		sendIslebotMessage(m, "Usage: /chan create [name]")
		return
	}
	newChannelName := args[0]

	// Check if the name exists
	channel, ok := m.app.channels[newChannelName]
	if ok {
		if channel.Public {
			sendIslebotMessage(m, fmt.Sprintf("Sorry but the channel #%s already exists, it was created by @%s. The channel is public so you can join with /chan join %s", newChannelName, channel.OwnerID, newChannelName))
		} else {
			sendIslebotMessage(m, fmt.Sprintf("Sorry but the channel #%s already exists, it was created by @%s. The channel is private so you can join once invited", newChannelName, channel.OwnerID))
		}
		return
	}

	match, _ := regexp.MatchString("^[a-zA-Z0-9_-]{1,10}$", newChannelName)
	if !match {
		sendIslebotMessage(m, "Invalid name. Please use 1–10 letters, numbers, underscores, or hyphens.")
		return
	}

	newChannel := Channel{
		ID:       newChannelName,
		OwnerID:  m.viewChatModel.id,
		Banner:   "Default channel banner :(",
		Public:   true,
		ReadOnly: false,
	}
	err := gorm.G[Channel](m.db).Create(context.Background(), &newChannel)
	if err != nil {
		sendIslebotMessage(m, "Sorry but there was an error whilst creating the channel")
		return
	}

	m.app.mu.Lock()
	m.app.messages[newChannelName] = make([]chatMsg, 0)
	m.app.channelMemberListCache[newChannelName] = &channelMemberList{
		onlineMembers:      make(map[string]*userSession),
		publicChannel:      true,
		offlineMembers:     make(map[string]string),
		offlineMemberCount: 0,
	}
	m.app.channels[newChannelName] = &newChannel
	m.app.mu.Unlock()

	// chan id might change so save it first then find it and change it
	oldCurChan := m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId
	addUserToChannel(m.app, m.viewChatModel.id, newChannelName)

	sendIslebotMessage(m, fmt.Sprintf("Your new channel, #%s, was created", newChannelName))

	for i, c := range m.viewChatModel.channels {
		if c.channelId == oldCurChan {
			m.viewChatModel.currentChannel = i
			m.viewChatModel.channelListCursor = m.viewChatModel.currentChannel
		}
	}

	m.viewChatModel.channels = append(m.viewChatModel.channels, userChannelState{
		channelId: newChannelName,
		unread:    0,
	})

	updateChannelMemberList(updateChannelMemberListParameters{
		app:       m.app,
		userId:    m.viewChatModel.id,
		change:    UserChannelJoin,
		channelId: newChannelName,
	})

	updateChannelList(m)
}

func runChanJoin(m *model, args []string) {
	if len(args) != 1 {
		sendIslebotMessage(m, "Usage: /chan join [name]")
		return
	}

	channelName := args[0]
	m.app.mu.RLock()
	channel, ok := m.app.channels[channelName]
	m.app.mu.RUnlock()
	if !ok {
		sendIslebotMessage(m, "Couldn't find a channel with that name. You can create it with /chan create <name>")
		return
	}

	if isUserBannedFromChannel(m.app, m.viewChatModel.id, channelName) {
		sendIslebotMessage(m, fmt.Sprintf("You are banned from #%s", channelName))
		return
	}

	userId := m.viewChatModel.id
	if channel.Public {
		m.app.mu.RLock()
		_, alreadyMember := m.app.channelMemberListCache[channelName].onlineMembers[userId]
		m.app.mu.RUnlock()
		if !alreadyMember {
			addUserToChannel(m.app, userId, channelName)
			updateChannelMemberList(updateChannelMemberListParameters{
				app:       m.app,
				userId:    userId,
				change:    UserChannelJoin,
				channelId: channelName,
			})
			m.viewChatModel.channels = append(m.viewChatModel.channels, userChannelState{
				channelId: channelName,
				unread:    0,
			})
			updateChannelList(m)
			return
		}
		sendIslebotMessage(m, fmt.Sprintf("You are already a member of #%s. You can leave it with /chan leave %s", channelName, channelName))
		return
	}

	_, err := gorm.G[Invite](m.db).
		Where("user_id = ?", m.viewChatModel.id).
		Where("channel_id = ?", channelName).
		First(context.Background())
	if err != nil {
		sendIslebotMessage(m, fmt.Sprintf("The channel #%s is private and you can only join if you are invited. The owner can invite you with /chan invite %s", channelName, userId))
		return
	}

	_, err = gorm.G[Invite](m.db).
		Where("user_id = ?", m.viewChatModel.id).
		Where("channel_id = ?", channelName).
		Delete(context.Background())
	if err != nil {
		sendIslebotMessage(m, fmt.Sprintf("Sorry an error occured joining #%s", channelName))
		return
	}

	refreshNotifications(m.app, userId)

	addUserToChannel(m.app, userId, channelName)
	updateChannelMemberList(updateChannelMemberListParameters{
		app:       m.app,
		userId:    userId,
		change:    UserChannelJoin,
		channelId: channelName,
	})
	m.viewChatModel.channels = append(m.viewChatModel.channels, userChannelState{
		channelId: channelName,
		unread:    0,
	})
	updateChannelList(m)
	sendIslebotMessagePermanent(m.app, fmt.Sprintf("@%s joined the channel", m.viewChatModel.id), channelName)
}

func runChanInvite(m *model, args []string) {
	if len(args) != 1 {
		sendIslebotMessage(m, "Usage: /chan invite [user]")
		return
	}
	targetUser := args[0]

	m.app.mu.RLock()
	channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	m.app.mu.RUnlock()
	if channel.OwnerID != m.viewChatModel.id {
		sendIslebotMessage(m, "You are not the owner of this channel")
		return
	}
	if channel.Public {
		sendIslebotMessage(m, fmt.Sprintf("This channel is public. Anyone can join with /chan join %s", channel.ID))
		return
	}

	m.app.mu.RLock()
	_, onlineok := m.app.channelMemberListCache[channel.ID].onlineMembers[targetUser]
	_, offlineok := m.app.channelMemberListCache[channel.ID].offlineMembers[targetUser]
	m.app.mu.RUnlock()
	if onlineok || offlineok {
		sendIslebotMessage(m, fmt.Sprintf("The user @%s is already a member of #%s", targetUser, channel.ID))
		return
	}

	_, err := gorm.G[User](m.db).
		Where("ID = ?", targetUser).
		First(context.Background())
	if err != nil {
		sendIslebotMessage(m, fmt.Sprintf("No user could be found: @%s", targetUser))
		return
	}

	if isUserBannedFromChannel(m.app, targetUser, channel.ID) {
		sendIslebotMessage(m, fmt.Sprintf("The user @%s is banned from #%s", targetUser, channel.ID))
		return
	}

	err = gorm.G[Invite](m.db).Create(context.Background(), &Invite{UserID: targetUser, ChannelID: channel.ID})
	if err == nil {
		refreshNotifications(m.app, targetUser)
		sendIslebotMessage(m, fmt.Sprintf("The invite was sent to @%s, they can now join with /chan join %s", targetUser, channel.ID))
		return
	}

	sendIslebotMessage(m, fmt.Sprintf("The user @%s could not be invited to #%s. Either they are already invited or they do not exist", targetUser, channel.ID))
}

func runChanUninvite(m *model, args []string) {
	if len(args) != 1 {
		sendIslebotMessage(m, "Usage: /chan uninvite [user]")
		return
	}
	targetUser := args[0]

	m.app.mu.RLock()
	channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	m.app.mu.RUnlock()
	if channel.OwnerID != m.viewChatModel.id {
		sendIslebotMessage(m, "You are not the owner of this channel")
		return
	}

	_, err := gorm.G[Invite](m.db).
		Where("user_id = ?", targetUser).
		Where("channel_id = ?", channel.ID).
		First(context.Background())
	if err != nil {
		sendIslebotMessage(m, "That user does not have an invite to this channel")
		return
	}

	_, err = gorm.G[Invite](m.db).
		Where("user_id = ?", targetUser).
		Where("channel_id = ?", channel.ID).
		Delete(context.Background())
	if err != nil {
		sendIslebotMessage(m, "Sorry but an error occured whilst revoking the invite")
		return
	}

	refreshNotifications(m.app, targetUser)

	sendIslebotMessage(m, fmt.Sprintf("The user @%s was uninvited from #%s", targetUser, channel.ID))
}

func runChanPublic(m *model, args []string) {
	if len(args) != 0 {
		sendIslebotMessage(m, "Usage: /chan public")
		return
	}

	m.app.mu.RLock()
	channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	m.app.mu.RUnlock()
	if channel.OwnerID != m.viewChatModel.id {
		sendIslebotMessage(m, "You are not the owner of this channel")
		return
	}
	if channel.Public {
		sendIslebotMessage(m, fmt.Sprintf("This channel is already public. Anyone can join with /chan join %s", channel.ID))
		return
	}

	_, err := gorm.G[Channel](m.app.db).Where("id = ?", channel.ID).Update(context.Background(), "public", true)
	if err != nil {
		sendIslebotMessage(m, "Sorry but an error occured whilst processing your command")
		return
	}

	var invitedUsers []string
	err = m.db.WithContext(context.Background()).
		Table("invites").
		Where("channel_id = ?", channel.ID).
		Pluck("user_id", &invitedUsers).
		Error
	if err != nil {
		log.Error("Failed to fetch invitees for channel", "channel", channel.ID, "error", err)
	}

	_, err = gorm.G[Invite](m.db).
		Where("channel_id = ?", channel.ID).
		Delete(context.Background())
	if err != nil {
		sendIslebotMessage(m, fmt.Sprintf("Whilst making #%s public, invites could not be deleted", channel.ID))
	}

	for _, userID := range invitedUsers {
		refreshNotifications(m.app, userID)
	}

	sendIslebotMessage(m, fmt.Sprintf("#%s is now public", channel.ID))

	m.app.mu.Lock()
	m.app.channels[channel.ID].Public = true
	m.app.channelMemberListCache[channel.ID].offlineMemberCount = len(m.app.channelMemberListCache[channel.ID].offlineMembers)
	m.app.channelMemberListCache[channel.ID].offlineMembers = make(map[string]string)
	m.app.mu.Unlock()

	m.app.mu.RLock()
	for _, v := range m.app.channelMemberListCache[channel.ID].onlineMembers {
		if v.currentChannelId == channel.ID {
			go v.prog.Send(channelMemberListMsg(m.app.channelMemberListCache[channel.ID]))
		}
	}
	m.app.mu.RUnlock()
}

func runChanPrivate(m *model, args []string) {
	if len(args) != 0 {
		sendIslebotMessage(m, "Usage: /chan private")
		return
	}

	m.app.mu.RLock()
	channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	m.app.mu.RUnlock()
	if channel.OwnerID != m.viewChatModel.id {
		sendIslebotMessage(m, "You are not the owner of this channel")
		return
	}
	if !channel.Public {
		sendIslebotMessage(m, "This channel is already private. You can invite members with /chan invite [user]")
		return
	}

	var count int64
	err := m.db.
		WithContext(context.Background()).
		Table("user_channels").
		Where("channel_id = ?", channel.ID).
		Count(&count).
		Error
	if err != nil || count > 300 {
		sendIslebotMessage(m, "Sorry but you cannot make a channel with over 300 members private")
		return
	}

	var ids []string
	err = m.app.db.
		Table("user_channels").
		Where("channel_id = ?", channel.ID).
		Pluck("user_id", &ids).
		Error
	if err != nil {
		sendIslebotMessage(m, "Sorry but an error occured whilst turning the channel private")
		return
	}

	_, err2 := gorm.G[Channel](m.app.db).Where("id = ?", channel.ID).Update(context.Background(), "public", false)
	if err2 != nil {
		sendIslebotMessage(m, "Sorry but an error occured whilst turning the channel private")
		return
	}

	m.app.mu.Lock()
	m.app.channels[channel.ID].Public = false
	for _, v := range ids {
		m.app.channelMemberListCache[channel.ID].offlineMembers[v] = v
	}
	for k := range m.app.channelMemberListCache[channel.ID].onlineMembers {
		delete(m.app.channelMemberListCache[channel.ID].offlineMembers, k)
	}
	for _, v := range m.app.channelMemberListCache[channel.ID].onlineMembers {
		if v.currentChannelId == channel.ID {
			go v.prog.Send(channelMemberListMsg(m.app.channelMemberListCache[channel.ID]))
		}
	}
	m.app.mu.Unlock()

	sendIslebotMessage(m, fmt.Sprintf("#%s is now private", channel.ID))
}

func runChanBanner(m *model, _ []string) {
	m.app.mu.RLock()
	channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	m.app.mu.RUnlock()
	if channel.OwnerID != m.viewChatModel.id {
		sendIslebotMessage(m, "You are not the owner of this channel")
		return
	}

	value := m.viewChatModel.textarea.Value()
	prefix := "/chan banner"
	if !strings.HasPrefix(value, prefix) {
		sendIslebotMessage(m, "Use /chan banner <text>\nYou can design your banner at https://isle.chat/banner")
		return
	}
	banner := strings.TrimSpace(value[len(prefix):])
	if banner == "" {
		sendIslebotMessage(m, "Use /chan banner <text>\nYou can design your banner at https://isle.chat/banner")
		return
	}

	blen := BannerWidth(banner)
	if blen < 2 || blen > 200 {
		sendIslebotMessage(m, "Banner is too small/large! Design one at https://isle.chat/banner")
		return
	}

	_, err := gorm.G[Channel](m.app.db).Where("id = ?", channel.ID).Update(context.Background(), "banner", banner)
	if err != nil {
		sendIslebotMessage(m, "Sorry but an error occured whilst editing the banner")
		return
	}

	m.app.mu.Lock()
	m.app.channels[channel.ID].Banner = banner
	m.app.mu.Unlock()

	m.app.mu.RLock()
	for _, v := range m.app.channelMemberListCache[channel.ID].onlineMembers {
		if v.currentChannelId == channel.ID {
			go v.prog.Send(newBannerMsg(banner))
		}
	}
	m.app.mu.RUnlock()
}

func runChanLeave(m *model, args []string) {
	if len(args) != 0 {
		sendIslebotMessage(m, "Usage: /chan leave")
		return
	}

	m.app.mu.RLock()
	channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	m.app.mu.RUnlock()
	if channel.OwnerID == m.viewChatModel.id {
		sendIslebotMessage(m, "You are the owner of this channel. You cannot leave it but you can delete it with /chan delete")
		return
	}
	if channel.ID == "global" {
		sendIslebotMessage(m, "You cannot leave #global")
		return
	}

	removeUserFromChannel(m.app, m.viewChatModel.id, channel.ID)
	updateChannelMemberList(updateChannelMemberListParameters{
		app:       m.app,
		userId:    m.viewChatModel.id,
		change:    UserChannnelLeave,
		channelId: channel.ID,
	})

	id := m.viewChatModel.currentChannel
	m.viewChatModel.channels = append(m.viewChatModel.channels[:id], m.viewChatModel.channels[id+1:]...)
	m.viewChatModel.currentChannel = 0
	m.viewChatModel.channelListCursor = 0

	m.app.mu.Lock()
	m.app.sessions[m.viewChatModel.id].currentChannelId = "global"
	m.viewChatModel.memberList = m.app.channelMemberListCache[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	m.app.mu.Unlock()

	updateChannelList(m)
	updateUserList(m)
	reloadMessagesChannelSwitch(m)
	if !channel.Public {
		sendIslebotMessagePermanent(m.app, fmt.Sprintf("@%s left the channel", m.viewChatModel.id), channel.ID)
	}
}

func runChanDelete(m *model, args []string) {
	if len(args) != 0 {
		sendIslebotMessage(m, "Usage: /chan delete")
		return
	}

	m.app.mu.RLock()
	channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	m.app.mu.RUnlock()
	if channel.OwnerID != m.viewChatModel.id {
		sendIslebotMessage(m, "You are not the owner of this channel")
		return
	}

	m.app.mu.RLock()
	onlineMembers := m.app.channelMemberListCache[channel.ID].onlineMembers
	offlineMembers := m.app.channelMemberListCache[channel.ID].offlineMembers
	m.app.mu.RUnlock()

	for id, sess := range onlineMembers {
		removeUserFromChannel(m.app, id, channel.ID)
		updateChannelMemberList(updateChannelMemberListParameters{
			app:       m.app,
			userId:    m.viewChatModel.id,
			change:    UserChannnelLeave,
			channelId: channel.ID,
		})
		go sess.prog.Send(removedFromChannelMsg(channel.ID))
	}
	for id := range offlineMembers {
		removeUserFromChannel(m.app, id, channel.ID)
		updateChannelMemberList(updateChannelMemberListParameters{
			app:       m.app,
			userId:    m.viewChatModel.id,
			change:    UserChannnelLeave,
			channelId: channel.ID,
		})
	}

	var invitedUsers []string
	err := m.db.WithContext(context.Background()).
		Table("invites").
		Where("channel_id = ?", channel.ID).
		Pluck("user_id", &invitedUsers).
		Error
	if err != nil {
		log.Error("Failed to load invites for channel delete", "channel", channel.ID, "error", err)
	}

	_, delErr := gorm.G[Invite](m.db).
		Where("channel_id = ?", channel.ID).
		Delete(context.Background())
	if delErr != nil {
		log.Error("Failed to delete invites for channel", "channel", channel.ID, "error", delErr)
	}

	for _, userID := range invitedUsers {
		refreshNotifications(m.app, userID)
	}

	_, banDelErr := gorm.G[Ban](m.db).
		Where("channel_id = ?", channel.ID).
		Delete(context.Background())
	if banDelErr != nil {
		log.Error("Failed to delete bans for channel", "channel", channel.ID, "error", banDelErr)
	}

	m.app.mu.Lock()
	delete(m.app.channels, channel.ID)
	delete(m.app.bans, channel.ID)
	m.app.mu.Unlock()

	_, err = gorm.G[Channel](m.db).
		Where("id = ?", channel.ID).
		Delete(context.Background())
	if err != nil {
		fmt.Errorf("Error whilst deleting channel %s", err)
	}
}

func formatDurationShort(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	if d < time.Minute {
		return "just now"
	}

	units := []struct {
		dur  time.Duration
		name string
	}{
		{24 * time.Hour, "d"},
		{time.Hour, "h"},
		{time.Minute, "m"},
	}

	parts := make([]string, 0, 2)
	for _, u := range units {
		if d >= u.dur {
			val := d / u.dur
			parts = append(parts, fmt.Sprintf("%d%s", val, u.name))
			d -= val * u.dur
		}
		if len(parts) >= 2 {
			break
		}
	}

	if len(parts) == 0 {
		return "less than a minute"
	}

	return strings.Join(parts, " ")
}

func mutualChannels(m *model, targetUser string) ([]string, error) {
	if m == nil || m.app == nil {
		return nil, fmt.Errorf("missing app state")
	}

	current := make(map[string]struct{}, len(m.viewChatModel.channels))
	for _, ch := range m.viewChatModel.channels {
		current[ch.channelId] = struct{}{}
	}

	var targetChannelIDs []string
	err := m.app.db.WithContext(context.Background()).
		Table("user_channels").
		Where("user_id = ?", targetUser).
		Pluck("channel_id", &targetChannelIDs).Error
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	mutual := make([]string, 0)
	for _, ch := range targetChannelIDs {
		if _, ok := current[ch]; !ok {
			continue
		}
		if _, dup := seen[ch]; dup {
			continue
		}
		seen[ch] = struct{}{}
		mutual = append(mutual, ch)
	}

	slices.Sort(mutual)
	return mutual, nil
}

func removeMemberAndNotify(m *model, channelID, targetUser, notification string) bool {
	if m == nil || m.app == nil {
		return false
	}

	if ok := removeUserFromChannel(m.app, targetUser, channelID); !ok {
		return false
	}

	updateChannelMemberList(updateChannelMemberListParameters{
		app:       m.app,
		userId:    targetUser,
		change:    UserChannnelLeave,
		channelId: channelID,
	})

	if notification != "" {
		createPersistentNotification(m.app, targetUser, notification)
	}

	var sessionCopy *userSession
	m.app.mu.Lock()
	if sess, ok := m.app.sessions[targetUser]; ok && sess != nil {
		if sess.currentChannelId == channelID {
			sess.currentChannelId = "global"
		}
		sessionCopy = sess
	}
	m.app.mu.Unlock()

	if sessionCopy != nil && sessionCopy.loggedIn {
		sessionCopy.prog.Send(removedFromChannelMsg(channelID))
	}

	return true
}

func runWhois(m *model, args []string) {
	if len(args) != 1 {
		sendIslebotMessage(m, "Usage: /whois <user>")
		return
	}

	targetUser := normalizeUserPrefix(args[0])
	if targetUser == "" {
		sendIslebotMessage(m, "Usage: /whois <user>")
		return
	}

	user, err := gorm.G[User](m.db).
		Where("ID = ?", targetUser).
		First(context.Background())
	if err != nil {
		sendIslebotMessage(m, fmt.Sprintf("No user could be found: @%s", targetUser))
		return
	}

	m.app.mu.RLock()
	session, ok := m.app.sessions[targetUser]
	m.app.mu.RUnlock()
	online := ok && session != nil && session.loggedIn

	statusText := "Offline"
	lastOnline := user.LastSeenAt
	if lastOnline.IsZero() {
		lastOnline = user.LastLoginAt
	}
	lastOnlineText := "No activity recorded"

	if online {
		statusText = "Online"
		lastOnlineText = "just now"
	} else if !lastOnline.IsZero() {
		ago := formatDurationShort(time.Since(lastOnline))
		lastOnlineText = fmt.Sprintf("%s (%s ago)", lastOnline.In(m.viewChatModel.timezone).Format("2006-01-02 15:04 MST"), ago)
	}

	mutual, mutualErr := mutualChannels(m, targetUser)
	if mutualErr != nil {
		log.Error("Failed to load mutual channels", "user", targetUser, "error", mutualErr)
		sendIslebotMessage(m, "Couldn't load mutual channels right now")
		return
	}
	mutualText := "none"
	if len(mutual) > 0 {
		mutualText = "#" + strings.Join(mutual, ", #")
	}

	msg := fmt.Sprintf("User: @%s\nStatus: %s\nLast online: %s\nMutual channels: %s", targetUser, statusText, lastOnlineText, mutualText)
	sendIslebotMessage(m, msg)
}

func runChanKick(m *model, args []string) {
	if len(args) != 1 {
		sendIslebotMessage(m, "Usage: /chan kick <user>")
		return
	}
	targetUser := normalizeUserPrefix(args[0])
	if targetUser == "" {
		sendIslebotMessage(m, "Usage: /chan kick <user>")
		return
	}

	m.app.mu.RLock()
	channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	m.app.mu.RUnlock()
	if channel.OwnerID != m.viewChatModel.id {
		sendIslebotMessage(m, "You are not the owner of this channel")
		return
	}

	if targetUser == m.viewChatModel.id || targetUser == channel.OwnerID {
		sendIslebotMessage(m, "You cannot kick yourself or the channel owner")
		return
	}
	if targetUser == m.app.config.AdminUsername || targetUser == m.app.config.BotUsername {
		sendIslebotMessage(m, "You cannot kick that user")
		return
	}

	_, err := gorm.G[User](m.db).
		Where("ID = ?", targetUser).
		First(context.Background())
	if err != nil {
		sendIslebotMessage(m, fmt.Sprintf("No user could be found: @%s", targetUser))
		return
	}

	var membership int64
	memberErr := m.db.WithContext(context.Background()).
		Table("user_channels").
		Where("user_id = ?", targetUser).
		Where("channel_id = ?", channel.ID).
		Count(&membership).Error
	if memberErr != nil {
		sendIslebotMessage(m, "Sorry, could not check membership right now")
		return
	}
	if membership == 0 {
		sendIslebotMessage(m, fmt.Sprintf("@%s is not a member of #%s", targetUser, channel.ID))
		return
	}

	notification := fmt.Sprintf("You were kicked from #%s by @%s", channel.ID, m.viewChatModel.id)
	if !removeMemberAndNotify(m, channel.ID, targetUser, notification) {
		sendIslebotMessage(m, "Sorry an error occured whilst removing the user")
		return
	}

	sendIslebotMessage(m, fmt.Sprintf("@%s was kicked from #%s", targetUser, channel.ID))
}

func runChanBan(m *model, args []string) {
	if len(args) != 1 {
		sendIslebotMessage(m, "Usage: /chan ban <user>")
		return
	}
	targetUser := normalizeUserPrefix(args[0])
	if targetUser == "" {
		sendIslebotMessage(m, "Usage: /chan ban <user>")
		return
	}

	m.app.mu.RLock()
	channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	m.app.mu.RUnlock()
	if channel.OwnerID != m.viewChatModel.id {
		sendIslebotMessage(m, "You are not the owner of this channel")
		return
	}

	if targetUser == m.viewChatModel.id || targetUser == channel.OwnerID {
		sendIslebotMessage(m, "You cannot ban yourself or the channel owner")
		return
	}
	if targetUser == m.app.config.AdminUsername || targetUser == m.app.config.BotUsername {
		sendIslebotMessage(m, "You cannot ban that user")
		return
	}

	if isUserBannedFromChannel(m.app, targetUser, channel.ID) {
		sendIslebotMessage(m, fmt.Sprintf("@%s is already banned from #%s", targetUser, channel.ID))
		return
	}

	_, err := gorm.G[User](m.db).
		Where("ID = ?", targetUser).
		First(context.Background())
	if err != nil {
		sendIslebotMessage(m, fmt.Sprintf("No user could be found: @%s", targetUser))
		return
	}

	banErr := gorm.G[Ban](m.db).Create(context.Background(), &Ban{UserID: targetUser, ChannelID: channel.ID})
	if banErr != nil {
		sendIslebotMessage(m, "Sorry but an error occured whilst banning the user")
		return
	}
	addBanToCache(m.app, targetUser, channel.ID)

	_, _ = gorm.G[Invite](m.db).
		Where("user_id = ?", targetUser).
		Where("channel_id = ?", channel.ID).
		Delete(context.Background())

	notification := fmt.Sprintf("You were banned from #%s by @%s", channel.ID, m.viewChatModel.id)
	if !removeMemberAndNotify(m, channel.ID, targetUser, notification) {
		removeBanFromCache(m.app, targetUser, channel.ID)
		_, _ = gorm.G[Ban](m.db).
			Where("user_id = ?", targetUser).
			Where("channel_id = ?", channel.ID).
			Delete(context.Background())
		sendIslebotMessage(m, "Sorry an error occured whilst removing the user")
		return
	}

	sendIslebotMessage(m, fmt.Sprintf("@%s was banned from #%s", targetUser, channel.ID))
}

func runChanUnban(m *model, args []string) {
	if len(args) != 1 {
		sendIslebotMessage(m, "Usage: /chan unban <user>")
		return
	}
	targetUser := normalizeUserPrefix(args[0])
	if targetUser == "" {
		sendIslebotMessage(m, "Usage: /chan unban <user>")
		return
	}

	m.app.mu.RLock()
	channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
	m.app.mu.RUnlock()
	if channel.OwnerID != m.viewChatModel.id {
		sendIslebotMessage(m, "You are not the owner of this channel")
		return
	}

	if !isUserBannedFromChannel(m.app, targetUser, channel.ID) {
		sendIslebotMessage(m, fmt.Sprintf("@%s is not banned from #%s", targetUser, channel.ID))
		return
	}

	_, err := gorm.G[Ban](m.db).
		Where("user_id = ?", targetUser).
		Where("channel_id = ?", channel.ID).
		Delete(context.Background())
	if err != nil {
		sendIslebotMessage(m, "Sorry but an error occured whilst unbanning the user")
		return
	}
	removeBanFromCache(m.app, targetUser, channel.ID)

	createPersistentNotification(m.app, targetUser, fmt.Sprintf("You were unbanned from #%s by @%s", channel.ID, m.viewChatModel.id))

	sendIslebotMessage(m, fmt.Sprintf("@%s was unbanned from #%s", targetUser, channel.ID))
}

func runTimezone(m *model, args []string) {
	if len(args) > 1 {
		sendIslebotMessage(m, "Usage: /tz <timezone>")
		return
	}

	if len(args) == 0 {
		sendIslebotMessage(m, fmt.Sprintf("Your current timezone is set to %s, you can change it with /tz <timezone>", m.viewChatModel.timezone.String()))
		return
	}

	newtz := args[0]
	tz, err := time.LoadLocation(newtz)
	if err != nil {
		sendIslebotMessage(m, "Couldn't use that timezone. Use IANA timezones e.g. America/New_York you can find yours here: https://webbrowsertools.com/timezone/")
		return
	}

	_, err = gorm.G[User](m.app.db).Where("id = ?", m.viewChatModel.id).Update(context.Background(), "timezone", tz.String())
	if err != nil {
		sendIslebotMessage(m, "Sorry an error occured updating your timezone. Please try again and if the error returns contact the administrator")
		return
	}

	m.viewChatModel.timezone = tz
	updateChatLines(m)
	sendIslebotMessage(m, fmt.Sprintf("Your timezone was set to %s", tz.String()))
}
