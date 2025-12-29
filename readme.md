# isle.chat

A ssh powered chat server with public and private (invite-only) channels 

Each channel has an owner who can change its banner and invite users (anyone can join if its public)

Demo it with
`ssh username@isle.chat`

![Screenshot](screenshots/1.png)

This project is very new right now so don't rely on it for anything critical

For now the code is all in one file, `main.go`, but I'm planning on cleaning it up and splitting it up, especially the command logic

Built using the charm bubbletea/wish stack

## Features
- Users can create their own channels and make them public or private. They can invite users and change the banner (20x10 character) of their channel which shows on the right.
- Who's online? A member list on the right shows online users and in private channels also shows offline users
- Discord/slack style interface with channels on the left, chat in the middle and users on the right
- Channels with new messages show on the channel list on the right with the number of unread messages


## Self-hosting

You can either build the binary yourself using `go build` or you can use docker. 

```bash
docker run -t -i -p 2222:2222 -e CLICOLOR_FORCE=1 -e COLORTERM=truecolor -e TERM=xterm-256color --tmpfs /tmp -v ./ssh_keys/id_ed25519:/home/islechat/app/.ssh/id_ed25519:ro -v ./config.toml:/home/islechat/config.toml ashfn0/islechat
```

Additonally a docker-compose file is in this repository. The format of the config.toml file is:
```bash
Host = "0.0.0.0"
Port = "2222"
ServerName = "isle.chat" # Name of the server
AdminUsername = "admin" # Admin's username (Can post in the announcement channel)
BotUsername = "islebot" # Username of the bot for system messages
GlobalBanner = "banner" # Banner used for the #global channel
AnnouncementChannel = "news" # Name of read-only announcement channel
DefaultBanner = "banner" # Default banner for new channels
WelcomeMessage = "A new user joined for the first time! Welcome @%s. Run /help for information" # Message sent when a user joins. %s is the username of the user
FilterPublicMessages = false # Whether or not public messages should be filtered for profanity
RegistrationHeader = "isle.chat registration   " # Text shown at top of registration page
DatabaseMode = "sqlite" # Either sqlite or postgres
PostgresHost = "postgres"
PostgresUser = "islechat"
PostgresPassword = "password"
PostgresDBName = "islechat"
PostgresPort = "5432"
PostgresSSL = "disable"
```


### Why use this?


### Features I'm working on adding:
- Timezone support (Potential auto timezone detection using an ip geolocation db?)
- Support for adding your pubkey for authentication alongside user/pass
- Better channel ownership and moderation tools, for example having moderators and a simple permissions system

### Features I'd like to add in the future:
- Friend requests/direct messages
- Connection to external authentication providers, for example LDAP
- Custom bot/command support 
