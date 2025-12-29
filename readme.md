# isle.chat

A ssh powered chat server with public and private (invite-only) channels 
Each channel has an owner who can change its banner and invite users (anyone can join if its public)

Demo it with
`ssh username@isle.chat`

![Screenshot](screenshots/1.png)

For now the code is all in one file, `main.go` but I'm planning on cleaning it up and splitting it up, especially the command logic

Built using the charm bubbletea/wish stack

## Self-hosting



### Features I'm working on adding:
- Timezone support (Potential auto timezone detection using an ip geolocation db?)
- Support for adding your pubkey for authentication alongside user/pass
- Better channel ownership and moderation tools, for example having moderators and a simple permissions system

### Features I'd like to add in the future:
- Friend requests/direct messages
- Connection to external authentication providers, for example LDAP
- Custom bot/command support 
