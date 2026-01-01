package main

import (
	"time"
	"strings"
	"context"
	"gorm.io/gorm"
	"fmt"
	"regexp"
)

func handleCmd(m *model, command []string){

	if(len(command)>0){
		switch strings.ToLower(command[0]){
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
/chan delete
For updates join #`+m.app.config.AnnouncementChannel

				if(len(command)>1){
					switch command[1]{
						case "create":
							if(len(command)==3){
								newChannelName := command[2]

								// Check if the name exists
								channel,ok := m.app.channels[newChannelName]

								if(ok){
									//
									if(channel.Public){
										sendIslebotMessage(m, fmt.Sprintf("Sorry but the channel #%s already exists, it was created by @%s. The channel is public so you can join with /chan join %s", newChannelName, channel.OwnerID, newChannelName))
									}else{
										sendIslebotMessage(m, fmt.Sprintf("Sorry but the channel #%s already exists, it was created by @%s. The channel is private so you can join once invited", newChannelName, channel.OwnerID))
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
											sendIslebotMessage(m, "Sorry but there was an error whilst creating the channel")
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

											sendIslebotMessage(m, fmt.Sprintf("Your new channel, #%s, was created", newChannelName))

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

											updateChannelList(m)
										}
									}else{
										sendIslebotMessage(m, "Invalid name. Please use 1–10 letters, numbers, underscores, or hyphens.")
									}
								}
							}else{
								sendIslebotMessage(m, "Usage: /chan create [name]")
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
											updateChannelList(m)
										}else{
											sendIslebotMessage(m, fmt.Sprintf("You are already a member of #%s. You can leave it with /chan leave %s", channelName, channelName))
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
												updateChannelList(m)
												sendIslebotMessagePermanent(m.app,  fmt.Sprintf("@%s joined the channel", m.viewChatModel.id), channelName)
											}else{
												sendIslebotMessage(m, fmt.Sprintf("Sorry an error occured joining #%s", channelName))
											}
										}else{
											sendIslebotMessage(m, fmt.Sprintf("The channel #%s is private and you can only join if you are invited. The owner can invite you with /chan invite %s", channelName, userId))
										}
									}

								}else{
									sendIslebotMessage(m, "Couldn't find a channel with that name. You can create it with /chan create <name>")
								}
							}else{
								sendIslebotMessage(m, "Usage: /chan join [name]")
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
													sendIslebotMessage(m, fmt.Sprintf("The invite was sent to @%s, they can now join with /chan join %s", targetUser, channel.ID))
												}else{
													sendIslebotMessage(m, fmt.Sprintf("The user @%s could not be invited to #%s. Either they are already invited or they do not exist", targetUser, channel.ID))
												}
											}else{
												sendIslebotMessage(m, fmt.Sprintf("No user could be found: @%s", targetUser))
											}
										}else{
											sendIslebotMessage(m, fmt.Sprintf("The user @%s is already a member of #%s", targetUser, channel.ID))
										}
									}else{
										sendIslebotMessage(m, fmt.Sprintf("This channel is public. Anyone can join with /chan join %s", channel.ID))
									}
								}else{
									sendIslebotMessage(m, "You are not the owner of this channel")
								}
							}else{
								sendIslebotMessage(m, "Usage: /chan invite [user]")
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
											sendIslebotMessage(m, fmt.Sprintf("The user @%s was uninvited from #%s", targetUser, channel.ID))
										}else{
											sendIslebotMessage(m, "Sorry but an error occured whilst revoking the invite")
										}
									}else{
										sendIslebotMessage(m, "That user does not have an invite to this channel")
									}
								}else{
									sendIslebotMessage(m, "You are not the owner of this channel")
								}
							}else{
								sendIslebotMessage(m, "Usage: /chan uninvite [user]")
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
												sendIslebotMessage(m, fmt.Sprintf("Whilst making #%s public, invites could not be deleted", channel.ID))
											}
											sendIslebotMessage(m, fmt.Sprintf("#%s is now public", channel.ID))
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
											sendIslebotMessage(m, fmt.Sprintf("Sorry but an error occured whilst processing your command"))
										}
									}else{
										sendIslebotMessage(m, fmt.Sprintf("This channel is already public. Anyone can join with /chan join %s", channel.ID))
									}
								}else{
									sendIslebotMessage(m, "You are not the owner of this channel")
								}
							}else{
								sendIslebotMessage(m, "Usage: /chan public")
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
													sendIslebotMessage(m, fmt.Sprintf("#%s is now private", channel.ID))
												}else{
													sendIslebotMessage(m, "Sorry but an error occured whilst turning the channel private")
												}
												
											}else{
												sendIslebotMessage(m, "Sorry but an error occured whilst turning the channel private")
											}

										}else{
											sendIslebotMessage(m, fmt.Sprintf("Sorry but you cannot make a channel with over 300 members private"))
										}
									}else{
										sendIslebotMessage(m, fmt.Sprintf("This channel is already private. You can invite members with /chan invite [user]"))
									}
								}else{
									sendIslebotMessage(m, "You are not the owner of this channel")
								}
							}else{
								sendIslebotMessage(m, "Usage: /chan private")
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
											sendIslebotMessage(m, "Sorry but an error occured whilst editing the banner")
										}
									}else{
										sendIslebotMessage(m, "Banner is too small/large! Design one at https://isle.chat/banner")
									}
								}else{
									sendIslebotMessage(m, "Use /banner <text> \nYou can design your banner at https://isle.chat/banner")
								}
								
							}else{
								sendIslebotMessage(m, "You are not the owner of this channel")
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
									updateChannelList(m)
									updateUserList(m)
									reloadMessagesChannelSwitch(m)
									if(!channel.Public){
										sendIslebotMessagePermanent(m.app, fmt.Sprintf("@%s left the channel", m.viewChatModel.id), channel.ID)
									}
								}else{
									sendIslebotMessage(m, "You cannot leave #global")
								}
							}else{
								sendIslebotMessage(m, "You are the owner of this channel. You cannot leave it but you can delete it with /chan delete")
							}
						case "delete":
							m.app.mu.RLock()
							channel := m.app.channels[m.viewChatModel.channels[m.viewChatModel.currentChannel].channelId]
							m.app.mu.RUnlock()
							if(channel.OwnerID==m.viewChatModel.id){

								// This can be heavily optimised at some point
								m.app.mu.RLock()
								onlineMembers := m.app.channelMemberListCache[channel.ID].onlineMembers
								offlineMembers := m.app.channelMemberListCache[channel.ID].offlineMembers
								m.app.mu.RUnlock()
								for id, sess := range onlineMembers {
									removeUserFromChannel(m.app, id, channel.ID)
									updateChannelMemberList(updateChannelMemberListParameters{
										app: m.app,
										userId: m.viewChatModel.id,
										change: UserChannnelLeave,
										channelId: channel.ID,
									})
									go sess.prog.Send(removedFromChannelMsg(channel.ID))
								}
								for id, _ := range offlineMembers {
									removeUserFromChannel(m.app, id, channel.ID)
									updateChannelMemberList(updateChannelMemberListParameters{
										app: m.app,
										userId: m.viewChatModel.id,
										change: UserChannnelLeave,
										channelId: channel.ID,
									})
								}
								
								m.app.mu.Lock()
								delete(m.app.channels, channel.ID)
								m.app.mu.Unlock()


								_, err := gorm.G[Channel](m.db).
									Where("id = ?", channel.ID).
									Delete(context.Background())
								
								if (err!=nil){
									fmt.Errorf("Error whilst deleting channel %s", err)
									// oh shit
								}
							}else{
								sendIslebotMessage(m, "You are the owner of this channel. You cannot delete it but you can leave with /chan leave")
							}
						default:
							sendIslebotMessage(m, chanHelpMsg)
					}
				}else{
					sendIslebotMessage(m, chanHelpMsg)
				}
			case "help":
				sendIslebotMessage(m, 
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
				updateChatLines(m)
		}
	}
}