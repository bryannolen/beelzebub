package SSH

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
	"github.com/mariocandela/beelzebub/v3/tracer"

	"github.com/bryannolen/dnsbl/spamhaus"
	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

type SSHStrategy struct {
	Sessions *historystore.HistoryStore
}

// shouldRespond checks the supplied sourceAddress against the Spamhaus ZEN DROP DNSBL using the supplied DNS resolver.
// It will return false (do not respond) if the supplied source address is present in the Spamhaus Zen DROP DNSBL.
// It will return true (okay to respond):
// * if there is no configured resolver (default), or
// * if there was an error making the query (fail open), or
// * if the sourceAddress is not on the DROP list.
func shouldRespond(sourceAddress, resolverAddress string) (bool, error) {
	if resolverAddress == "" {
		// Unconfigured resolver, so assume success.
		return true, nil
	}
	if sourceAddress == "" {
		// Fail open - this case should never happen but just in case.
		return true, fmt.Errorf("sourceAddress is empty")
	}
	res, err := spamhaus.QueryByIP(sourceAddress, resolverAddress)
	if err != nil {
		// Fail open.
		return true, err
	}
	if slices.Contains(res, "DROP") {
		return false, nil
	}
	return true, nil
}

func (sshStrategy *SSHStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	if sshStrategy.Sessions == nil {
		sshStrategy.Sessions = historystore.NewHistoryStore()
	}
	go sshStrategy.Sessions.HistoryCleaner()
	go func() {
		server := &ssh.Server{
			Addr:        servConf.Address,
			MaxTimeout:  time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
			IdleTimeout: time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
			Version:     servConf.ServerVersion,
			Handler: func(sess ssh.Session) {
				uuidSession := uuid.New()

				host, port, _ := net.SplitHostPort(sess.RemoteAddr().String())
				sessionKey := "SSH" + host + sess.User()

				// Check the remote address (host) against the DNS Block List (if configured).
				if servConf.ResolverAddress != "" {
					if canProceed, err := shouldRespond(host, servConf.ResolverAddress); err != nil {
						// Log the error and continue processing the connection.
						log.Errorf("error checking against DNSBL: %v", err)
					} else if !canProceed {
						// Drop the connection (early return).
						log.Infof("ignoring connection from %q due to DNSBL match", host)
						return
					}
				}

				// Inline SSH command
				if sess.RawCommand() != "" {
					var histories []plugins.Message
					if sshStrategy.Sessions.HasKey(sessionKey) {
						histories = sshStrategy.Sessions.Query(sessionKey)
					}
					for _, command := range servConf.Commands {
						if command.Regex.MatchString(sess.RawCommand()) {
							commandOutput := command.Handler
							if command.Plugin == plugins.LLMPluginName {
								llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)
								if err != nil {
									log.Errorf("error: %s", err.Error())
									commandOutput = "command not found"
									llmProvider = plugins.OpenAI
								}
								llmHoneypot := plugins.LLMHoneypot{
									Histories:    histories,
									OpenAIKey:    servConf.Plugin.OpenAISecretKey,
									Protocol:     tracer.SSH,
									Host:         servConf.Plugin.Host,
									Model:        servConf.Plugin.LLMModel,
									Provider:     llmProvider,
									CustomPrompt: servConf.Plugin.Prompt,
								}
								llmHoneypotInstance := plugins.InitLLMHoneypot(llmHoneypot)
								if commandOutput, err = llmHoneypotInstance.ExecuteModel(sess.RawCommand()); err != nil {
									log.Errorf("error ExecuteModel: %s, %s", sess.RawCommand(), err.Error())
									commandOutput = "command not found"
								}
							}
							var newEntries []plugins.Message
							newEntries = append(newEntries, plugins.Message{Role: plugins.USER.String(), Content: sess.RawCommand()})
							newEntries = append(newEntries, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})
							// Append the new entries to the store.
							sshStrategy.Sessions.Append(sessionKey, newEntries...)

							sess.Write(append([]byte(commandOutput), '\n'))

							tr.TraceEvent(tracer.Event{
								Msg:           "SSH Raw Command",
								Protocol:      tracer.SSH.String(),
								RemoteAddr:    sess.RemoteAddr().String(),
								SourceIp:      host,
								SourcePort:    port,
								Status:        tracer.Start.String(),
								ID:            uuidSession.String(),
								Environ:       strings.Join(sess.Environ(), ","),
								User:          sess.User(),
								Description:   servConf.Description,
								Command:       sess.RawCommand(),
								CommandOutput: commandOutput,
								Handler:       command.Name,
							})
							return
						}
					}
				}

				tr.TraceEvent(tracer.Event{
					Msg:         "New SSH Terminal Session",
					Protocol:    tracer.SSH.String(),
					RemoteAddr:  sess.RemoteAddr().String(),
					SourceIp:    host,
					SourcePort:  port,
					Status:      tracer.Start.String(),
					ID:          uuidSession.String(),
					Environ:     strings.Join(sess.Environ(), ","),
					User:        sess.User(),
					Description: servConf.Description,
				})

				terminal := term.NewTerminal(sess, buildPrompt(sess.User(), servConf.ServerName))
				var histories []plugins.Message
				if sshStrategy.Sessions.HasKey(sessionKey) {
					histories = sshStrategy.Sessions.Query(sessionKey)
				}

				for {
					commandInput, err := terminal.ReadLine()
					if err != nil {
						break
					}
					if commandInput == "exit" {
						break
					}
					for _, command := range servConf.Commands {
						if command.Regex.MatchString(commandInput) {
							commandOutput := command.Handler
							if command.Plugin == plugins.LLMPluginName {
								llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)
								if err != nil {
									log.Errorf("error: %s, fallback OpenAI", err.Error())
									llmProvider = plugins.OpenAI
								}
								llmHoneypot := plugins.LLMHoneypot{
									Histories:    histories,
									OpenAIKey:    servConf.Plugin.OpenAISecretKey,
									Protocol:     tracer.SSH,
									Host:         servConf.Plugin.Host,
									Model:        servConf.Plugin.LLMModel,
									Provider:     llmProvider,
									CustomPrompt: servConf.Plugin.Prompt,
								}
								llmHoneypotInstance := plugins.InitLLMHoneypot(llmHoneypot)
								if commandOutput, err = llmHoneypotInstance.ExecuteModel(commandInput); err != nil {
									log.Errorf("error ExecuteModel: %s, %s", commandInput, err.Error())
									commandOutput = "command not found"
								}
							}
							var newEntries []plugins.Message
							newEntries = append(newEntries, plugins.Message{Role: plugins.USER.String(), Content: commandInput})
							newEntries = append(newEntries, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})
							// Stash the new entries to the store, and update the history for this running session.
							sshStrategy.Sessions.Append(sessionKey, newEntries...)
							histories = append(histories, newEntries...)

							terminal.Write(append([]byte(commandOutput), '\n'))

							tr.TraceEvent(tracer.Event{
								Msg:           "SSH Terminal Session Interaction",
								RemoteAddr:    sess.RemoteAddr().String(),
								SourceIp:      host,
								SourcePort:    port,
								Status:        tracer.Interaction.String(),
								Command:       commandInput,
								CommandOutput: commandOutput,
								ID:            uuidSession.String(),
								Protocol:      tracer.SSH.String(),
								Description:   servConf.Description,
								Handler:       command.Name,
							})
							break // Inner range over commands.
						}
					}
				}

				tr.TraceEvent(tracer.Event{
					Msg:      "End SSH Session",
					Status:   tracer.End.String(),
					ID:       uuidSession.String(),
					Protocol: tracer.SSH.String(),
				})
			},
			PasswordHandler: func(ctx ssh.Context, password string) bool {
				host, port, _ := net.SplitHostPort(ctx.RemoteAddr().String())

				tr.TraceEvent(tracer.Event{
					Msg:         "New SSH Login Attempt",
					Protocol:    tracer.SSH.String(),
					Status:      tracer.Stateless.String(),
					User:        ctx.User(),
					Password:    password,
					Client:      ctx.ClientVersion(),
					RemoteAddr:  ctx.RemoteAddr().String(),
					SourceIp:    host,
					SourcePort:  port,
					ID:          uuid.New().String(),
					Description: servConf.Description,
				})
				matched, err := regexp.MatchString(servConf.PasswordRegex, password)
				if err != nil {
					log.Errorf("error regex: %s, %s", servConf.PasswordRegex, err.Error())
					return false
				}
				return matched
			},
		}
		err := server.ListenAndServe()
		if err != nil {
			log.Errorf("error during init SSH Protocol: %s", err.Error())
		}
	}()

	log.WithFields(log.Fields{
		"port":     servConf.Address,
		"commands": len(servConf.Commands),
	}).Infof("GetInstance service %s", servConf.Protocol)
	return nil
}

func buildPrompt(user string, serverName string) string {
	return fmt.Sprintf("%s@%s:~$ ", user, serverName)
}
