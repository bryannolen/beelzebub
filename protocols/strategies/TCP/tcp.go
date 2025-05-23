package TCP

import (
	"bufio"
	"net"
	"strings"
	"time"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type TCPStrategy struct {
}

func handleConnection(conn net.Conn, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	defer conn.Close() // Ensure connection is closed when this function returns

	err := conn.SetDeadline(time.Now().Add(time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second))
	if err != nil {
		log.Errorf("[%s] Error setting deadline: %v", conn.RemoteAddr().String(), err)
		return
	}

	log.Debugf("[%s] Accepted new client from: %s", conn.LocalAddr().String(), conn.RemoteAddr().String())

	// Send Banner - assuming servConf.Banner from config includes a newline if desired.
	// TestTCPConnectionHandling configures banner with \n.
	_, errWrite := conn.Write([]byte(servConf.Banner))
	if errWrite != nil {
		log.Errorf("[%s] Error sending banner: %v", conn.RemoteAddr().String(), errWrite)
		return 
	}

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	sessionID := uuid.New().String()

	// Trace New Connection (Start Event)
	startEvent := tracer.Event{
		Msg:         "New TCP Connection",
		Protocol:    tracer.TCP.String(),
		Status:      tracer.Start.String(),
		RemoteAddr:  conn.RemoteAddr().String(),
		SourceIp:    host,
		SourcePort:  port,
		ID:          sessionID,
		Description: servConf.Description,
	}
	if tr != nil {
		tr.TraceEvent(startEvent)
	} else {
		log.Warnf("[%s] Tracer is nil, cannot trace Start Event", conn.RemoteAddr().String())
	}


	command := ""
	reader := bufio.NewReader(conn)
	commandInput, readErr := reader.ReadString('\n')

	if readErr != nil {
		log.Warnf("[%s] Error reading command: %v", conn.RemoteAddr().String(), readErr)
		// Continue to send End trace event even if read failed, command might be empty or partial.
	}
	command = strings.TrimSpace(commandInput)

	// Trace End Connection (End Event)
	endEvent := tracer.Event{
		Msg:         "End TCP Connection",
		Protocol:    tracer.TCP.String(),
		Command:     command,
		Status:      tracer.End.String(),
		RemoteAddr:  conn.RemoteAddr().String(),
		SourceIp:    host,
		SourcePort:  port,
		ID:          sessionID, // Use the same ID as the start event for correlation
		Description: servConf.Description,
	}
	if tr != nil {
		tr.TraceEvent(endEvent)
	} else {
		log.Warnf("[%s] Tracer is nil, cannot trace End Event for command [%s]", conn.RemoteAddr().String(), command)
	}


	log.Infof("[%s] Closing connection after command: [%s]", conn.RemoteAddr().String(), command)
}

func (tcpStrategy *TCPStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	listen, err := net.Listen("tcp", servConf.Address)
	if err != nil {
		log.Errorf("Error during init TCP Protocol for address %s: %s", servConf.Address, err.Error())
		return err
	}

	log.WithFields(log.Fields{
		"port":   servConf.Address,
		"banner": servConf.Banner, 
	}).Infof("Init TCP service: %s", servConf.Description) // Using Description

	go func() {
		for {
			conn, err := listen.Accept()
			if err != nil {
				log.Errorf("Error accepting TCP connection: %v", err)
				// If the listener was closed, exit the loop.
				if opError, ok := err.(*net.OpError); ok && opError.Err.Error() == "use of closed network connection" {
					log.Info("TCP listener closed, stopping accept loop.")
					return
				}
				continue 
			}
			go handleConnection(conn, servConf, tr)
		}
	}()

	return nil
}
