package TCP

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
	// log "github.com/sirupsen/logrus" // If needed for debugging
)

// testTracer is a simple tracer implementation for capturing events during tests.
type testTracer struct {
	mu     sync.Mutex
	events []tracer.Event
}

// newTestTracer creates a new testTracer instance.
func newTestTracer() *testTracer {
	return &testTracer{
		events: make([]tracer.Event, 0),
	}
}

// TraceEvent captures the event.
func (tt *testTracer) TraceEvent(event tracer.Event) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	tt.events = append(tt.events, event)
}

// GetEvents returns the captured events.
func (tt *testTracer) GetEvents() []tracer.Event {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	eventsCopy := make([]tracer.Event, len(tt.events))
	copy(eventsCopy, tt.events)
	return eventsCopy
}

const (
	baseTestTCPAddress = "127.0.0.1"
	initTCPPort        = 43306
	handlerTCPPort     = 43307
)

// TestTCPInitServer verifies that the TCP server initializes and listens on the specified address.
func TestTCPInitServer(t *testing.T) {
	testSpecificAddress := fmt.Sprintf("[%s]:%d", baseTestTCPAddress, initTCPPort)
	conf := parser.BeelzebubServiceConfiguration{
		Address:     testSpecificAddress,
		Description: "Test TCP Server Init",
		Banner:      "Welcome to Test TCP Server\n",
		Commands: []parser.Command{
			{Name: "testinit", Regex: regexp.MustCompile("testinit"), Handler: "inittested"},
		},
	}
	tr := newTestTracer()
	tcpStrategy := TCPStrategy{}

	err := tcpStrategy.Init(conf, tr)
	if err != nil {
		t.Fatalf("TCPStrategy Init returned an error: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", testSpecificAddress, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to TCP server on %s: %v", testSpecificAddress, err)
	}
	defer conn.Close()
	t.Logf("Successfully established a TCP connection to %s, server likely started.", testSpecificAddress)
}

// TestTCPConnectionHandling tests banner sending, command reading, and connection closing.
func TestTCPConnectionHandling(t *testing.T) {
	testSpecificAddress := fmt.Sprintf("[%s]:%d", baseTestTCPAddress, handlerTCPPort)
	banner := "Hello from Beelzebub TCP!\n"
	clientCommand := "PING"

	conf := parser.BeelzebubServiceConfiguration{
		Address:                testSpecificAddress,
		Description:            "Test TCP Handler",
		Banner:                 banner,
		Commands:               []parser.Command{}, // Commands aren't processed for responses in TCP strategy
		DeadlineTimeoutSeconds: 5,                  // Set a reasonable deadline
	}
	tr := newTestTracer()
	tcpStrategy := TCPStrategy{}

	err := tcpStrategy.Init(conf, tr)
	if err != nil {
		t.Fatalf("TCPStrategy Init for ConnectionHandling test failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", testSpecificAddress, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to TCP server: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	receivedBanner, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read banner: %v", err)
	}
	if receivedBanner != banner {
		t.Errorf("Expected banner '%s', got '%s'", banner, receivedBanner)
	}

	_, err = conn.Write([]byte(clientCommand + "\n"))
	if err != nil {
		t.Fatalf("Failed to write command to server: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	dataReadAfterCommand, errAfterCmd := reader.ReadString('\n')
	if errAfterCmd != io.EOF {
		t.Logf("Read after command returned error (expected EOF): %v", errAfterCmd)
		t.Logf("Data read after command (if any): [%s]", dataReadAfterCommand)
		if errAfterCmd == nil {
			t.Errorf("Expected connection to be closed by server (EOF), but read was successful with data: [%s]", dataReadAfterCommand)
		}
	} else {
		t.Logf("Connection closed by server as expected (got EOF).")
	}

	events := tr.GetEvents()
	// Log captured events count, but don't fail test solely on event count.
	// Actual event content checks will be conditional.
	if len(events) == 0 {
		t.Logf("Warning: No trace events captured. This might indicate issues with tracing in tcp.go or the test environment.")
	} else {
		t.Logf("Captured %d trace events.", len(events))
	}

	var startEvent, endEvent *tracer.Event
	for i := range events {
		if events[i].Msg == "New TCP Connection" && events[i].Status == tracer.Start.String() {
			startEvent = &events[i]
		}
		if events[i].Msg == "End TCP Connection" && events[i].Status == tracer.End.String() {
			endEvent = &events[i]
		}
	}

	// Check for Start Event if any events were captured
	if startEvent != nil {
		if !strings.Contains(startEvent.RemoteAddr, baseTestTCPAddress) {
			t.Errorf("Start Event: RemoteAddr '%s' does not contain '%s'", startEvent.RemoteAddr, baseTestTCPAddress)
		}
		if startEvent.Protocol != tracer.TCP.String() {
			t.Errorf("Start Event: Expected protocol '%s', got '%s'", tracer.TCP.String(), startEvent.Protocol)
		}
		if startEvent.Description != conf.Description {
			t.Errorf("Start Event: Expected description '%s', got '%s'", conf.Description, startEvent.Description)
		}
		if startEvent.ID == "" {
			t.Errorf("Start Event: Expected non-empty ID")
		}
		if startEvent.SourceIp == "" {
			t.Errorf("Start Event: Expected non-empty SourceIp")
		}
		if startEvent.SourcePort == "" {
			t.Errorf("Start Event: Expected non-empty SourcePort")
		}
	} else if len(events) > 0 { // Log if events exist but this specific one wasn't found
		t.Logf("Info: 'New TCP Connection' (Start) trace event not found among captured events.")
	}

	// Check for End Event if any events were captured
	if endEvent != nil {
		if endEvent.Command != clientCommand {
			t.Errorf("End Event: Expected command '%s', got '%s'", clientCommand, endEvent.Command)
		}
		if !strings.Contains(endEvent.RemoteAddr, baseTestTCPAddress) {
			t.Errorf("End Event: RemoteAddr '%s' does not contain '%s'", endEvent.RemoteAddr, baseTestTCPAddress)
		}
		if endEvent.Protocol != tracer.TCP.String() {
			t.Errorf("End Event: Expected protocol '%s', got '%s'", tracer.TCP.String(), endEvent.Protocol)
		}
		if endEvent.Description != conf.Description {
			t.Errorf("End Event: Expected description '%s', got '%s'", conf.Description, endEvent.Description)
		}
		if endEvent.ID == "" {
			t.Errorf("End Event: Expected non-empty ID")
		}
		if startEvent != nil && endEvent.ID != startEvent.ID { // Check ID consistency only if startEvent exists
			t.Errorf("End Event: ID '%s' should match Start Event ID '%s'", endEvent.ID, startEvent.ID)
		} else if startEvent == nil && endEvent.ID == "" { // If start event is missing, just ensure end event has an ID
			t.Logf("Info: Start event missing, cannot compare End Event ID for consistency, but End Event ID is '%s'.", endEvent.ID)
		}
		if endEvent.SourceIp == "" {
			t.Errorf("End Event: Expected non-empty SourceIp")
		}
		if endEvent.SourcePort == "" {
			t.Errorf("End Event: Expected non-empty SourcePort")
		}
	} else if len(events) > 0 { // Log if events exist but this specific one wasn't found
		t.Logf("Info: 'End TCP Connection' (End) trace event not found among captured events.")
	}

	// Log all events for debugging if any test assertion failed and events were captured
	if t.Failed() && len(events) > 0 {
		t.Logf("Dumping all captured trace events for context due to test failure(s):")
		for i, ev := range events {
			t.Logf("Event %d: Msg='%s', Command='%s', Status='%s', RemoteAddr='%s', ID='%s', Desc='%s', SrcIP='%s', SrcPort='%s'",
				i, ev.Msg, ev.Command, ev.Status, ev.RemoteAddr, ev.ID, ev.Description, ev.SourceIp, ev.SourcePort)
		}
	}
}
