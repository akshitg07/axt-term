package terminal

import "encoding/json"

// WebSocket framing.
//
// Binary frames carry data with a one-byte opcode; text frames carry JSON control
// messages. The split matters: a keystroke must not pay for JSON encoding and
// base64, and a screenful of output must not either. At 60 frames per second of
// terminal output the difference is the gap between a responsive terminal and a
// sluggish one.
const (
	// OpOutput is host output, server to client.
	OpOutput byte = 0x00
	// OpInput is keystrokes, client to server.
	OpInput byte = 0x01
	// OpReplay is buffered output sent once on attach, before live data.
	//
	// A separate opcode from OpOutput so the client can render it without
	// animation and without ringing the bell for output that already happened.
	OpReplay byte = 0x02
)

// Control message types, carried in text frames.
const (
	CtlResize = "resize"
	CtlStatus = "status"
	CtlError  = "error"
	CtlExit   = "exit"
	CtlPing   = "ping"
	CtlPong   = "pong"
	CtlAck    = "ack"
)

// Control is the JSON shape of every control frame in both directions.
type Control struct {
	Type string `json:"t"`

	// resize
	Cols int `json:"cols,omitempty"`
	Rows int `json:"rows,omitempty"`

	// status
	State string `json:"state,omitempty"`
	Seq   uint64 `json:"seq,omitempty"`
	// Reset tells the client to clear its display because replayed output has a
	// hole in it. Appending after a gap produces corruption that looks like a
	// terminal bug rather than missing data.
	Reset     bool   `json:"reset,omitempty"`
	Host      string `json:"host,omitempty"`
	Recording bool   `json:"recording,omitempty"`

	// error
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`

	// exit
	ExitCode *int   `json:"exit_code,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// encode renders a control frame.
func (c Control) encode() ([]byte, error) { return json.Marshal(c) }

// frame prefixes a payload with an opcode.
func frame(op byte, payload []byte) []byte {
	out := make([]byte, 0, len(payload)+1)
	out = append(out, op)
	out = append(out, payload...)
	return out
}
