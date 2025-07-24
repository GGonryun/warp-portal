package socket

import (
	"encoding/json"
	"fmt"
	"net"

	"warp_portal_daemon/logging"
	"warp_portal_daemon/providers"
)

// Handler handles socket connections and requests
type Handler struct {
	provider providers.DataProvider
	logger   *logging.Logger
}

// NewHandler creates a new socket handler
func NewHandler(provider providers.DataProvider) *Handler {
	return &Handler{
		provider: provider,
		logger:   logging.NewLogger("socket"),
	}
}

// HandleConnection handles an incoming socket connection
func (h *Handler) HandleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req Request
	if err := decoder.Decode(&req); err != nil {
		h.logger.Error("Error decoding request: %v", err)
		return
	}

	h.logger.Trace("Received request: %+v", req)

	switch req.Op {
	case "getpwnam":
		h.handleGetPwnam(encoder, req.Username)
	case "getpwuid":
		h.handleGetPwuid(encoder, req.UID)
	case "getgrnam":
		h.handleGetGrnam(encoder, req.Groupname)
	case "getgrgid":
		h.handleGetGrgid(encoder, req.GID)
	case "getpwent":
		h.handleGetPwent(encoder, req.Index)
	case "getgrent":
		h.handleGetGrent(encoder, req.Index)
	case "getkeys":
		h.handleGetKeys(encoder, req.Username, req.KeyType, req.KeyFingerprint)
	case "checksudo":
		h.handleCheckSudo(conn, req.Username)
	case "initgroups":
		h.handleInitGroups(encoder, req.Username)
	case "open_session":
		h.handleOpenSession(encoder, req.Username, req.RHost, req.Timestamp)
	case "close_session":
		h.handleCloseSession(encoder, req.Username, req.RHost, req.Timestamp)
	default:
		h.logger.Warn("Unknown operation: %s", req.Op)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  fmt.Sprintf("Unknown operation: %s", req.Op),
		})
	}
}