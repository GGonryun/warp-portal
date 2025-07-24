package socket

import (
	"encoding/json"
	"fmt"
	"net"
)

// handleGetPwnam handles user lookup by username
func (h *Handler) handleGetPwnam(encoder *json.Encoder, username string) {
	if h.provider == nil {
		h.logger.Error("Data provider not initialized")
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	user, err := h.provider.GetUser(username)
	if err != nil {
		h.logger.Debug("User not found: %s - %v", username, err)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "User not found",
		})
		return
	}

	h.logger.Info("Found user: %s (UID: %d)", user.Name, user.UID)
	encoder.Encode(UserResponse{
		Status: "success",
		User:   user,
	})
}

// handleGetPwuid handles user lookup by UID
func (h *Handler) handleGetPwuid(encoder *json.Encoder, uid int) {
	if h.provider == nil {
		h.logger.Error("Data provider not initialized")
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	user, err := h.provider.GetUserByUID(uid)
	if err != nil {
		h.logger.Debug("User not found for UID: %d - %v", uid, err)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "User not found",
		})
		return
	}

	h.logger.Info("Found user: %s (UID: %d)", user.Name, user.UID)
	encoder.Encode(UserResponse{
		Status: "success",
		User:   user,
	})
}

// handleGetGrnam handles group lookup by name
func (h *Handler) handleGetGrnam(encoder *json.Encoder, groupname string) {
	if h.provider == nil {
		h.logger.Error("Data provider not initialized")
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	group, err := h.provider.GetGroup(groupname)
	if err != nil {
		h.logger.Debug("Group not found: %s - %v", groupname, err)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Group not found",
		})
		return
	}

	h.logger.Info("Found group: %s (GID: %d)", group.Name, group.GID)
	encoder.Encode(GroupResponse{
		Status: "success",
		Group:  group,
	})
}

// handleGetGrgid handles group lookup by GID
func (h *Handler) handleGetGrgid(encoder *json.Encoder, gid int) {
	if h.provider == nil {
		h.logger.Error("Data provider not initialized")
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	group, err := h.provider.GetGroupByGID(gid)
	if err != nil {
		h.logger.Debug("Group not found for GID: %d - %v", gid, err)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Group not found",
		})
		return
	}

	h.logger.Info("Found group: %s (GID: %d)", group.Name, group.GID)
	encoder.Encode(GroupResponse{
		Status: "success",
		Group:  group,
	})
}

// handleGetPwent handles user enumeration
func (h *Handler) handleGetPwent(encoder *json.Encoder, index int) {
	h.logger.Trace("getpwent request for index: %d", index)

	if h.provider == nil {
		h.logger.Error("Data provider not initialized")
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	// Reload provider configuration before listing
	if err := h.provider.Reload(); err != nil {
		h.logger.Error("Failed to list users: %v", err)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "Failed to refresh user list",
		})
		return
	}

	users, err := h.provider.ListUsers()
	if err != nil {
		h.logger.Warn("No users available or error listing users: %v", err)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "No users available",
		})
		return
	}

	if index >= len(users) {
		h.logger.Info("End of user list reached (index %d >= %d users)", index, len(users))
		encoder.Encode(UserResponse{
			Status: "end",
		})
		return
	}

	user := users[index]
	h.logger.Trace("Returning user at index %d: %s", index, user.Name)
	encoder.Encode(UserResponse{
		Status: "success",
		User:   user,
	})
}

// handleGetGrent handles group enumeration
func (h *Handler) handleGetGrent(encoder *json.Encoder, index int) {
	h.logger.Trace("getgrent request for index: %d", index)

	if h.provider == nil {
		h.logger.Error("Data provider not initialized")
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	// Reload provider configuration before listing
	if err := h.provider.Reload(); err != nil {
		h.logger.Error("Failed to list groups: %v", err)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Failed to refresh group list",
		})
		return
	}

	groups, err := h.provider.ListGroups()
	if err != nil {
		h.logger.Warn("No groups available or error listing groups: %v", err)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "No groups available",
		})
		return
	}

	if index >= len(groups) {
		h.logger.Info("End of group list reached (index %d >= %d groups)", index, len(groups))
		encoder.Encode(GroupResponse{
			Status: "end",
		})
		return
	}

	group := groups[index]
	h.logger.Trace("Returning group at index %d: %s", index, group.Name)
	encoder.Encode(GroupResponse{
		Status: "success",
		Group:  group,
	})
}

// handleGetKeys handles SSH key lookup
func (h *Handler) handleGetKeys(encoder *json.Encoder, username, keyType, keyFingerprint string) {
	if h.provider == nil {
		h.logger.Error("Data provider not initialized")
		encoder.Encode(KeyResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	// First reload to get fresh data
	if err := h.provider.Reload(); err != nil {
		h.logger.Error("Failed to reload provider configuration: %v", err)
		encoder.Encode(KeyResponse{
			Status: "error",
			Error:  "Failed to refresh configuration",
		})
		return
	}

	keys, err := h.provider.GetKeys(username)
	if err != nil {
		h.logger.Debug("No SSH keys found for user %s: %v", username, err)
		encoder.Encode(KeyResponse{
			Status: "error",
			Error:  "No SSH keys found",
		})
		return
	}

	h.logger.Info("Found %d SSH keys for user: %s", len(keys), username)
	h.logger.Debug("SSH keys for user %s: %v", username, keys)

	h.logger.Trace("SSH key request completed for user: %s", username)
	encoder.Encode(KeyResponse{
		Status: "success",
		Keys:   keys,
	})
}

// handleCheckSudo handles sudo access check
func (h *Handler) handleCheckSudo(conn net.Conn, username string) {
	if h.provider == nil {
		h.logger.Error("Data provider not initialized")
		conn.Write([]byte("DENY\n"))
		return
	}

	// Reload configuration to get fresh sudo permissions
	if err := h.provider.Reload(); err != nil {
		h.logger.Error("Failed to reload provider configuration: %v", err)
		conn.Write([]byte("DENY\n"))
		return
	}

	hasSudo, err := h.provider.CheckSudo(username)
	if err != nil {
		h.logger.Error("Error checking sudo access for user %s: %v", username, err)
		conn.Write([]byte("DENY\n"))
		return
	}

	if hasSudo {
		h.logger.Debug("Sudo access granted for user: %s", username)
		conn.Write([]byte("ALLOW\n"))
	} else {
		h.logger.Debug("Sudo access denied for user: %s", username)
		conn.Write([]byte("DENY\n"))
	}
}

// handleInitGroups handles supplementary group initialization
func (h *Handler) handleInitGroups(encoder *json.Encoder, username string) {
	if h.provider == nil {
		h.logger.Error("Data provider not initialized")
		encoder.Encode(InitGroupsResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

	groups, err := h.provider.InitGroups(username)
	if err != nil {
		h.logger.Error("Failed to get groups for user %s: %v", username, err)
		encoder.Encode(InitGroupsResponse{
			Status: "error",
			Error:  "Failed to get user groups",
		})
		return
	}

	h.logger.Debug("initgroups for user %s: %v", username, groups)
	encoder.Encode(InitGroupsResponse{
		Status: "success",
		Groups: groups,
	})
}

// handleOpenSession handles session opening
func (h *Handler) handleOpenSession(encoder *json.Encoder, username, rhost string, timestamp int64) {
	h.logger.Info("Session opened for user %s from %s at %d", username, rhost, timestamp)

	h.logger.Trace("Processing session open for user: %s", username)

	if rhost == "" {
		rhost = "unknown"
		h.logger.Warn("No remote host provided for session open")
	}

	h.logger.Info("Session management: opened for %s", username)
	encoder.Encode(SessionResponse{
		Status:  "success",
		Message: fmt.Sprintf("Session opened for user %s", username),
	})
}

// handleCloseSession handles session closing
func (h *Handler) handleCloseSession(encoder *json.Encoder, username, rhost string, timestamp int64) {
	h.logger.Info("Session closed for user %s from %s at %d", username, rhost, timestamp)

	h.logger.Trace("Processing session close for user: %s", username)

	if rhost == "" {
		rhost = "unknown"
		h.logger.Warn("No remote host provided for session close")
	}

	h.logger.Info("Session management: closed for %s", username)
	encoder.Encode(SessionResponse{
		Status:  "success",
		Message: fmt.Sprintf("Session closed for user %s", username),
	})
}