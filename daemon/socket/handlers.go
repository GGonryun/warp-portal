package socket

import (
	"encoding/json"
	"fmt"
	"net"

	"warp_portal_daemon/providers"
)

func (h *Handler) handleGetPwnam(encoder *json.Encoder, username string) {
	h.logger.Trace("getpwnam request for user: %s", username)

	if h.isUserDenied(username) {
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "user explicitly denied",
		})
		return
	}

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

func (h *Handler) handleGetPwuid(encoder *json.Encoder, uid int) {
	h.logger.Trace("getpwuid request for UID: %d", uid)

	if h.isUidDenied(uid) {
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "UID explicitly denied",
		})
		return
	}

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

	if h.isUserDenied(user.Name) {
		h.logger.Debug("User %s (UID: %d) is in deny list, rejecting", user.Name, uid)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "user explicitly denied",
		})
		return
	}

	h.logger.Info("Found user: %s (UID: %d)", user.Name, user.UID)
	encoder.Encode(UserResponse{
		Status: "success",
		User:   user,
	})
}

func (h *Handler) handleGetGrnam(encoder *json.Encoder, groupname string) {
	h.logger.Trace("getgrnam request for group: %s", groupname)

	if h.isGroupDenied(groupname) {
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "group explicitly denied",
		})
		return
	}

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

func (h *Handler) handleGetGrgid(encoder *json.Encoder, gid int) {
	h.logger.Trace("getgrgid request for GID: %d", gid)

	if h.isGidDenied(gid) {
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "GID explicitly denied",
		})
		return
	}

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

	if h.isGroupDenied(group.Name) {
		h.logger.Debug("Group %s (GID: %d) is in deny list, rejecting", group.Name, gid)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "group explicitly denied",
		})
		return
	}

	h.logger.Info("Found group: %s (GID: %d)", group.Name, group.GID)
	encoder.Encode(GroupResponse{
		Status: "success",
		Group:  group,
	})
}

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

func (h *Handler) handleGetKeys(encoder *json.Encoder, username, keyType, keyFingerprint string) {
	h.logger.Trace("getkeys request for user: %s, type: %s, fingerprint: %s", username, keyType, keyFingerprint)

	if h.isUserDenied(username) {
		encoder.Encode(KeyResponse{
			Status: "error",
			Error:  "user explicitly denied",
		})
		return
	}

	if h.provider == nil {
		h.logger.Error("Data provider not initialized")
		encoder.Encode(KeyResponse{
			Status: "error",
			Error:  "Service temporarily unavailable",
		})
		return
	}

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

func (h *Handler) handleCheckSudo(conn net.Conn, username string) {
	h.logger.Trace("checksudo request for user: %s", username)

	if h.isUserDenied(username) {
		h.logger.Debug("User %s is in deny list, denying sudo access", username)
		conn.Write([]byte("DENY\n"))
		return
	}

	if h.provider == nil {
		h.logger.Error("Data provider not initialized")
		conn.Write([]byte("DENY\n"))
		return
	}

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

func (h *Handler) handleInitGroups(encoder *json.Encoder, username string) {
	h.logger.Trace("initgroups request for user: %s", username)

	if h.isUserDenied(username) {
		encoder.Encode(InitGroupsResponse{
			Status: "error",
			Error:  "user explicitly denied",
		})
		return
	}

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

func (h *Handler) handleOpenSession(encoder *json.Encoder, username, rhost string, timestamp int64) {
	h.logger.Trace("Processing session open for user %s from %s at %d", username, rhost, timestamp)

	if h.isUserDenied(username) {
		encoder.Encode(SessionResponse{
			Status: "error",
			Error:  "user explicitly denied",
		})
		return
	}

	if rhost == "" {
		rhost = "unknown"
		h.logger.Warn("No remote host provided for session open")
	}

	// Attempt user provisioning if enabled
	h.provisionUserIfEnabled(username)

	h.logger.Info("Session management: opened for %s", username)
	encoder.Encode(SessionResponse{
		Status:  "success",
		Message: fmt.Sprintf("Session opened for user %s", username),
	})
}

// provisionUserIfEnabled handles user provisioning to passwd file if retention is enabled
func (h *Handler) provisionUserIfEnabled(username string) {
	h.configMu.RLock()
	retainUsers := h.config != nil && h.config.UserProvisioning.RetainUsers
	h.configMu.RUnlock()

	if !retainUsers {
		return
	}

	if h.provider == nil {
		h.logger.Error("Provider not available for user provisioning")
		return
	}

	user, err := h.provider.GetUser(username)
	if err != nil {
		h.logger.Error("Failed to get user %s for provisioning: %v", username, err)
		return
	}

	if err := providers.ProvisionUser(user); err != nil {
		h.logger.Error("Failed to provision user %s to passwd file: %v", username, err)
		return
	}

	h.logger.Info("Successfully provisioned user %s to passwd file", username)
}

// reclaimUserIfEnabled handles user removal from passwd file if reclaim is enabled
func (h *Handler) reclaimUserIfEnabled(username string) {
	h.configMu.RLock()
	reclaimUsers := h.config != nil && h.config.UserProvisioning.ReclaimUsers
	h.configMu.RUnlock()

	if !reclaimUsers {
		return
	}

	if err := providers.RemoveUser(username); err != nil {
		h.logger.Error("Failed to remove user %s from passwd file: %v", username, err)
		return
	}

	h.logger.Info("Successfully removed user %s from passwd file", username)
}

func (h *Handler) handleCloseSession(encoder *json.Encoder, username, rhost string, timestamp int64) {
	h.logger.Trace("Processing session close for user %s from %s at %d", username, rhost, timestamp)

	if h.isUserDenied(username) {
		encoder.Encode(SessionResponse{
			Status: "error",
			Error:  "user explicitly denied",
		})
		return
	}

	if rhost == "" {
		rhost = "unknown"
		h.logger.Warn("No remote host provided for session close")
	}

	// Attempt user reclaim if enabled
	h.reclaimUserIfEnabled(username)

	h.logger.Trace("Session management: closed for %s", username)
	encoder.Encode(SessionResponse{
		Status:  "success",
		Message: fmt.Sprintf("Session closed for user %s", username),
	})
}
