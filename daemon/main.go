package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const (
	SocketPath = "/run/nss-forward.sock"
	LogPath    = "/var/log/nss-daemon.log"
)

type Request struct {
	Op        string `json:"op"`
	Username  string `json:"username,omitempty"`
	Groupname string `json:"groupname,omitempty"`
	UID       int    `json:"uid,omitempty"`
	GID       int    `json:"gid,omitempty"`
	Index     int    `json:"index,omitempty"`
}

type UserResponse struct {
	Status string `json:"status"`
	User   *User  `json:"user,omitempty"`
	Error  string `json:"error,omitempty"`
}

type GroupResponse struct {
	Status string `json:"status"`
	Group  *Group `json:"group,omitempty"`
	Error  string `json:"error,omitempty"`
}

type User struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Gecos string `json:"gecos"`
	Dir   string `json:"dir"`
	Shell string `json:"shell"`
}

type Group struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}

var staticUsers = map[string]*User{
	"miguel": {
		Name:  "miguel",
		UID:   1874,
		GID:   1874,
		Gecos: "Miguel Campos",
		Dir:   "/home/miguel",
		Shell: "/bin/bash",
	},
}

var staticUsersByUID = map[int]*User{
	1874: staticUsers["miguel"],
}

var staticUsersSlice = []*User{
	staticUsers["miguel"],
}

var staticGroups = map[string]*Group{
	"miguel": {
		Name:    "miguel",
		GID:     1874,
		Members: []string{"miguel"},
	},
}

var staticGroupsByGID = map[int]*Group{
	1874: staticGroups["miguel"],
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req Request
	if err := decoder.Decode(&req); err != nil {
		log.Printf("Error decoding request: %v", err)
		return
	}

	log.Printf("Received request: %+v", req)

	switch req.Op {
	case "getpwnam":
		handleGetPwnam(encoder, req.Username)
	case "getpwuid":
		handleGetPwuid(encoder, req.UID)
	case "getgrnam":
		handleGetGrnam(encoder, req.Groupname)
	case "getgrgid":
		handleGetGrgid(encoder, req.GID)
	case "getpwent":
		handleGetPwent(encoder, req.Index)
	default:
		log.Printf("Unknown operation: %s", req.Op)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  fmt.Sprintf("Unknown operation: %s", req.Op),
		})
	}
}

func handleGetPwnam(encoder *json.Encoder, username string) {
	user, exists := staticUsers[username]
	if !exists {
		log.Printf("User not found: %s", username)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "User not found",
		})
		return
	}

	log.Printf("Found user: %s (UID: %d)", user.Name, user.UID)
	encoder.Encode(UserResponse{
		Status: "success",
		User:   user,
	})
}

func handleGetPwuid(encoder *json.Encoder, uid int) {
	user, exists := staticUsersByUID[uid]
	if !exists {
		log.Printf("User not found for UID: %d", uid)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "User not found",
		})
		return
	}

	log.Printf("Found user: %s (UID: %d)", user.Name, user.UID)
	encoder.Encode(UserResponse{
		Status: "success",
		User:   user,
	})
}

func handleGetGrnam(encoder *json.Encoder, groupname string) {
	group, exists := staticGroups[groupname]
	if !exists {
		log.Printf("Group not found: %s", groupname)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Group not found",
		})
		return
	}

	log.Printf("Found group: %s (GID: %d)", group.Name, group.GID)
	encoder.Encode(GroupResponse{
		Status: "success",
		Group:  group,
	})
}

func handleGetGrgid(encoder *json.Encoder, gid int) {
	group, exists := staticGroupsByGID[gid]
	if !exists {
		log.Printf("Group not found for GID: %d", gid)
		encoder.Encode(GroupResponse{
			Status: "error",
			Error:  "Group not found",
		})
		return
	}

	log.Printf("Found group: %s (GID: %d)", group.Name, group.GID)
	encoder.Encode(GroupResponse{
		Status: "success",
		Group:  group,
	})
}

func handleGetPwent(encoder *json.Encoder, index int) {
	log.Printf("getpwent requested for index: %d", index)

	if index < 0 || index >= len(staticUsersSlice) {
		log.Printf("Index out of range: %d (max: %d)", index, len(staticUsersSlice)-1)
		encoder.Encode(UserResponse{
			Status: "error",
			Error:  "End of enumeration",
		})
		return
	}

	user := staticUsersSlice[index]
	log.Printf("Found user at index %d: %s (UID: %d)", index, user.Name, user.UID)
	encoder.Encode(UserResponse{
		Status: "success",
		User:   user,
	})
}

func setupLogging() {
	logFile, err := os.OpenFile(LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Warning: Failed to open log file %s, using stdout: %v", LogPath, err)
		return
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Logging to file: %s", LogPath)
}

func main() {
	setupLogging()

	// Remove existing socket if it exists
	if err := os.Remove(SocketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("Failed to remove existing socket: %v", err)
	}

	// Create Unix domain socket
	listener, err := net.Listen("unix", SocketPath)
	if err != nil {
		log.Fatalf("Failed to create socket: %v", err)
	}
	defer listener.Close()

	// Set socket permissions
	if err := os.Chmod(SocketPath, 0666); err != nil {
		log.Fatalf("Failed to set socket permissions: %v", err)
	}

	log.Printf("NSS daemon listening on %s", SocketPath)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal, cleaning up...")
		listener.Close()
		os.Remove(SocketPath)
		os.Exit(0)
	}()

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}
