package providers

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	PasswdFile = "/etc/passwd"
	GroupFile  = "/etc/group"
)

// ProvisionUser adds a user and their primary group to the system passwd and group files
func ProvisionUser(user *User) error {
	// First, ensure the user's primary group exists
	if err := ensureGroup(user.Name, user.GID); err != nil {
		return fmt.Errorf("failed to provision group for user %s: %w", user.Name, err)
	}

	// Then add the user to passwd file
	if err := addUserToPasswd(user); err != nil {
		return fmt.Errorf("failed to provision user %s: %w", user.Name, err)
	}

	return nil
}

// RemoveUser removes a user from the system passwd and group files
func RemoveUser(username string) error {
	// Remove user from passwd file
	if err := removeUserFromPasswd(username); err != nil {
		return fmt.Errorf("failed to remove user %s from passwd: %w", username, err)
	}

	// Remove user's primary group (if it only contains this user)
	if err := removeUserGroup(username); err != nil {
		return fmt.Errorf("failed to remove group for user %s: %w", username, err)
	}

	return nil
}

// UserExistsInPasswd checks if a user already exists in the passwd file
func UserExistsInPasswd(username string) (bool, error) {
	file, err := os.Open(PasswdFile)
	if err != nil {
		return false, fmt.Errorf("failed to open %s: %w", PasswdFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, username+":") {
			return true, nil
		}
	}

	return false, scanner.Err()
}

// GroupExistsInGroup checks if a group already exists in the group file
func GroupExistsInGroup(groupname string) (bool, error) {
	file, err := os.Open(GroupFile)
	if err != nil {
		return false, fmt.Errorf("failed to open %s: %w", GroupFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, groupname+":") {
			return true, nil
		}
	}

	return false, scanner.Err()
}

// ensureGroup creates a group if it doesn't exist
func ensureGroup(groupname string, gid int) error {
	exists, err := GroupExistsInGroup(groupname)
	if err != nil {
		return err
	}

	if exists {
		return nil // Group already exists
	}

	return addGroupToGroupFile(groupname, gid)
}

// addUserToPasswd adds a user entry to the passwd file
func addUserToPasswd(user *User) error {
	exists, err := UserExistsInPasswd(user.Name)
	if err != nil {
		return err
	}

	if exists {
		return nil // User already exists
	}

	// Create passwd entry: username:x:uid:gid:gecos:homedir:shell
	entry := fmt.Sprintf("%s:x:%d:%d:%s:%s:%s\n",
		user.Name,
		user.UID,
		user.GID,
		user.Gecos,
		user.Dir,
		user.Shell,
	)

	return appendToFile(PasswdFile, entry)
}

// addGroupToGroupFile adds a group entry to the group file
func addGroupToGroupFile(groupname string, gid int) error {
	// Create group entry: groupname:x:gid:
	entry := fmt.Sprintf("%s:x:%d:\n", groupname, gid)
	return appendToFile(GroupFile, entry)
}

// removeUserFromPasswd removes a user entry from the passwd file
func removeUserFromPasswd(username string) error {
	return removeLineFromFile(PasswdFile, username+":")
}

// removeUserGroup removes a user's primary group from the group file
func removeUserGroup(username string) error {
	return removeLineFromFile(GroupFile, username+":")
}

// appendToFile safely appends content to a file with proper permissions
func appendToFile(filename, content string) error {
	// Create a backup first
	if err := createBackup(filename); err != nil {
		return fmt.Errorf("failed to create backup of %s: %w", filename, err)
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", filename, err)
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("failed to write to %s: %w", filename, err)
	}

	return nil
}

// removeLineFromFile removes lines starting with prefix from a file
func removeLineFromFile(filename, prefix string) error {
	// Create a backup first
	if err := createBackup(filename); err != nil {
		return fmt.Errorf("failed to create backup of %s: %w", filename, err)
	}

	input, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", filename, err)
	}

	lines := strings.Split(string(input), "\n")
	var filteredLines []string

	for _, line := range lines {
		if !strings.HasPrefix(line, prefix) {
			filteredLines = append(filteredLines, line)
		}
	}

	output := strings.Join(filteredLines, "\n")
	
	if err := os.WriteFile(filename, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", filename, err)
	}

	return nil
}

// createBackup creates a timestamped backup of a file
func createBackup(filename string) error {
	timestamp := fmt.Sprintf("%d", os.Getpid()) // Use PID for uniqueness
	backupName := fmt.Sprintf("%s.bak.%s", filename, timestamp)
	
	cmd := exec.Command("cp", filename, backupName)
	return cmd.Run()
}