package accounts

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"keywarden/agent/internal/config"
)

const (
	stateFileName  = "accounts.json"
	maxUsernameLen = 32
	passwdFilePath = "/etc/passwd"
	sshDirName     = ".ssh"
	authKeysName   = "authorized_keys"
)

type AccessUser struct {
	UserID   int
	Username string
	Email    string
	Keys     []string
}

type ReportAccount struct {
	UserID     int    `json:"user_id"`
	SystemUser string `json:"system_username"`
	Present    bool   `json:"present"`
}

type Result struct {
	Applied  int
	Revoked  int
	Accounts []ReportAccount
}

type managedAccount struct {
	UserID     int    `json:"user_id"`
	SystemUser string `json:"system_username"`
}

type state struct {
	Users map[string]managedAccount `json:"users"`
}

type passwdEntry struct {
	UID  int
	GID  int
	Home string
}

func Sync(policy config.AccountPolicy, stateDir string, users []AccessUser) (Result, error) {
	result := Result{}
	statePath := filepath.Join(stateDir, stateFileName)
	current, err := loadState(statePath)
	if err != nil {
		return result, err
	}

	desired := make(map[int]managedAccount, len(users))
	userIndex := make(map[int]AccessUser, len(users))
	for _, user := range users {
		systemUser := renderUsername(policy.UsernameTemplate, user.Username, user.UserID)
		desired[user.UserID] = managedAccount{UserID: user.UserID, SystemUser: systemUser}
		userIndex[user.UserID] = user
	}

	var syncErr error
	for _, account := range current.Users {
		if _, ok := desired[account.UserID]; ok {
			continue
		}
		if err := revokeUser(account.SystemUser, policy); err != nil && syncErr == nil {
			syncErr = err
		}
		result.Revoked++
	}

	for userID, account := range desired {
		accessUser := userIndex[userID]
		present, err := ensureAccount(account.SystemUser, policy, accessUser.Keys)
		if err != nil && syncErr == nil {
			syncErr = err
		}
		if present {
			result.Applied++
		}
		result.Accounts = append(result.Accounts, ReportAccount{
			UserID:     userID,
			SystemUser: account.SystemUser,
			Present:    present,
		})
	}

	if err := saveState(statePath, desired); err != nil && syncErr == nil {
		syncErr = err
	}
	return result, syncErr
}

func loadState(path string) (state, error) {
	st := state{Users: map[string]managedAccount{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, nil
		}
		return st, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("parse state: %w", err)
	}
	if st.Users == nil {
		st.Users = map[string]managedAccount{}
	}
	return st, nil
}

func saveState(path string, desired map[int]managedAccount) error {
	st := state{Users: map[string]managedAccount{}}
	for id, account := range desired {
		st.Users[strconv.Itoa(id)] = account
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}

func renderUsername(template string, username string, userID int) string {
	raw := strings.ReplaceAll(template, "{{username}}", username)
	raw = strings.ReplaceAll(raw, "{{user_id}}", strconv.Itoa(userID))
	clean := sanitizeUsername(raw)
	if len(clean) > maxUsernameLen {
		clean = clean[:maxUsernameLen]
	}
	if clean == "" {
		clean = fmt.Sprintf("kw_%d", userID)
	}
	return clean
}

func sanitizeUsername(raw string) string {
	raw = strings.ToLower(raw)
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	out := strings.Trim(b.String(), "-_")
	if out == "" {
		return ""
	}
	if strings.HasPrefix(out, "-") {
		return "kw" + out
	}
	return out
}

func userExists(username string) (bool, error) {
	cmd := exec.Command("id", "-u", username)
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func ensureAccount(username string, policy config.AccountPolicy, keys []string) (bool, error) {
	exists, err := userExists(username)
	if err != nil {
		return false, err
	}
	if !exists {
		if err := createUser(username, policy); err != nil {
			return false, err
		}
	}
	if err := lockPassword(username); err != nil {
		return true, err
	}
	if err := writeAuthorizedKeys(username, keys); err != nil {
		return true, err
	}
	return true, nil
}

func createUser(username string, policy config.AccountPolicy) error {
	args := []string{"-U"}
	if policy.CreateHome {
		args = append(args, "-m")
	} else {
		args = append(args, "-M")
	}
	if policy.DefaultShell != "" {
		args = append(args, "-s", policy.DefaultShell)
	}
	args = append(args, username)
	cmd := exec.Command("useradd", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("useradd %s: %w", username, err)
	}
	return nil
}

func lockPassword(username string) error {
	cmd := exec.Command("usermod", "-L", username)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock password %s: %w", username, err)
	}
	return nil
}

func revokeUser(username string, policy config.AccountPolicy) error {
	exists, err := userExists(username)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	var revokeErr error
	if policy.LockOnRevoke {
		if err := lockPassword(username); err != nil {
			revokeErr = err
		}
	}
	if err := writeAuthorizedKeys(username, nil); err != nil && revokeErr == nil {
		revokeErr = err
	}
	return revokeErr
}

func writeAuthorizedKeys(username string, keys []string) error {
	entry, err := lookupUser(username)
	if err != nil {
		return err
	}
	if entry.Home == "" {
		return fmt.Errorf("missing home dir for %s", username)
	}
	sshDir := filepath.Join(entry.Home, sshDirName)
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", sshDir, err)
	}
	if err := os.Chmod(sshDir, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", sshDir, err)
	}
	if err := os.Chown(sshDir, entry.UID, entry.GID); err != nil {
		return fmt.Errorf("chown %s: %w", sshDir, err)
	}
	authKeysPath := filepath.Join(sshDir, authKeysName)
	payload := strings.TrimSpace(strings.Join(keys, "\n"))
	if payload != "" {
		payload += "\n"
	}
	if err := os.WriteFile(authKeysPath, []byte(payload), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", authKeysPath, err)
	}
	if err := os.Chown(authKeysPath, entry.UID, entry.GID); err != nil {
		return fmt.Errorf("chown %s: %w", authKeysPath, err)
	}
	return nil
}

func lookupUser(username string) (passwdEntry, error) {
	file, err := os.Open(passwdFilePath)
	if err != nil {
		return passwdEntry{}, fmt.Errorf("open passwd: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 7)
		if len(fields) < 7 {
			continue
		}
		if fields[0] != username {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			return passwdEntry{}, fmt.Errorf("parse uid for %s: %w", username, err)
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			return passwdEntry{}, fmt.Errorf("parse gid for %s: %w", username, err)
		}
		return passwdEntry{
			UID:  uid,
			GID:  gid,
			Home: fields[5],
		}, nil
	}
	if err := scanner.Err(); err != nil {
		return passwdEntry{}, fmt.Errorf("scan passwd: %w", err)
	}
	return passwdEntry{}, fmt.Errorf("user %s not found", username)
}
