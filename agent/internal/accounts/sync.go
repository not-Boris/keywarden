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
	stateFileName     = "accounts.json"
	maxUsernameLen    = 32
	passwdFilePath    = "/etc/passwd"
	groupFilePath     = "/etc/group"
	sshDirName        = ".ssh"
	authKeysName      = "authorized_keys"
	keywardenGroup    = "keywarden"
	userCAPath        = "/etc/ssh/keywarden_user_ca.pub"
	sshdConfigDropDir = "/etc/ssh/sshd_config.d"
	sshdConfigDropIn  = "/etc/ssh/sshd_config.d/keywarden.conf"
	sshdConfigPath    = "/etc/ssh/sshd_config"
)

type AccessUser struct {
	UserID         int
	Username       string
	Email          string
	SystemUsername string
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
	for _, user := range users {
		systemUser := user.SystemUsername
		if strings.TrimSpace(systemUser) == "" {
			systemUser = renderUsername(policy.UsernameTemplate, user.Username, user.UserID)
		}
		desired[user.UserID] = managedAccount{UserID: user.UserID, SystemUser: systemUser}
	}

	var syncErr error
	if err := ensureGroup(keywardenGroup); err != nil && syncErr == nil {
		syncErr = err
	}
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
		present, err := ensureAccount(account.SystemUser, policy)
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

func ensureAccount(username string, policy config.AccountPolicy) (bool, error) {
	exists, err := userExists(username)
	if err != nil {
		return false, err
	}
	if !exists {
		if err := createUser(username, policy); err != nil {
			return false, err
		}
	}
	if err := ensureGroupMembership(username, keywardenGroup); err != nil {
		return true, err
	}
	if err := enforceCertificateOnly(username, policy); err != nil {
		return true, err
	}
	if err := writeAuthorizedKeys(username, nil); err != nil {
		return true, err
	}
	return true, nil
}

func createUser(username string, policy config.AccountPolicy) error {
	args := []string{"-U", "-G", keywardenGroup}
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

func enforceCertificateOnly(username string, policy config.AccountPolicy) error {
	cmd := exec.Command("usermod", "-L", username)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock account %s: %w", username, err)
	}
	if policy.DefaultShell != "" {
		shellCmd := exec.Command("usermod", "-s", policy.DefaultShell, username)
		if err := shellCmd.Run(); err != nil {
			return fmt.Errorf("set shell %s: %w", username, err)
		}
	}
	expiryCmd := exec.Command("chage", "-E", "-1", username)
	if err := expiryCmd.Run(); err != nil {
		return fmt.Errorf("clear expiry %s: %w", username, err)
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
		if err := disableAccount(username); err != nil {
			revokeErr = err
		}
	}
	if err := writeAuthorizedKeys(username, nil); err != nil && revokeErr == nil {
		revokeErr = err
	}
	return revokeErr
}

func disableAccount(username string) error {
	cmd := exec.Command("usermod", "-L", username)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lock account %s: %w", username, err)
	}
	expiryCmd := exec.Command("chage", "-E", "0", username)
	if err := expiryCmd.Run(); err != nil {
		return fmt.Errorf("expire account %s: %w", username, err)
	}
	return nil
}

func ensureGroup(name string) error {
	exists, err := groupExists(name)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	cmd := exec.Command("groupadd", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("groupadd %s: %w", name, err)
	}
	return nil
}

func groupExists(name string) (bool, error) {
	file, err := os.Open(groupFilePath)
	if err != nil {
		return false, fmt.Errorf("open group file: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 4)
		if len(fields) < 1 {
			continue
		}
		if fields[0] == name {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("scan group file: %w", err)
	}
	return false, nil
}

func ensureGroupMembership(username string, group string) error {
	cmd := exec.Command("usermod", "-a", "-G", group, username)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("usermod add %s to %s: %w", username, group, err)
	}
	return nil
}

func EnsureCA(publicKey string) error {
	key := strings.TrimSpace(publicKey)
	if key == "" {
		return errors.New("user CA public key required")
	}
	changed, err := writeCAKeyIfChanged(key)
	if err != nil {
		return err
	}
	configChanged, err := ensureSSHDConfig()
	if err != nil {
		return err
	}
	if changed || configChanged {
		if err := reloadSSHD(); err != nil {
			return err
		}
	}
	return nil
}

func writeCAKeyIfChanged(key string) (bool, error) {
	if data, err := os.ReadFile(userCAPath); err == nil {
		if strings.TrimSpace(string(data)) == key {
			return false, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("read user CA key: %w", err)
	}
	if err := os.WriteFile(userCAPath, []byte(key+"\n"), 0o644); err != nil {
		return false, fmt.Errorf("write user CA key: %w", err)
	}
	return true, nil
}

func ensureSSHDConfig() (bool, error) {
	content := fmt.Sprintf(
		"TrustedUserCAKeys %s\nMatch Group %s\n    AuthorizedKeysFile none\n    PasswordAuthentication no\n    ChallengeResponseAuthentication no\n",
		userCAPath,
		keywardenGroup,
	)
	if info, err := os.Stat(sshdConfigDropDir); err == nil && info.IsDir() {
		if existing, err := os.ReadFile(sshdConfigDropIn); err == nil {
			if string(existing) == content {
				return false, nil
			}
		}
		if err := os.WriteFile(sshdConfigDropIn, []byte(content), 0o644); err != nil {
			return false, fmt.Errorf("write sshd drop-in: %w", err)
		}
		return true, nil
	}
	data, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return false, fmt.Errorf("read sshd config: %w", err)
	}
	if strings.Contains(string(data), "TrustedUserCAKeys "+userCAPath) {
		return false, nil
	}
	updated := string(data)
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += "\n# Keywarden managed users\n" + content
	if err := os.WriteFile(sshdConfigPath, []byte(updated), 0o644); err != nil {
		return false, fmt.Errorf("write sshd config: %w", err)
	}
	return true, nil
}

func reloadSSHD() error {
	if path, _ := exec.LookPath("systemctl"); path != "" {
		if err := exec.Command("systemctl", "reload", "sshd").Run(); err == nil {
			return nil
		}
		if err := exec.Command("systemctl", "reload", "ssh").Run(); err == nil {
			return nil
		}
	}
	if path, _ := exec.LookPath("service"); path != "" {
		if err := exec.Command("service", "sshd", "reload").Run(); err == nil {
			return nil
		}
		if err := exec.Command("service", "ssh", "reload").Run(); err == nil {
			return nil
		}
	}
	return errors.New("unable to reload sshd")
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
