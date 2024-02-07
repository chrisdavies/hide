package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// hidePrefix is the prefix we place on the header line when editing
// an encrypted file. That is a temporary, edit-only line.
var hidePrefix = "#hide:"

type KeySalt struct {
	AES  []byte
	Salt []byte
}

type DecryptedContent struct {
	*KeySalt
	Filename string
	Content  string
}

type CLICommand struct {
	Command        string
	Filename       string
	MaskPassphrase bool
	NeovimFlags    []string
}

func main() {
	cmd, err := parseCLI(os.Args)

	if err != nil || cmd.Command == "help" {
		printHelp(err)
		os.Exit(1)
		return
	}

	switch cmd.Command {
	case "new":
		err = cmdNew(cmd)
	case "edit":
		err = cmdEdit(cmd)
	case "save":
		err = cmdSave(os.Stdin)
	default:
		printHelp(fmt.Errorf("unrecognized command %s", cmd.Command))
		os.Exit(1)
	}

	if err != nil {
		println(err)
		os.Exit(1)
	}
}

// qualify returns the fully-qualified location of the specified file
func qualify(filename string) string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Errorf("os.UserHomeDir %w", err))
	}
	return path.Join(homeDir, ".hide", filename)
}

// nvim launches nvim to edit the decrypted content
func nvim(content *DecryptedContent, flags []string) error {
	args := append([]string{"-nm"}, flags...)
	cmd := exec.Command("nvim", args...)
	stdin := new(bytes.Buffer)

	stdin.WriteString(fileHeader(content) + "\n")
	stdin.WriteString(content.Content)

	cmd.Stdin = stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("exec.Command nvim %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("cmd.Wait nvim %w", err)
	}

	// Clear the terminal
	fmt.Printf("\x1bc")
	fmt.Printf("\x1b[2J")

	return nil
}

// cmdNew opens a new file for editing in neovim
func cmdNew(cmd *CLICommand) error {
	if _, err := os.Stat(qualify(cmd.Filename)); !os.IsNotExist(err) {
		if err != nil {
			return err
		}
		return fmt.Errorf("file %s exists and can be edited with 'hide edit %s'", cmd.Filename, cmd.Filename)
	}
	pass, err := confirmPassphrase(cmd.MaskPassphrase)
	if err != nil {
		return fmt.Errorf("confirmPassphrase %w", err)
	}
	keys, err := genKeys(pass)
	if err != nil {
		return fmt.Errorf("genKeys %w", err)
	}
	content := &DecryptedContent{
		KeySalt:  keys,
		Filename: cmd.Filename,
		Content:  "\n\nEdit this content, but leave the first line alone!",
	}
	return nvim(content, cmd.NeovimFlags)
}

// cmdEdit decrypts the file and displays it in neovim
func cmdEdit(cmd *CLICommand) error {
	rawContent, err := os.ReadFile(qualify(cmd.Filename))
	if err != nil {
		return fmt.Errorf("os.ReadFile %w", err)
	}
	pass, err := readPassphrase("Passphrase:", cmd.MaskPassphrase)
	if err != nil {
		return fmt.Errorf("readPassphrase %w", err)
	}
	content, err := decrypt(pass, rawContent)
	if err != nil {
		return fmt.Errorf("decrypt %w", err)
	}
	content.Filename = cmd.Filename
	return nvim(content, cmd.NeovimFlags)
}

// cmdSave saves the specified file to disk, using the header to encrypt
func cmdSave(r io.Reader) error {
	println("Encrypting stdin...")
	if err := os.MkdirAll(qualify(""), 0o750); err != nil {
		return fmt.Errorf("os.MkdirAll %w", err)
	}
	rawContent, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("ReadAll stdin %w", err)
	}
	lineIndex := bytes.IndexRune(rawContent, '\n')
	if lineIndex < 0 {
		return fmt.Errorf("could not find first line of file")
	}
	header := string(rawContent[:lineIndex])
	if !strings.HasPrefix(header, hidePrefix) {
		return fmt.Errorf("could not find hide header")
	}
	headerPieces := strings.Split(header, " ")
	if len(headerPieces) != 3 {
		return fmt.Errorf("invalid hide header")
	}
	filename := headerPieces[0][len(hidePrefix):]
	salt, err := base64.URLEncoding.DecodeString(headerPieces[1])
	if err != nil {
		return fmt.Errorf("invalid salt %w", err)
	}
	key, err := base64.URLEncoding.DecodeString(headerPieces[2])
	if err != nil {
		return fmt.Errorf("invalid key %w", err)
	}
	keys := KeySalt{
		AES:  key,
		Salt: salt,
	}
	content, err := encrypt(&keys, string(rawContent)[lineIndex+1:])
	if err != nil {
		return fmt.Errorf("encrypt %w", err)
	}
	tmp, err := os.CreateTemp(qualify(""), "tmp*")
	if err != nil {
		return fmt.Errorf("os.CreateTemp %w", err)
	}
	defer tmp.Close()
	if n, err := tmp.Write(content); err != nil || n != len(content) {
		return fmt.Errorf("tmp.Write failed %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("tmp.Close %w", err)
	}
	if err := os.Rename(tmp.Name(), qualify(filename)); err != nil {
		return fmt.Errorf("os.Rename %w", err)
	}
	return nil
}

// fileHeader creates a file header comment from the specified struct
func fileHeader(content *DecryptedContent) string {
	return hidePrefix + content.Filename + " " + base64.URLEncoding.EncodeToString(content.Salt) + " " + base64.URLEncoding.EncodeToString(content.AES)
}

// println prints to os.Stderr so that we don't interrupt piping
func println(a ...any) {
	fmt.Fprintln(os.Stderr, a...)
}

// printHelp prints basic usage to the terminal
func printHelp(err error) {
	if err != nil {
		println(err)
	}
	println()
	println("Usage:")
	println()
	println("  hide new <filename>")
	println("  hide edit <filename>")
	println("  hide    -- Called from nevoim like :w !hide")
	println("  hide help")
	println()
	println("Any additional arguments are passed as flags to neovim.")
	println()
	println("Example:")
	println()
	println("  hide edit mysecretfile --noplugin")
	println()
}

// parseCLI parses {command} {filename} from the argument list
func parseCLI(args []string) (*CLICommand, error) {
	cmd := &CLICommand{}
	if len(args) > 1 {
		cmd.Command = args[1]
	}
	if len(args) > 2 && !strings.HasPrefix(args[2], "-") {
		cmd.Filename = args[2]
	}
	if cmd.Command == "" {
		cmd.Command = "save"
	}
	isNeovimCommand := cmd.Command == "new" || cmd.Command == "edit"
	if isNeovimCommand && cmd.Filename == "" {
		return nil, errors.New("filename parameter is required")
	}
	if isNeovimCommand && len(args) > 3 {
		cmd.NeovimFlags = []string{}
		for _, flag := range args[3:] {
			if flag == "--mask" {
				cmd.MaskPassphrase = true
			} else {
				cmd.NeovimFlags = append(cmd.NeovimFlags, flag)
			}
		}
	}
	return cmd, nil
}

// readPassphrase prompts the user for a passphrase and returns it
func readPassphrase(prompt string, mask bool) (string, error) {
	println(prompt)
	f, err := os.Open("/dev/tty")
	if err != nil {
		return "", fmt.Errorf("os.Open /dev/tty %w", err)
	}
	var result string
	if mask {
		passBytes, passErr := term.ReadPassword(int(f.Fd()))
		result = string(passBytes)
		err = passErr
	} else {
		reader := bufio.NewReader(f)
		result, err = reader.ReadString('\n')
	}
	if err != nil {
		return "", fmt.Errorf("term.ReadPassword %w", err)
	}
	return strings.TrimSpace(result), nil
}

// confirmPassphrase prompts the user for a passphrase and confirmation, and returns it
func confirmPassphrase(mask bool) (string, error) {
	for {
		phrase, err := readPassphrase("Passphrase: ", mask)
		if err != nil {
			return "", err
		}
		confirm, err := readPassphrase("Confirm passphrase: ", mask)
		if err != nil {
			return "", err
		}
		if phrase != confirm {
			println("Passphrase mismatch. Please try again.")
			continue
		}
		return phrase, nil
	}
}

// genKeys generates the aes, salt, and ed25519 keys
func genKeys(passphrase string) (*KeySalt, error) {
	salt := make([]byte, 128)
	if _, err := rand.Reader.Read(salt); err != nil {
		return nil, fmt.Errorf("rand.Read %w", err)
	}
	key, err := genAES(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("scrypt.Key %w", err)
	}
	result := &KeySalt{AES: key, Salt: salt}
	return result, nil
}

// genAES generates the aes key from the passphrase and salt
func genAES(passphrase string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(passphrase), []byte(salt), 32768, 8, 1, 32)
}

// Encrypt the specified message using the key
func encrypt(keys *KeySalt, message string) ([]byte, error) {
	c, err := aes.NewCipher(keys.AES)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher %w", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("chiper.NewGCM %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("reand.Read(nonce) %w", err)
	}
	buf := new(bytes.Buffer)
	buf.Write([]byte(base64.URLEncoding.EncodeToString(keys.Salt) + "\n"))
	buf.Write(gcm.Seal(nonce, nonce, []byte(message), nil))
	return buf.Bytes(), nil
}

// Decrypt the specified content using the passphrase
func decrypt(passphrase string, content []byte) (*DecryptedContent, error) {
	saltEnd := bytes.IndexRune(content, '\n')
	if saltEnd < 0 {
		return nil, errors.New("could not find the salt")
	}
	salt, err := base64.URLEncoding.DecodeString(string(content[:saltEnd]))
	if err != nil {
		return nil, fmt.Errorf("base64.DecodeString %w", err)
	}
	key, err := genAES(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("scrypt.Key %w", err)
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher %w", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("chiper.NewGCM %w", err)
	}
	cipherbytes := content[saltEnd+1:]
	nonceSize := gcm.NonceSize()
	dnonce, dbytes := cipherbytes[:nonceSize], cipherbytes[nonceSize:]
	dtext, err := gcm.Open(nil, dnonce, dbytes, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm.Open %w", err)
	}
	result := &DecryptedContent{
		KeySalt: &KeySalt{
			AES:  key,
			Salt: salt,
		},
		Content: string(dtext),
	}
	return result, nil
}
