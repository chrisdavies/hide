package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

type AESKey struct {
	Key  []byte
	Salt []byte
}

func main() {
	pass, err := confirmPassphrase()
	if err != nil {
		panic(err)
	}
	key, err := genAesKey(pass)
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.URLEncoding.EncodeToString(key.Key))
	fmt.Println(base64.URLEncoding.EncodeToString(key.Salt))
}

// println prints to os.Stderr so that we don't interrupt piping
func println(a ...any) {
	fmt.Fprintln(os.Stderr, a...)
}

// readPassphrase prompts the user for a passphrase and returns it
func readPassphrase(prompt string) (string, error) {
	println(prompt)
	f, err := os.Open("/dev/tty")
	if err != nil {
		return "", fmt.Errorf("os.Open /dev/tty %w", err)
	}
	result, err := term.ReadPassword(int(f.Fd()))
	if err != nil {
		return "", fmt.Errorf("term.ReadPassword %w", err)
	}
	return string(result), nil
}

// confirmPassphrase prompts the user for a passphrase and confirmation, and returns it
func confirmPassphrase() (string, error) {
	for {
		phrase, err := readPassphrase("Passphrase: ")
		if err != nil {
			return "", err
		}
		confirm, err := readPassphrase("Confirm passphrase: ")
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

// genAesKey generates a salt and key from a passphrase
func genAesKey(passphrase string) (*AESKey, error) {
	salt := make([]byte, 128)
	if _, err := rand.Reader.Read(salt); err != nil {
		return nil, fmt.Errorf("rand.Read %w", err)
	}
	key, err := scrypt.Key([]byte(passphrase), []byte(salt), 32768, 8, 1, 256)
	if err != nil {
		return nil, fmt.Errorf("scrypt.Key %w", err)
	}
	result := &AESKey{Key: key, Salt: salt}
	return result, nil
}
