package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/common/hexutil"
	log "github.com/sirupsen/logrus"
	"github.com/tyler-smith/go-bip39"
)

func main() {
	var encryptedMnemonic = flag.String("encrypted-mnemonic", "", "Encrypted mnemonic to decrypt: 0x prefixed hex string")
	var rawMnemonic = flag.String("raw-mnemonic", "", "Raw mnemonic to encrypt")
	var password = flag.String("password", "", "Password to encrypt/decrypt mnemonic, max 32 bytes")
	flag.Parse()

	if *encryptedMnemonic != "" && *rawMnemonic != "" {
		log.Fatal("You can't use both -encrypted-mnemonic and -raw-mnemonic flags")
	}
	if *password == "" {
		log.Fatal("You must provide a password with --password flag")
	}

	if *encryptedMnemonic != "" {
		// Decrypt mnemonic
		text, err := hexutil.Decode(*encryptedMnemonic)
		if err != nil {
			log.Fatal(err)
		}
		key := padPasswordTo32Bytes(*password)
		plaintext, err := decrypt(text, key)
		if err != nil {
			log.Fatal(err)
		}
		log.Info("Desencrypted mnemonic: ", string(plaintext))

	} else if *rawMnemonic != "" {
		// Encrypt mnemonic
		if !bip39.IsMnemonicValid(*rawMnemonic) {
			log.Fatal("Invalid mnemonic")
		}
		text := []byte(*rawMnemonic)
		key := padPasswordTo32Bytes(*password)

		ciphertext, err := encrypt(text, key)
		if err != nil {
			log.Fatal(err)
		}
		log.Info("Encrypted mnemonic: ", hexutil.Encode(ciphertext))
	}
}

func padPasswordTo32Bytes(password string) []byte {
	return []byte(fmt.Sprintf("%032s", password))
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
