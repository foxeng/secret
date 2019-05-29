package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

// A Vault represents a secrets vault kept in a file
type Vault interface {
	Set(key, value string) error
	Get(key string) (value string, err error)
}

type encKey [32]byte

type vault struct {
	path string
	key  encKey
}

func encryptAES(key encKey, message []byte) (encrypted []byte) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic("Internal key size is not right!")
	}
	iv := make([]byte, block.BlockSize()) // NOTE: Normally, this should be properly initialized
	stream := cipher.NewCFBEncrypter(block, iv)
	encrypted = make([]byte, len(message))
	stream.XORKeyStream(encrypted, message)
	return encrypted
}

func decryptAES(key encKey, encrypted []byte) (message []byte) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic("Internal key size is not right!")
	}
	iv := make([]byte, block.BlockSize()) // NOTE: Normally, this should be properly initialized
	stream := cipher.NewCFBDecrypter(block, iv)
	message = make([]byte, len(encrypted))
	stream.XORKeyStream(message, encrypted)
	return message
}

// FileVault returns a new Vault for the file specified in path using encKey
// as the encryption key
func FileVault(key, path string) Vault {
	return &vault{path: path, key: sha256.Sum256([]byte(key))}
}

func (v *vault) Set(key, value string) error {
	// NOTE: By simply reading in the whole file and later writing it, there is
	// of course a race condition.
	secrets := make(map[string]string)
	eeb, err := ioutil.ReadFile(v.path) // encrypted, encoded bytes
	if err == nil {
		deb := decryptAES(v.key, eeb) // decrypted, encoded bytes

		if err := json.Unmarshal(deb, &secrets); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) { // fail only if the file already exists
		return err
	}

	secrets[key] = value
	deb, err := json.Marshal(secrets) // decrypted, encoded bytes
	if err != nil {
		return err
	}

	eeb = encryptAES(v.key, deb) // encrypted, encoded bytes

	if err := ioutil.WriteFile(v.path, eeb, 0644); err != nil {
		return err
	}
	return nil
}

func (v *vault) Get(key string) (value string, err error) {
	eeb, err := ioutil.ReadFile(v.path) // encrypted, encoded bytes
	if err != nil {
		return "", err
	}

	deb := decryptAES(v.key, eeb) // decrypted, encoded bytes

	secrets := make(map[string]string)
	if err := json.Unmarshal(deb, &secrets); err != nil {
		return "", err
	}

	if value, ok := secrets[key]; ok {
		return value, nil
	}
	return "", fmt.Errorf("key %s not found", key)
}
