package secret

import (
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

type vault struct {
	path string
	key  string
}

// FileVault returns a new Vault for the file specified in path using encKey
// as the encryption key
func FileVault(encKey, path string) Vault {
	return &vault{path: path, key: encKey}
}

func (v *vault) Set(key, value string) error {
	// NOTE: By simply reading in the whole file and later writing it, there is
	// of course a race condition.
	secrets := make(map[string]string)
	eeb, err := ioutil.ReadFile(v.path) // encrypted, encoded bytes
	if err == nil {
		// TODO: Decrypt
		deb := eeb // decrypted, encoded bytes

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

	// TODO: Encrypt

	if err := ioutil.WriteFile(v.path, deb, 0755); err != nil {
		return err
	}
	return nil
}

func (v *vault) Get(key string) (value string, err error) {
	eeb, err := ioutil.ReadFile(v.path) // encrypted, encoded bytes
	if err != nil {
		return "", err
	}

	// TODO: Decrypt
	deb := eeb // decrypted, encoded bytes

	secrets := make(map[string]string)
	if err := json.Unmarshal(deb, &secrets); err != nil {
		return "", err
	}

	if value, ok := secrets[key]; ok {
		return value, nil
	}
	return "", fmt.Errorf("key %s not found", key)
}
