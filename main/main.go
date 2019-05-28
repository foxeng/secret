package main

import (
	"fmt"
	"os"

	"github.com/foxeng/secret"
)

const usage = `secret is a CLI for managing your secrets

Usage:
	secret get <key> -k <encKey>
	secret set <key> <value> -k <encKey>
`

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		fmt.Print(usage)
		return
	}

	// TODO: Determine path either from the user or from the environment
	path := "secrets.db"

	switch args[0] {
	case "get":
		if len(args) < 4 || args[2] != "-k" {
			fmt.Print(usage)
			return
		}
		key := args[1]
		encKey := args[3]
		v := secret.FileVault(encKey, path)
		value, err := v.Get(key)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("%q\n", value)
	case "set":
		if len(args) < 5 || args[3] != "-k" {
			fmt.Print(usage)
			return
		}
		key := args[1]
		value := args[2]
		encKey := args[4]
		v := secret.FileVault(encKey, path)
		if err := v.Set(key, value); err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Value set!")
	default:
		fmt.Print(usage)
		return
	}
}
