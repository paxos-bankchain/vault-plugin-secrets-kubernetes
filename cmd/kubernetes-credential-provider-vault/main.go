package main

import (
	"fmt"
	"github.com/paxos-bankchain/vault-plugin-secrets-kubernetes/pkg/client"
	"os"
)

func main() {
	err := client.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
