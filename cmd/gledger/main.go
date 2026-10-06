// Command gledger verifies the integrity of a hash-chained audit log.
//
//	gledger verify logs/audit.jsonl
package main

import (
	"fmt"
	"os"

	"github.com/t0ul/gledger"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: gledger verify [audit.jsonl]")
		os.Exit(2)
	}
	path := "logs/audit.jsonl"
	if len(os.Args) > 2 {
		path = os.Args[2]
	}
	ok, n := gledger.VerifyFile(path)
	fmt.Printf("chain_ok=%v records=%d\n", ok, n)
	if !ok {
		os.Exit(1)
	}
}
