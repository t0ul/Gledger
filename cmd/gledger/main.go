// Command gledger works with hash-chained audit logs.
//
//	gledger verify [audit.jsonl]              # check the chain
//	gledger view   [audit.jsonl] [out.html]   # verify, then write a replayable HTML timeline
package main

import (
	"fmt"
	"os"

	"github.com/t0ul/gledger"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "verify":
		path := arg(2, "logs/audit.jsonl")
		ok, n := gledger.VerifyFile(path)
		fmt.Printf("chain_ok=%v records=%d\n", ok, n)
		if !ok {
			os.Exit(1)
		}
	case "view":
		path := arg(2, "logs/audit.jsonl")
		out := arg(3, "audit.html")
		ok, n := gledger.VerifyFile(path)
		fmt.Printf("chain_ok=%v records=%d\n", ok, n)
		recs, err := gledger.Read(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pageHTML, err := gledger.RenderHTML(path, recs, ok)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(out, pageHTML, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s (%d records)\n", out, n)
	default:
		usage()
	}
}

func arg(i int, def string) string {
	if len(os.Args) > i {
		return os.Args[i]
	}
	return def
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  gledger verify [audit.jsonl]\n  gledger view [audit.jsonl] [out.html]")
	os.Exit(2)
}
