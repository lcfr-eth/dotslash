// dtswap.go - Injects a .so into target ELF by changing dt_debug to dt_needed.
// build: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o dtswap dtswap.go
// ~lcfr

package main

import (
  "bytes"
  "fmt"
  "io/ioutil"
  "os"
  "github.com/6F75746C6177/debug/elf"
)

func check(e error) {
  if e != nil {
    panic(e)
  }
}

func main() {
  // best to check included libs here and find one that has a nice name because we will "strip" the first 3 characters
  // of the name to make that name our new .so path so libc.so.5 becomes c.so.5 etc.
  if len(os.Args) < 2 {
    fmt.Println("Usage: src.elf lib2mimic out.elf")
    os.Exit(1)
  }

  srcBin, err := ioutil.ReadFile(os.Args[1])
  check(err)

  if srcBin[0] != '\x7f' || srcBin[1] != 'E' || srcBin[2] != 'L' || srcBin[3] != 'F' {
    fmt.Printf("Bad magic number at %d\n", srcBin[0:4])
    os.Exit(1)
  }

  _elf, err := elf.NewFile(bytes.NewReader(srcBin))
  check(err)

  dyn := _elf.DynTags
  for idx, j := range dyn {
    switch j.Tag {
      case elf.DT_DEBUG:
        fmt.Printf("changing DT_DEBUG -> DT_NEEDED\n")
        // not properly changing Value this would duplicate the value at 0 + 3..
        // add ability to search strtab for a specified lib idx/value
        _elf.DynTags[idx] = elf.DynTagValue{Tag: elf.DT_NEEDED, Value: _elf.DynTags[0].Value+3 }
      }
  }

  // maybe: verify DT_NEEDED addition with a 2nd loop verifying ...
  // so the user doesnt have to verify with readelf etc.
  destBytes, _ := _elf.Bytes()
  destFile     := os.Args[3]

  f, err := os.Create(destFile)
  check(err)

  defer f.Close()
  _, err = f.Write(destBytes)
  check(err)
}
