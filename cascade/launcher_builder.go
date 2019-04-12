package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/Craumix/mwutil"
)

func main() {
	os.Mkdir("in", 0777)
	os.Mkdir("tmp", 0777)
	os.Mkdir("out", 0777)

	compress := readBool("Compress?")
	encrypt := readBool("Encrypt?")
	_ = encrypt
	_ = compress

	fmt.Println("Please enter the name of the main file!")
	mainfile := readString(":")

	fmt.Println("Please list the names of the OTHER .exe files,\n loacted in the \"in\" folder!")
	fmt.Println("Seperated by \";\"")
	otherfiles := strings.Split(readString(":"), ";")

	otherfiles = append(otherfiles, mainfile)

	copy("launcher/launcher.go", "tmp/launcher.go")
	//copy("launcher/dynamic.go", "tmp/dynamic.go")
	dynfile, err := string(ioutil.ReadFile("launcher/dynamic.go"))
	mwutil.Logif(err)
	dynfile = strings.ReplaceAll(dynfile, "//COMPRESSION_PLACEHOLDER", "iscompressed="+strconv.FormatBool(compress))
	if encrypt {
		key, _ := mwutil.GenKey()
		dynfile = strings.ReplaceAll(dynfile, "//COMPRESSION_PLACEHOLDER", "encryptionkey="+byteToString(key))

	}
}

func byteToString(data []byte) string {

}

func readBool(msg string) bool {
	s := strings.ToLower(readString(msg + " [y/n]"))
	if s == "y" {
		return true
	} else if s == "n" {
		return false
	} else {
		fmt.Println("Invalid!")
		return readBool(msg)
	}
}

func readString(msg string) string {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print(msg + " ")
	input, _ := reader.ReadString('\n')
	return strings.ReplaceAll(input, "\n", "")
}

func copy(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}
