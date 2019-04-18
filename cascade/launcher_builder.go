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

var defaultkey []byte

func main() {
	defaultkey := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	os.Mkdir("in", 0777)
	os.Mkdir("tmp", 0777)
	os.Mkdir("out", 0777)

	fmt.Println("Please enter the name of the main file!")
	mainfile := readString(":")

	fmt.Println("Please list the names of the OTHER .exe files,\n loacted in the \"in\" folder!")
	fmt.Println("Seperated by \";\"")
	otherfiles := strings.Split(readString(":"), ";")

	otherfiles = append(otherfiles, mainfile)

	fmt.Println("Starting...")

	copy("launcher/launcher.go", "tmp/launcher.go")
	//copy("launcher/dynamic.go", "tmp/dynamic.go")

	addFile(mainfile)
	for _, filename := range otherfiles {
		addFile(mainfile)
	}
}

func addFile(path string) {
	fmt.Println("[" + path + "]")
	data, err := ioutil.ReadFile(path)
	mwutil.Logif(err)
	fmt.Print("Compressing... ")
	startsize := len(data)
	data, err = mwutil.Gzipdata(data)
	mwutil.Logif(err)
	fmt.Println("Done!")

	percent := len(data) / startsize * 100
	fmt.Println(strconv.Itoa(startsize) + " -> " + strconv.Itoa(len(data)) + " [" + strconv.Itoa(percent) + "%]")

	fmt.Print("Encrypting... ")
	data, err = mwutil.AesEncrypt(defaultkey, data)
	mwutil.Logif(err)
	fmt.Println("Done!")
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
