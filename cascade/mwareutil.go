package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/logrusorgru/aurora"
	"golang.org/x/crypto/scrypt"
)

type mwclient struct {
	conn   net.Conn
	aeskey []byte
}

const defaultKeyLen = 32

// DerivateKey256 creates 256 bit key based on a password. Random salt is
// returned with the key.
func DerivateKey256(password string) ([]byte, []byte, error) {
	salt, err := generateSalt(defaultKeyLen)
	if err != nil {
		return nil, nil, err
	}
	key, err := DerivateKey256WithSalt(password, salt)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

// DerivateKey256WithSalt creates 256 bit key from provided password and salt.
func DerivateKey256WithSalt(password string, salt []byte) ([]byte, error) {
	if password == "" {
		return nil, errors.New("Empty pass")
	}
	if salt == nil || len(salt) != 32 {
		return nil, errors.New("Salt is not 256 bit")
	}
	// Recommended settings for scrypt
	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, defaultKeyLen)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func generateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func generateKey() ([]byte, error) {
	return generateSalt(32)
}

// appendHMAC appends 32 bytes to data. Returns nil if no data is provided.
func appendHMAC(key, data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	macProducer := hmac.New(sha256.New, key)
	macProducer.Write(data)
	mac := macProducer.Sum(nil)
	return append(data, mac...)
}

// validateHMAC checks mac, and returns original data without mac bytes.
// Returns nil, if mac is not valid.
func validateHMAC(key, data []byte) []byte {
	if len(data) <= 32 {
		return nil
	}
	message := data[:len(data)-32]
	mac := data[len(data)-32:]
	macProducer := hmac.New(sha256.New, key)
	macProducer.Write(message)
	calculatedMac := macProducer.Sum(nil)
	if calculatedMac == nil {
		return nil
	}
	for i := 0; i < 32; i++ {
		if mac[i] != calculatedMac[i] {
			return nil
		}
	}
	return message
}

// Encrypt encrypts data with aes 256 and adds HMAC(EnM). Fails if key is not
// 256 bit or it data is empty.
func Encrypt(key, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("This is not a 256 bit key, length: " + strconv.Itoa(len(key)))
	}
	if len(data) == 0 {
		return nil, errors.New("Data is empty")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return appendHMAC(key, ciphertext), nil
}

// Decrypt validates mac and returns decoded data.
func Decrypt(key, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("This is not a 256 bit key, length: " + strconv.Itoa(len(key)))
	}
	if len(data) == 0 {
		return nil, errors.New("Data is empty")
	}
	ciphertext := validateHMAC(key, data)
	if ciphertext == nil {
		return nil, errors.New("Invalid HMAC")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("Ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	result := ciphertext[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(result, result)
	return result, nil
}

func clearConsole() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func privKeySHA1(privKey *rsa.PrivateKey) string {
	b := PrivateKeyToBytes(privKey)
	h := sha1.New()
	h.Write(b)
	bh := h.Sum(nil)
	return "[SHA1] " + hexString(bh)
}

func pubKeySHA1(pubKey *rsa.PublicKey) string {
	b := PublicKeyToBytes(pubKey)
	h := sha1.New()
	h.Write(b)
	bh := h.Sum(nil)
	return "[SHA1] " + hexString(bh)
}

func hexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

func loadKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	if _, err := os.Stat("keys/pubkey.key"); os.IsNotExist(err) {
		makeKeyPair()
	}

	fmt.Print(aurora.Green("Loading RSA-KeyPair... "))

	b, err := ioutil.ReadFile("keys/privkey.key")
	if err != nil {
		fmt.Print(err)
	}
	privkey := BytesToPrivateKey(b)

	b, err = ioutil.ReadFile("keys/pubkey.key")
	if err != nil {
		fmt.Print(err)
	}
	pubkey := BytesToPublicKey(b)

	fmt.Println(aurora.Green("Done!"))
	fmt.Println(aurora.Red("PrivateKey Fingerprint:").BgGray())
	fmt.Println(aurora.Green(privKeySHA1(privkey)))
	fmt.Println(aurora.Red("PublicKey  Fingerprint:").BgGray())
	fmt.Println(aurora.Green(pubKeySHA1(pubkey)))

	return privkey, pubkey
}

func makeKeyPair() {
	fmt.Print(aurora.Green("Generating new RSA-KeyPair with 4096 bits... "))

	_ = os.Mkdir("keys", 0777)

	privKey, pubKey := GenerateKeyPair(4096)
	err := ioutil.WriteFile("keys/privkey.key", PrivateKeyToBytes(privKey), 0777)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("keys/pubkey.key", PublicKeyToBytes(pubKey), 0777)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(aurora.Green("Done!"))
}

func printInfo(VERSION string) {
	fmt.Println(aurora.Cyan("+-----------------------------------------------+"))
	fmt.Println(aurora.Cyan("| ███╗   ███╗██╗    ██╗ █████╗ ██████╗ ███████╗ |"))
	fmt.Println(aurora.Cyan("| ████╗ ████║██║    ██║██╔══██╗██╔══██╗██╔════╝ |"))
	fmt.Println(aurora.Cyan("| ██╔████╔██║██║ █╗ ██║███████║██████╔╝█████╗   |"))
	fmt.Println(aurora.Cyan("| ██║╚██╔╝██║██║███╗██║██╔══██║██╔══██╗██╔══╝   |"))
	fmt.Println(aurora.Cyan("| ██║ ╚═╝ ██║╚███╔███╔╝██║  ██║██║  ██║███████╗ |"))
	fmt.Println(aurora.Cyan("| ╚═╝     ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ |"))
	fmt.Println(aurora.Cyan("+-----------------------------------------------+"))
	fmt.Println(aurora.Red(VERSION).BgGray())
}

// GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatal(err)
	}
	return privkey, &privkey.PublicKey
}

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	logif(err)

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

// BytesToPrivateKey bytes to private key
func BytesToPrivateKey(priv []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		logif(err)
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	logif(err)
	return key
}

// BytesToPublicKey bytes to public key
func BytesToPublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		logif(err)
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		log.Fatal(err)
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		log.Fatal("not ok")
	}
	return key
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	logif(err)
	return ciphertext
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	logif(err)
	return plaintext
}

func rB(client mwclient) []byte {
	return readBytes(client.conn, client.aeskey)
}

func readBytes(conn net.Conn, key []byte) []byte {
	b := readRawBytes(conn)
	if len(b) != 0 {
		b, err := Decrypt(key, b)
		logif(err)
		return b
	}
	return nil
}

func sB(client mwclient, data []byte) {
	sendBytes(client.conn, client.aeskey, data)
}

func sendBytes(conn net.Conn, key, data []byte) {
	b, err := Encrypt(key, data)
	logif(err)
	sendRawBytes(b, conn)
}

func bytesToInt(data []byte) int {
	return int(binary.LittleEndian.Uint32(data))
}

func intToBytes(data int) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(data))
	return buf
}

func sendRawBytes(data []byte, conn net.Conn) {
	datalen := len(data)
	//fmt.Println("Sending", datalen)
	w := bufio.NewWriter(conn)
	w.Write(intToBytes(datalen))
	w.Write(data)
	w.Flush()
}

func readRawBytes(conn net.Conn) []byte {
	r := bufio.NewReader(conn)
	buf := make([]byte, 4)
	r.Read(buf)
	datalen := bytesToInt(buf)
	//fmt.Println("Read", datalen)
	buf = make([]byte, datalen)
	r.Read(buf)
	return buf
}

func logif(err error) {
	if err != nil {
		log.Println(err)
	}
}
func gUnzipData(data []byte) (resData []byte, err error) {
	b := bytes.NewBuffer(data)

	var r io.Reader
	r, err = gzip.NewReader(b)
	if err != nil {
		return
	}

	var resB bytes.Buffer
	_, err = resB.ReadFrom(r)
	if err != nil {
		return
	}

	resData = resB.Bytes()

	return
}

func gZipData(data []byte) (compressedData []byte, err error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)

	_, err = gz.Write(data)
	if err != nil {
		return
	}

	if err = gz.Flush(); err != nil {
		return
	}

	if err = gz.Close(); err != nil {
		return
	}

	compressedData = b.Bytes()

	return
}
