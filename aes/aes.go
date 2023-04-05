package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
)

func PaddingText1(str []byte, blockSize int) []byte {
	paddingCount := blockSize - len(str)%blockSize
	paddingStr := bytes.Repeat([]byte{byte(paddingCount)}, paddingCount)
	newPaddingStr := append(str, paddingStr...)
	return newPaddingStr
}

func EncyptogAES(src, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(nil)
		return nil
	}
	src = PaddingText1(src, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	blockMode.CryptBlocks(src, src)
	return src
}

func GzipEncode(input []byte) ([]byte, error) {
	var buf bytes.Buffer
	gzipWriter, _ := gzip.NewWriterLevel(&buf, 9)
	_, err := gzipWriter.Write(input)
	if err != nil {
		_ = gzipWriter.Close()
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func main() {
	c, _ := os.ReadFile("base64Code.txt")
	k, _ := os.ReadFile("aesKey.txt")
	src := EncyptogAES(c, k)
	base64Str := base64.StdEncoding.EncodeToString(src)
	fmt.Println(base64Str)
	gzipCode, _ := GzipEncode([]byte(base64Str))
	_ = os.WriteFile("../aesBase64Code.gzip", gzipCode, 0666)
	gzipKey, _ := GzipEncode(k)
	_ = os.WriteFile("../aesKey.gzip", gzipKey, 0666)
}
