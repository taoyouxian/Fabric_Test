package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

var decrypted string
var privateKey, publicKey []byte

// https://blog.csdn.net/fyxichen/article/details/50161835
func init() {
	var err error
	flag.StringVar(&decrypted, "d", "", "加密过的数据")
	flag.Parse()
	publicKey, err = ioutil.ReadFile("public.pem")
	if err != nil {
		os.Exit(-1)
	}
	//fmt.Print(string(publicKey))

	privateKey, err = ioutil.ReadFile("private.pem")
	if err != nil {
		os.Exit(-1)
	}
	//fmt.Print(string(privateKey))
}

func main() {
	var data []byte
	var err error
	data, err = RsaEncrypt([]byte("fyxichen"))
	if err != nil {
		panic(err)
	}

	// 写文件 (https://www.jianshu.com/p/7790ca1bc8f6)
	name := "data.txt"
	WriteWithIoutil(name, string(data))

	origData, err := RsaDecrypt(data)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(origData))

	// 读文件
	content := OsIoutil(name)

	origData2, err := RsaDecrypt([]byte(content))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(origData2))

}

// 加密
func RsaEncrypt(origData []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

// 解密
func RsaDecrypt(ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

//使用ioutil.WriteFile方式写入文件,是将[]byte内容写入文件,如果content字符串中没有换行符的话，默认就不会有换行符
func WriteWithIoutil(name, content string) {
	data := []byte(content)
	if ioutil.WriteFile(name, data, 0644) == nil {
		fmt.Println("写入文件成功:", content)
	}
}

func OsIoutil(name string) (string) {
	var res string
	if fileObj, err := os.Open(name); err == nil {
		//if fileObj,err := os.OpenFile(name,os.O_RDONLY,0644); err == nil {
		defer fileObj.Close()
		if contents, err := ioutil.ReadAll(fileObj); err == nil {
			result := strings.Replace(string(contents), "\n", "", 1)
			fmt.Println("Use os.Open family functions and ioutil.ReadAll to read a file :", result)
			res = result
		}
	}
	return res
}