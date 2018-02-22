package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"log"
)

type aesMode int

const (
	// CBC is Cipher Block Chaining
	CBC = aesMode(1)
	// CTR is CounTeR
	CTR = aesMode(2)
)

type examQ struct {
	aesMode
	key        string
	cipherText string
}

func main() {

	examQs := []examQ{
		{
			aesMode:    CBC,
			key:        `140b41b22a29beb4061bda66b6747e14`,
			cipherText: `4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81`,
		},
		{
			aesMode:    CBC,
			key:        `140b41b22a29beb4061bda66b6747e14`,
			cipherText: `5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253`,
		},
		{
			aesMode:    CTR,
			key:        `36f18357be4dbd77f050515c73fcf9f2`,
			cipherText: `69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329`,
		},
		{
			aesMode:    CTR,
			key:        `36f18357be4dbd77f050515c73fcf9f2`,
			cipherText: `770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451`,
		},
	}

	for _, eq := range examQs {
		res, err := eq.decode()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", res)
	}

}

func (eq examQ) decode() ([]byte, error) {
	keyHex, errKDec := hex.DecodeString(eq.key)
	if errKDec != nil {
		return nil, errKDec
	}

	cipherTextHex, errCDec := hex.DecodeString(eq.cipherText)
	if errCDec != nil {
		return nil, errCDec
	}

	switch eq.aesMode {
	case CBC:
		return cbcDecrypt(keyHex, cipherTextHex)
	case CTR:
		return ctrDecrypt(keyHex, cipherTextHex)
	default:
		return nil, fmt.Errorf("error decode")
	}
}

func cbcDecrypt(key, ciphertext []byte) ([]byte, error) {

	block, errNC := aes.NewCipher(key)
	if errNC != nil {
		return nil, errNC
	}
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}

func ctrDecrypt(key, ciphertext []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]

	// CTR mode is the same for both encryption and decryption, so we can
	// also decrypt that ciphertext with NewCTR.
	stream := cipher.NewCTR(block, iv)

	plaintext := make([]byte, len(ciphertext))
	stream = cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	return plaintext, nil
}
