package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
)

func main() {
	// filename := "./week3/6.1.intro.mp4_download"
	// blockSize := int64(1024)

	filename := "./week3/dat"
	blockSize := int64(4)
	fs, err := os.Stat(filename)
	if err != nil {
		log.Fatalf("%v", err)
	}
	lastChunkSize := fs.Size() % blockSize

	f, err := os.Open(filename)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalf("%v", err)
		}
	}()
	_, errSeek := f.Seek(-lastChunkSize, 2)
	if errSeek != nil {
		log.Fatalf("%v", errSeek)
	}
	lastByteSlice := make([]byte, lastChunkSize)
	_, errRead := f.Read(lastByteSlice)
	if errRead != nil {
		log.Fatalf("%v\n", errRead)
	}
	previousHash := sha256.Sum256(lastByteSlice)
	fmt.Printf("%s >> %x\n", lastByteSlice, previousHash)

	_, errSeek2 := f.Seek(-lastChunkSize-blockSize, 2)
	if errSeek2 != nil {
		log.Fatalf("%v", errSeek2)
	}
	byteSlice := make([]byte, blockSize)
	var errSeek3 error
	for errSeek3 == nil {
		_, errReadL := f.Read(byteSlice)
		if errReadL != nil {
			log.Fatalf("%v", errReadL)
		}
		fmt.Printf("%s || %x ", byteSlice, previousHash)
		previousHash = sha256.Sum256(append(byteSlice[:], previousHash[:]...))
		fmt.Printf(" >> %x\n", previousHash)
		_, errSeek3 = f.Seek(-blockSize*2, 1)
	}
	fmt.Printf("%x\n", previousHash)
}
