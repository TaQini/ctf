package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)
import "net"

func main() {
	fmt.Println("hello there~")
	sha := sha256.New()
	sha.Write([]byte(os.Getenv("passwd")))
	key := sha.Sum([]byte(""))[:aes.BlockSize]
	fmt.Printf("key: %x, %d\n\n", key, len(key))

	listener, err := net.Listen("tcp", ":1080")
	if err != nil {
		panic("Error on create listening sockets.")
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			break
		}
		go handleConn(conn, key)
	}
}

func handleConn(conn net.Conn, key []byte) {
	defer conn.Close()
	in := handleIn(conn, key)
	out := handleOut(conn, key)

	target, err := parseDest(in); if err != nil {
		fmt.Println("error on parse destination:", err)
		return
	}
	fmt.Println("target: ", target)

	remote, err := net.DialTimeout("tcp", target, 3 * time.Second); if err != nil {
		fmt.Println("error on connect remote server:", err)
		return
	}
	defer remote.Close()

	buf := readWithTimeout(in)
	_, err = remote.Write(buf); if err != nil {
		return
	}

	remote_response := readWithTimeout(remote)
	pad := generatePadding(len(remote_response))
	remote_response = append(remote_response, pad...)
	fmt.Println(len(remote_response))
	_, err = out.Write(remote_response); if err != nil {
		fmt.Println("error when writing response")
		return
	}

	println()
}

func handleIn(conn net.Conn, key []byte) net.Conn {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	var iv [aes.BlockSize]byte
	stream := cipher.NewCFBDecrypter(block, iv[:])
	reader := cipher.StreamReader{
		S: stream,
		R: conn,
	}

	pr, pw := net.Pipe()
	go func() {
		for {
			if _, err := io.Copy(pw, reader); err != nil {
				return
			}
		}
	}()
	return pr
}

func handleOut(conn net.Conn, key []byte) net.Conn {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	var iv [aes.BlockSize]byte
	stream := cipher.NewCFBEncrypter(block, iv[:])
	writer := cipher.StreamWriter{
		S: stream,
		W: conn,
	}

	pr, pw := net.Pipe()
	go func() {
		for {
			if _, err := io.Copy(writer, pr); err != nil {
				return
			}
		}
	}()
	return pw
}

func parseDest(in net.Conn) (string, error) {
	type_, err := readUntil(in, 1)
	if err != nil {
		return "", err
	}
	fmt.Println("type: ", type_[0])

	switch type_[0] {
	case 0x01:
		buf, err := readUntil(in, 4)
		if err != nil {
			return "", err
		}
		ip_addr := net.IP(buf)

		buf, err = readUntil(in, 2)
		if err != nil {
			return "", err
		}
		port := binary.BigEndian.Uint16(buf)
		return fmt.Sprintf("%s:%d", ip_addr, port), nil
	case 0x03:
		len_, err := readUntil(in, 1)
		if err != nil {
			return "", err
		}
		domain, err := readUntil(in, int(len_[0]))
		buf, err := readUntil(in, 2)
		if err != nil {
			return "", err
		}
		port := binary.BigEndian.Uint16(buf)
		return fmt.Sprintf("%s:%d", domain, port), nil
	default:
		return "", errors.New("no such method")
	}
}

func readUntil(src net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	nbytes, err := src.Read(buf)
	if nbytes != n || err != nil {
		return nil, errors.New("not enough data")
	}
	return buf, nil
}

func readWithTimeout(in net.Conn) []byte {
	var result []byte
	buf := make([]byte, 1024)
	in.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	for {
		nbytes, err := in.Read(buf)
		result = append(result, buf[:nbytes]...)
		if err != nil {
			break
		}
	}
	return result
}

func generatePadding(nbytes int) []byte {
	pad := make([]byte, aes.BlockSize - nbytes % aes.BlockSize)
	for i := range pad {
		pad[i] = byte(aes.BlockSize - nbytes % aes.BlockSize)
	}
	return pad
}