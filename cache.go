package proxy

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
)

func isCached(h string) bool {
	if h == "" {
		return false
	}
	_, err := os.Open("data/" + h)
	return err == nil
}

// hash returns a sha256 representation of a url & http method
func hash(url string) string {
	log.Printf("hashing: %v\n", url)
	h := sha256.New()
	h.Write([]byte(url))
	hash := fmt.Sprintf("%x", h.Sum(nil))
	return hash
}

func fromCache(h string) ([]byte, error) {
	f, err := os.Open("data/" + h)
	if err != nil {
		return nil, fmt.Errorf("error opening cached file: %s - %v", h, err)
	}
	defer f.Close()

	log.Printf("serving cached file: %s\n", f.Name())
	info, _ := f.Stat()
	b := make([]byte, info.Size())
	_, err = f.Read(b)
	if err != nil {
		return nil, fmt.Errorf("error reading cached file: %s - %v", h, err)
	}

	return b, nil
}

func writeCache(h string, b []byte) error {
	f, err := os.Create("data/" + h)
	if err != nil {
		return fmt.Errorf("unable to create file: %v\n", err)
	}
	defer f.Close()

	if _, err = f.Write(b); err != nil {
		return fmt.Errorf("unable to write file: %v\n", err)
	}
	log.Printf("wrote cache file: %s\n", f.Name())
	return nil
}
