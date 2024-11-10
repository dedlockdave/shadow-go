package shadow

import (
	"bytes"
	"fmt"
	"log"
	"mime/multipart"
	"testing"

	"github.com/twystd/tweetnacl-go/tweetnacl"
)

func TestSign(t *testing.T) {

	client, err := NewClient("C4W2QJYnE2z3HQtW4SeH6F2nzWSiPZuYAukuJfV8xHbW")
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	message := "testme"
	signature, err := client.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}
	valid, err := tweetnacl.CryptoSignOpen(signature, client.Key.PublicKey().Bytes())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("📌 %+s\n", valid)
}

// InMemoryFile implements the multipart.File interface for testing
type InMemoryFile struct {
	*bytes.Reader
}

func (f *InMemoryFile) Close() error {
	// No action needed for in-memory file
	return nil
}

// NewInMemoryFile creates a new InMemoryFile with the provided data
func NewInMemoryFile(data []byte) *InMemoryFile {
	return &InMemoryFile{
		Reader: bytes.NewReader(data),
	}
}

func TestUpload(t *testing.T) {
	client, err := NewClient("C4W2QJYnE2z3HQtW4SeH6F2nzWSiPZuYAukuJfV8xHbW")
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}
	if client == nil {
		t.Fatal("Client is nil")
	}

	// Create the file content
	fileContent := []byte("hello")

	// Create an in-memory file that satisfies the multipart.File interface
	file := NewInMemoryFile(fileContent)

	// Prepare slices for the files, filenames, and contentTypes
	files := []multipart.File{file}
	filenames := []string{"test-file.txt"}
	contentTypes := []string{"text/plain"}

	res, err := client.UploadFiles(files, filenames, contentTypes)
	if err != nil {
		t.Fatalf("UploadFiles failed: %v", err)
	}

	log.Printf("Response: %v", res)
}
