package shadow

import (
	"encoding/json"
	"fmt"
	"log"
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
	decodedPubKey := client.Key.PublicKey()
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	fmt.Printf("📌 %+v\n", decodedPubKey)

	// Verify the signature using the public key and the message
	valid, err := tweetnacl.CryptoSignOpen(signature, decodedPubKey.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("📌 %+s\n", valid)

	// fmt.Printf("📌 %+v\n", signature)

	// // Decode the base58 signature
	// decodedSignature, err := base58.Decode(signature)
	// if err != nil {
	// 	t.Fatalf("Failed to decode signature: %v", err)
	// }

	// Reconstruct the original message that was signed
	// hashSum := sha256.Sum256([]byte(message))
	// fileNamesHashed := hex.EncodeToString(hashSum[:])
	// msgTemplate := "ShdwDrive Signed Message:\nStorage Account: %s\nUpload files with hash: %s"
	// originalMessage := fmt.Sprintf(msgTemplate, client.StorageAccountPubKey, fileNamesHashed)

	// Decode the base58 encoded public key from the client

}

func TestUpload(t *testing.T) {
	client, err := NewClient("C4W2QJYnE2z3HQtW4SeH6F2nzWSiPZuYAukuJfV8xHbW")
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}
	if client == nil {
		t.Fatal("Client is nil")
	}

	res, err := client.UploadFiles([]File{
		{
			FileName:    "test-file",
			Data:        []byte("hello"),
			ContentType: "text/plain",
		},
	})

	if err != nil {
		log.Fatalf("we failed %s", err)
	}

	defer res.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	log.Printf("Response: %v", result)

}
