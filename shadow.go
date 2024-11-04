package shadow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"os"
	"strings"

	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58"
	"github.com/twystd/tweetnacl-go/tweetnacl"
)

type File struct {
	FileName    string
	Data        []byte
	ContentType string
}

type Client struct {
	Endpoint             string
	Key                  solana.PrivateKey
	StorageAccountPubKey string
	httpClient           *http.Client
}

func NewClient(storageAccountPubKey string) (*Client, error) {
	endpoint := os.Getenv("SHADOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://shadow-storage.genesysgo.net"
	}

	privateKey, err := solana.PrivateKeyFromBase58(os.Getenv("SHADOW_KEY"))
	if err != nil {
		panic(err)
	}

	// storageAccountPubKey := os.Getenv("SHADOW_STORAGE_ACCOUNT_PUB_KEY")

	if storageAccountPubKey == "" {
		return nil, fmt.Errorf("no SHADOW_STORAGE_ACCOUNT_PUB_KEY found in env")
	}

	return &Client{
		Endpoint:             endpoint,
		Key:                  privateKey,
		StorageAccountPubKey: storageAccountPubKey,
		httpClient:           &http.Client{},
	}, nil
}

func (c *Client) SignDetached(fileNamesString string) (string, error) {
	// Create the message to be signed
	hashSum := sha256.Sum256([]byte(fileNamesString))
	fileNamesHashed := hex.EncodeToString(hashSum[:])
	msgTemplate := "ShdwDrive Signed Message:\nStorage Account: %s\nUpload files with hash: %s"
	message := fmt.Sprintf(msgTemplate, c.StorageAccountPubKey, fileNamesHashed)

	sk, err := base58.Decode(c.Key.String())
	if err != nil {
		return "", fmt.Errorf("could not decode %s: %s", c.Key, err)
	}

	if len(sk) != 64 {
		log.Fatal("Decoded key is not the correct size for a NaCl secret key (32 bytes)")
	}
	signedMessage, err := tweetnacl.CryptoSign([]byte(message), sk)
	if err != nil {
		return "", fmt.Errorf("CryptoSign: %s", err)
	}

	// Extract the detached signature (first 64 bytes)
	detachedSignature := signedMessage[:64]

	fmt.Printf("Detached Signature: %x\n", detachedSignature)

	// bs := ed25519.SignDetached(ed25519.PrivateKey(sk), []byte(message))
	return base58.Encode(detachedSignature), nil
}

func (c *Client) Sign(fileNamesString string) ([]byte, error) {
	// Create the message to be signed
	hashSum := sha256.Sum256([]byte(fileNamesString))
	fileNamesHashed := hex.EncodeToString(hashSum[:])
	msgTemplate := "ShdwDrive Signed Message:\nStorage Account: %s\nUpload files with hash: %s"
	message := fmt.Sprintf(msgTemplate, c.StorageAccountPubKey, fileNamesHashed)

	sk, err := base58.Decode(c.Key.String())
	if err != nil {
		return nil, fmt.Errorf("could not decode %s: %s", c.Key, err)
	}

	if len(sk) != 64 {
		log.Fatal("Decoded key is not the correct size for a NaCl secret key (32 bytes)")
	}
	return tweetnacl.CryptoSign([]byte(message), sk)

}

func (c *Client) UploadFiles(files []File) (*http.Response, error) {
	var allFileNames []string
	for _, file := range files {
		allFileNames = append(allFileNames, file.FileName)
	}

	fileNamesString := strings.Join(allFileNames, ",")

	signedMessage, err := c.SignDetached(fileNamesString)
	if err != nil {
		return nil, fmt.Errorf("could not sign key: %s", err)
	}

	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	for _, file := range files {

		partHeader := textproto.MIMEHeader{}
		partHeader.Set("Content-Disposition",
			fmt.Sprintf(`form-data; name="file"; filename="%s"`, file.FileName))
		partHeader.Set("Content-Type", file.ContentType)

		part, err := writer.CreatePart(partHeader)
		if err != nil {
			return nil, err
		}

		_, err = io.Copy(part, bytes.NewReader(file.Data))
		if err != nil {
			return nil, err
		}
	}

	writer.WriteField("message", signedMessage)
	writer.WriteField("signer", c.Key.PublicKey().String())
	writer.WriteField("storage_account", c.StorageAccountPubKey)
	writer.WriteField("fileNames", fileNamesString)

	if err := writer.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.Endpoint+"/upload", &requestBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	reqDump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		fmt.Println("Error dumping request:", err)
	} else {
		fmt.Println("HTTP Request:")
		fmt.Println(string(reqDump))
	}

	// Send the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
