package shadow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
		return nil, fmt.Errorf("could not find SHADOW_KEY")
	}

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

// createSignMessage creates the message to be signed for Shadow Drive
func (c *Client) createSignMessage(fileNamesString string) string {
	hashSum := sha256.Sum256([]byte(fileNamesString))
	fileNamesHashed := hex.EncodeToString(hashSum[:])
	msgTemplate := "Shadow Drive Signed Message:\nStorage Account: %s\nUpload files with hash: %s"
	return fmt.Sprintf(msgTemplate, c.StorageAccountPubKey, fileNamesHashed)
}

func (c *Client) SignDetached(fileNamesString string) (string, error) {

	signedMessage, err := c.Sign(fileNamesString)
	if err != nil {
		return "", fmt.Errorf(": %s", err)
	}

	detachedSignature := signedMessage[:64]

	return base58.Encode(detachedSignature), nil
}

func (c *Client) Sign(fileNamesString string) ([]byte, error) {
	message := c.createSignMessage(fileNamesString)
	return tweetnacl.CryptoSign([]byte(message), c.Key)
}

func (c *Client) UploadFiles(files []multipart.File, filenames []string, contentTypes []string) ([]string, error) {
	if len(files) != len(filenames) || len(files) != len(contentTypes) {
		return nil, fmt.Errorf("files, filenames, and contentTypes must have the same length")
	}

	fileNamesString := strings.Join(filenames, ",")
	signedMessage, err := c.SignDetached(fileNamesString)
	if err != nil {
		return nil, fmt.Errorf("could not sign key: %s", err)
	}

	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	for i, file := range files {
		filename := filenames[i]
		contentType := contentTypes[i]

		partHeader := textproto.MIMEHeader{}
		partHeader.Set("Content-Disposition",
			fmt.Sprintf(`form-data; name="file"; filename="%s"`, filename))
		partHeader.Set("Content-Type", contentType)

		part, err := writer.CreatePart(partHeader)
		if err != nil {
			return nil, err
		}

		_, err = io.Copy(part, file)
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
	defer resp.Body.Close()
	// Read and parse the response
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract finalized_locations
	locations, ok := result["finalized_locations"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("finalized_locations not found in response")
	}

	// Convert locations to []string
	finalizedLocations := make([]string, len(locations))
	for i, loc := range locations {
		finalizedLocations[i] = loc.(string)
	}

	return finalizedLocations, nil
}
