# GO-KEYVAULT-CERT
[![GoDoc](https://godoc.org/github.com/jfarleyx/go-keyvault-cert?status.svg)](http://godoc.org/github.com/jfarleyx/go-keyvault-cert)
[![Go Report](https://goreportcard.com/badge/github.com/jfarleyx/go-keyvault-cert)](https://goreportcard.com/report/github.com/jfarleyx/go-keyvault-cert)

go-keyvault-cert is an easy-to-use wrapper around [azure-sdk-for-go](https://github.com/Azure/azure-sdk-for-go) that allows you 
to fetch a certificate and key from Azure Key Vault. go-keyvault-cert is ideal for fetching a certificate and key from Azure Key Vault and loading the certificate into your Go application's HTTP server to facilitate TLS to your app/api.  

## Usage

``` go get github.com/jfarleyx/go-keyvault-cert ```

go-keyvault-cert is really easy to use. The simplist way to get started is to utilize Azure client credentials provided 
as environment variables. The following environment variables and their associated values 
are required: 

```AZURE_TENANT_ID```: an Azure tenant ID

```AZURE_CLIENT_ID```: an Azure client ID

```AZURE_CLIENT_SECRET```: an Azure client secret

**Note: The designated Azure client must have the following permissions to Azure Key Vault:**
- Certificate permissions: Get & List
- Secret permissions: Get

The environment variables are read by the azure-sdk-for-go when you call the ```AuthorizeFromEnvironment()``` method in ```kvcert```. 

Here is an simple example of using go-keyvault-cert to fetch a cert & key from AKV and use it in an HTTP server. The global variables ```KEY_VAULT_NAME``` & ```KEY_VAULT_CERT_NAME``` are used for example purposes only. You can provide strings in place of those two environment variables. 

```
package main

  import (
  	"context"
  	"crypto/tls"
  	"log"
  	"net/http"

  	"github.com/jfarleyx/go-keyvault-cert"
  )

  func main() {
  	// Create new key vault certificate object that will be used to fetch certificate
  	akv := kvcert.New(os.Getenv("KEY_VAULT_NAME"))

  	// Authorize access to Azure Key Vault utilizing environment variables mentioned above.
  	err := akv.AuthorizeFromEnvironment()
  	if err != nil {
  	  log.Fatalf("Error attempting to authorize azure key vault: %v", err)
  	}

  	ctx := context.Background()

  	// Fetch certificate from Azure Key Vault
  	kvCert, err := akv.GetCertificate(ctx, os.Getenv("KEY_VAULT_CERT_NAME"))
  	if err != nil {
  	  log.Fatalf("Error attempting to fetch certificate: %v", err)
  	}

  	// Convert cert & key bytes to an x509 key pair
  	x509Cert, err := tls.x509KeyPair(kvCert.Cert, kvCert.Key)
  	if err != nil {
  	  log.Fatalf("Unable to create x509 Key Pair from Key Vault Certificate: %v", err)
  	}

  	// Add x509 to tls configuration
  	config := &tls.Config{
  	  Certificates: []tls.Certificates{x509Cert},
  	}

  	// Add tls configuration to http server
  	server := &http.Server{
  	  Addr:      ":44366",
  	  TLSConfig: config,
  	}

  	server.ListenAndServeTLS("", "")
  }
```


