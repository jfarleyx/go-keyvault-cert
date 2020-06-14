# GO-KEYVAULT-CERT
[![GoDoc](https://godoc.org/github.com/jfarleyx/go-keyvault-cert?status.svg)](http://godoc.org/github.com/jfarleyx/go-keyvault-cert)
[![Go Report](https://goreportcard.com/badge/github.com/jfarleyx/go-keyvault-cert)](https://goreportcard.com/report/github.com/jfarleyx/go-keyvault-cert)

go-keyvault-cert is an easy-to-use wrapper around [azure-sdk-for-go](https://github.com/Azure/azure-sdk-for-go) that allows you 
to fetch a PEM encoded certificate from Azure Key Vault and returns an x509 ```tls.Certificate{}``` that you can use in your API's web server.  

## Usage

``` go get github.com/jfarleyx/go-keyvault-cert/v2 ```

go-keyvault-cert is really easy to use. First, register your API in Azure AD App Registration and retreive your tenant Id, client Id, and the client secret. Next, make the following environment variables available to your application: 

```AZURE_TENANT_ID```: an Azure tenant ID

```AZURE_CLIENT_ID```: an Azure app client ID

```AZURE_CLIENT_SECRET```: an Azure app client secret

**Note: The designated Azure client must have the following permissions to Azure Key Vault:**
- Certificate permissions: Get & List
- Secret permissions: Get

The environment variables are read by the azure-sdk-for-go when you call the ```AuthorizeFromEnvironment()``` method in this package (```kvcert```). 

Here is an simple example of using go-keyvault-cert to fetch an x509 certificate from Azure Key Vault and use it in an HTTP server. The global variables ```KEY_VAULT_NAME``` & ```KEY_VAULT_CERT_NAME``` are used for example purposes only. You can provide strings in place of those two environment variables. 

```
package main

  import (
  	"context"
  	"crypto/tls"
  	"log"
  	"net/http"

  	kvcert "github.com/jfarleyx/go-keyvault-cert/v2"
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
  	cert, err := akv.GetCertificate(ctx, os.Getenv("KEY_VAULT_CERT_NAME"))
  	if err != nil {
  	  log.Fatalf("Error attempting to fetch certificate: %v", err)
  	}
  	
  	// Add cert to tls configuration
  	config := &tls.Config{
  	  Certificates: []tls.Certificates{*cert},
  	}

  	// Add tls configuration to http server
  	server := &http.Server{
  	  Addr:      ":44366",
  	  TLSConfig: config,
  	}

  	server.ListenAndServeTLS("", "")
  }
```


