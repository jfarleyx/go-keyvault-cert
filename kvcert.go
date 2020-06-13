// Copyright 2020 John Farley. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

// Package kvcert is a simple utility that utilizes the azure-sdk-for-go to
// fetch a Certificate from Azure Key Vault. The certificate can then be used
// in your Go web server to support TLS communication.
//
// A trivial example is below. This example uses the following environment
// variables:
//
// KEY_VAULT_NAME: name of your Azure Key Vault
//
// KEY_VAULT_CERT_NAME: name of your certificate in Azure Key Vault
//
// AZURE_TENANT_ID: azure tenant id (not visible in example, but required by azure-sdk-for-go)
//
// AZURE_CLIENT_ID: azure client id (not visible in example, but required by azure-sdk-for-go)
//
// AZURE_CLIENT_SECRET: azure client secret (not visible in example, but required by azure-sdk-for-go)
//
//  package main
//
//  import (
//  	"context"
//  	"crypto/tls"
//  	"log"
//  	"net/http"
//
//  	"github.com/jfarleyx/go-keyvault-cert"
//  )
//
//  func main() {
//  	// Create new key vault certificate object that will be used to fetch certificate
//  	akv := kvcert.New(os.Getenv("KEY_VAULT_NAME"))
//
//  	// Authorize access to Azure Key Vault utilizing environment variables mentioned above.
//  	err := akv.AuthorizeFromEnvironment()
//  	if err != nil {
//  	  log.Fatalf("Error attempting to authorize azure key vault: %v", err)
//  	}
//
//  	ctx := context.Background()
//
//  	// Fetch certificate from Azure Key Vault
//  	cert, err := akv.GetCertificate(ctx, os.Getenv("KEY_VAULT_CERT_NAME"))
//  	if err != nil {
//  	  log.Fatalf("Error attempting to fetch certificate: %v", err)
//  	}
//
//  	// Add x509 certificate to tls configuration
//  	tlsConfig := &tls.Config{
//  	  Certificates: []tls.Certificates{cert},
//  	}
//
//  	// Add tls configuration to http server
//  	server := &http.Server{
//  	  Addr:      ":44366",
//  	  TLSConfig: tlsConfig,
//  	}
//
//  	server.ListenAndServeTLS("", "")
//  }
package kvcert

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
	"golang.org/x/crypto/pkcs12"
)

// AzureKeyVault is a Key Vault client that facilitates connecting to and communicating with an Azure Key Vault instance.
type AzureKeyVault struct {
	// VaultName is the name of the Azure Key Vault.
	VaultName string
	// authenticated is set to true when the Key Vault client is authenticated
	authenticated bool
	// client is the keyvault.BaseClient that facilitates communication with Azure Key Vault.
	client keyvault.BaseClient
	// The URL to a specific Azure Key Vault. Comprised of protocol (https), VaultName, and azure.PublicCloud.KeyVaultDNSSuffix.
	vaultBaseURL string
}

// azureKeyVaultCert contains a private key and the certs associated
// with that key that were fetched from Azure Key Vault.
type azureKeyVaultCert struct {
	// key represents the private key of the certificate
	key []byte
	// cert represents the server certificate
	cert []byte
}

// New creates and returns a new kvcert.AzureKeyVault struct.
func New(vaultName string) *AzureKeyVault {
	return &AzureKeyVault{
		VaultName:     vaultName,
		authenticated: false,
		client:        keyvault.New(),
		vaultBaseURL:  fmt.Sprintf("https://%s.%s", vaultName, azure.PublicCloud.KeyVaultDNSSuffix),
	}
}

// AuthorizeFromEnvironment creates a keyvault dataplane Authorizer configured from environment variables in the
// order: 1. Client credentials 2. Client certificate 3. Username password 4. MSI. See github.com/Azure/azure-sdk-for-go/services/keyvault/auth
// for more details.
func (kv *AzureKeyVault) AuthorizeFromEnvironment() error {
	if os.Getenv("AZURE_TENANT_ID") == "" {
		return errors.New("AZURE_TENANT_ID environment variable not found")
	}

	if os.Getenv("AZURE_CLIENT_ID") == "" {
		return errors.New("AZURE_CLIENT_ID environment variable not found")
	}

	if os.Getenv("AZURE_CLIENT_SECRET") == "" {
		return errors.New("AZURE_CLIENT_SECRET environment variable not found")
	}

	authorizer, err := auth.NewAuthorizerFromEnvironment()
	if err != nil {
		return fmt.Errorf("Error occurred while authorizing: %v", err)
	}

	kv.client.Authorizer = authorizer
	kv.authenticated = true

	return nil
}

// GetCertificate returns an X509 Certificate from Azure Key Vault Certificate store.
func (kv *AzureKeyVault) GetCertificate(ctx context.Context, certName string) (*tls.Certificate, error) {
	if !kv.authenticated {
		return nil, errors.New("Not Authorized - invoke AuthorizeFromEnvironment() first")
	}

	// make sure a cert name is provided, otherwise we risk returning the wrong certificate
	if strings.Trim(certName, " ") == "" {
		return nil, errors.New("Certificate name not provided")
	}

	// get version id for current version of certificate
	certVersion, err := kv.getLatestCertVersion(ctx, certName)
	if err != nil {
		return nil, err
	}

	// Fetch key from secret in Azure Key Vault.
	secBundle, err := kv.client.GetSecret(ctx, kv.vaultBaseURL, certName, certVersion)
	if err != nil {
		return nil, fmt.Errorf("Error fetching secret: %v", err)
	}

	// Decode string to byte slice
	pfxBytes, err := base64.StdEncoding.DecodeString(*secBundle.Value)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode keyvault.SecretBundle.Value: %v", err)
	}

	// Using ToPEM, because some of our PFX files contain multiple certs (cert chain).
	// Decode throws an error if there are multiple certs.
	pemBlocks, err := pkcs12.ToPEM(pfxBytes, "")
	if err != nil {
		return nil, fmt.Errorf("Error converting PFX contents to PEM blocks: %v", err)
	}

	// A PFX can contain more than one cert and we need to account for that here.
	certs := &azureKeyVaultCert{}
	for i, v := range pemBlocks {
		if strings.Contains(v.Type, "KEY") == true {
			var keyPEM bytes.Buffer
			err = pem.Encode(&keyPEM, pemBlocks[i])
			if err != nil {
				return nil, fmt.Errorf("Error encoding key pem block: %v", err)
			}
			certs.key = keyPEM.Bytes()
		}

		if strings.Contains(v.Type, "CERTIFICATE") == true {
			var certPEM bytes.Buffer
			err = pem.Encode(&certPEM, pemBlocks[1])
			if err != nil {
				return nil, fmt.Errorf("Error encoding certificate pem block: %v", err)
			}

			if certs.cert == nil {
				certs.cert = certPEM.Bytes()
			} else {
				certs.cert = append(certs.cert, certPEM.Bytes()...)
			}
		}
	}

	// Convert to x509 certificate
	cert, err := tls.X509KeyPair(certs.cert, certs.key)
	if err != nil {
		return nil, fmt.Errorf("Error creating X509 Key Pair: %v", err)
	}

	return &cert, nil
}

// getLatestCertVersion returns the identifier for the most recent version of the certificate.
func (kv *AzureKeyVault) getLatestCertVersion(ctx context.Context, certName string) (version string, err error) {
	// List certificate versions
	list, err := kv.client.GetCertificateVersionsComplete(ctx, kv.vaultBaseURL, certName, nil)
	if err != nil {
		return "", fmt.Errorf("Error while trying to fetch certificate versions from Azure Key Vault: %v", err)
	}

	// Iterate through the list and get the last version
	var lastItemDate time.Time
	var lastItemVersion string
	for list.NotDone() {
		// Get element
		item := list.Value()
		// Filter only enabled items
		if *item.Attributes.Enabled {
			// Get the most recent element
			updatedTime := time.Time(*item.Attributes.Updated)
			if lastItemDate.IsZero() || updatedTime.After(lastItemDate) {
				lastItemDate = updatedTime

				// Get the ID
				parts := strings.Split(*item.ID, "/")
				lastItemVersion = parts[len(parts)-1]
			}
		}
		// Iterate to next
		list.Next()
	}

	return lastItemVersion, nil
}
