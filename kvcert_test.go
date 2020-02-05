// Copyright 2020 John Farley. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package kvcert

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func TestNewAzureKeyVault(t *testing.T) {
	fmt.Printf("Running %s\n", t.Name())

	akv := New(os.Getenv("KEY_VAULT_NAME"))

	if akv.VaultName == "" {
		t.Fatal("Expected AzureKeyVault.VaultName to be a string, received empty string")
	}
}

func TestAuthorizeFromEnvironment(t *testing.T) {
	fmt.Printf("Running %s\n", t.Name())
	fmt.Println("  Verify the following environment variables are set...")
	fmt.Printf("  KEY_VAULT_NAME: %s\n", os.Getenv("KEY_VAULT_NAME"))
	fmt.Printf("  AZURE_TENANT_ID: %s\n", os.Getenv("AZURE_TENANT_ID"))
	fmt.Printf("  AZURE_CLIENT_ID: %s\n", os.Getenv("AZURE_CLIENT_ID"))
	fmt.Printf("  AZURE_CLIENT_SECRET: %s\n", os.Getenv("AZURE_CLIENT_SECRET"))

	akv := New(os.Getenv("KEY_VAULT_NAME"))
	err := akv.AuthorizeFromEnvironment()
	if err != nil {
		t.Fatalf("Error attempting to authorize azure key vault %v\n", err)
	}
}

func TestGetCertificate(t *testing.T) {
	fmt.Printf("Running %s\n", t.Name())
	akv := New(os.Getenv("KEY_VAULT_NAME"))

	err := akv.AuthorizeFromEnvironment()
	if err != nil {
		t.Fatalf("Error attempting to authorize azure key vault: %v\n", err)
	}
	ctx := context.Background()

	cert, err := akv.GetCertificate(ctx, os.Getenv("CERT_NAME"))
	if err != nil {
		t.Fatalf("Error attempting to fetch cert: %v\n", err)
	}
	if cert == nil {
		t.Fatal("Expected AzureKeyVaultCert struct, received nil")
	}
	if cert.Key == nil {
		t.Fatal("Expected cert key as byte slice, received nil")
	}
	if cert.Cert == nil {
		t.Fatal("Expected certificate as byte slice, received nil")
	}
}
