// main_test.go
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestItemsHandler(t *testing.T) {
	// Set up a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(itemsHandler))
	defer server.Close()

	// Make a request to the mock server
	resp, err := http.Get(server.URL + "/logs1")
	if err != nil {
		t.Fatalf("Failed to make a request: %v", err)
	}
	defer resp.Body.Close()

	// Check the status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

}

func TestHelpHandler(t *testing.T) {
	// Set up a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(helpHandler))
	defer server.Close()

	// Make a request to the mock server
	resp, err := http.Get(server.URL + "/help")
	if err != nil {
		t.Fatalf("Failed to make a request: %v", err)
	}
	defer resp.Body.Close()

	// Check the status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

}
