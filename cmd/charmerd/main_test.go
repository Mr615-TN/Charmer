package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthCheckHandler(t *testing.T) {
	srv := newServer("/test/auth.log")
	handler := setupHTTPRoutes(srv)

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", rr.Code)
	}

	// Verify Security Headers
	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Content-Security-Policy": "default-src 'none'",
	}
	for header, expectedVal := range expectedHeaders {
		if val := rr.Header().Get(header); val != expectedVal {
			t.Errorf("Expected %s = %s, got %s", header, expectedVal, val)
		}
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Response is not valid JSON: %v", err)
	}

	if resp["status"] != "ok" {
		t.Errorf("Expected status: ok, got %v", resp["status"])
	}
	if resp["service"] != "charmerd" {
		t.Errorf("Expected service: charmerd, got %v", resp["service"])
	}
}

func TestThreatHistoryHandler(t *testing.T) {
	srv := newServer("/test/auth.log")
	srv.recordThreat(Threat{
		IsTruePositive:  true,
		ConfidenceScore: 0.95,
		AttackType:      "SQL Injection",
		Explanation:     "UNION SELECT detected",
	})

	handler := setupHTTPRoutes(srv)

	req, err := http.NewRequest(http.MethodGet, "/api/threats", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", rr.Code)
	}

	var resp struct {
		Count   int      `json:"count"`
		Threats []Threat `json:"threats"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Response is not valid JSON: %v", err)
	}

	if resp.Count != 1 {
		t.Errorf("Expected count 1, got %d", resp.Count)
	}
	if len(resp.Threats) != 1 || resp.Threats[0].AttackType != "SQL Injection" {
		t.Errorf("Unexpected threat data: %+v", resp.Threats)
	}
}
