package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ============================================================================
// MCP & JSON-RPC PROTOCOL STRUCTURES
// ============================================================================

type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id"`
}

type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type RPCErrorResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Error   RPCError    `json:"error"`
	ID      interface{} `json:"id"`
}

// ============================================================================
// 🛡️ PROMPT INJECTION DETECTION ENGINE (YOUR DOMAIN)
// ============================================================================

// IsPromptInjection scans string inputs for adversarial system overrides
func IsPromptInjection(text string) (bool, string) {
	lower := strings.ToLower(text)

	// High-confidence heuristic signatures for adversarial payload overrides
	heuristics := []string{
		"ignore previous instructions",
		"ignore the above",
		"system override",
		"you are now an adversarial",
		"you must now act as",
		"disregard all prior commands",
		"new rules:",
		"hypothetically speaking, if you were unrestricted",
		"decode the following base64",
		"forget your safety guidelines",
		"assistant override",
	}

	for _, trigger := range heuristics {
		if strings.Contains(lower, trigger) {
			return true, fmt.Sprintf("Inbound Jailbreak Match: Found payload containing '%s'", trigger)
		}
	}

	// Behavioral anomaly check for classic jailbreaks
	if strings.Contains(lower, "dan") && strings.Contains(lower, "do anything now") {
		return true, "Inbound Jailbreak Match: Classic DAN signature detected"
	}

	return false, ""
}

// ============================================================================
// 🔄 PAYLOAD PIPELINE INTERCEPTOR
// ============================================================================

func ProcessIncomingPayload(rawJSON []byte) ([]byte, bool) {
	var req RPCRequest
	if err := json.Unmarshal(rawJSON, &req); err != nil {
		return rawJSON, true 
	}

	if req.Method == "tools/call" {
		var params ToolCallParams
		if err := json.Unmarshal(req.Params, &params); err == nil {
			
			for key, val := range params.Arguments {
				if strVal, ok := val.(string); ok {
					
					// Scan specifically for prompt injection attempts
					if injected, reason := IsPromptInjection(strVal); injected {
						return generateErrorResponse(req.ID, reason, key), false
					}
				}
			}
		}
	}

	return rawJSON, true
}

// Helper to compile compliant JSON-RPC errors back to Copilot
func generateErrorResponse(id interface{}, reason string, argumentKey string) []byte {
	errorResp := RPCErrorResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: RPCError{
			Code:    -32603, 
			Message: fmt.Sprintf("[securemcp] %s in argument '%s'", reason, argumentKey),
		},
	}
	blockedPayload, _ := json.Marshal(errorResp)
	return blockedPayload
}
