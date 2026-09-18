package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath" 
	"os/exec"
	"strings"
)

func main() {
	// Dynamically find the folder where 'secure-mcp' is running
	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting binary path:", err)
		os.Exit(1)
	}
	currentDir := filepath.Dir(exePath)

	// Dynamically direct your real wrapped server to the active directory
	realServerCmd := "npx"
	realServerArgs := []string{"@modelcontextprotocol/server-filesystem", currentDir}

	cmd := exec.Command(realServerCmd, realServerArgs...)

	// Link the real server's inputs/outputs to our shim variables
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating stdin pipe:", err)
		os.Exit(1)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating stdout pipe:", err)
		os.Exit(1)
	}

	// Start the real MCP server
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to start real MCP server:", err)
		os.Exit(1)
	}

	// 3. Pipeline A: Intercept messages going from AI Agent -> Real MCP Server
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return // Agent disconnected
			}

			// --- SECURITY GATEKEEPER CHECK ---
			// Check for simple prompt manipulation or dangerous destructive keywords
			if strings.Contains(strings.ToLower(line), `"rm `) || strings.Contains(strings.ToLower(line), "delete") {
				// Block execution and send a safe JSON-RPC error back to the AI Agent
				securityError := `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Security Violation: Dangerous command blocked by secure-mcp."}}` + "\n"
				os.Stdout.WriteString(securityError)
				continue // Skip sending this malicious text to the real server!
			}

			// If safe, pass the line straight to the real MCP server
			serverIn.Write([]byte(line))
		}
	}()

	// 4. Pipeline B: Forward responses from Real MCP Server -> AI Agent
	go func() {
		io.Copy(os.Stdout, serverOut)
	}()

	// Keep the shim alive until the background server exits
	cmd.Wait()
}
