package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath" 
	"os/exec"
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

			// ====================================================================
			// 🛡️ INTEGRATED SECURITY PIPELINE (From prompt-injection.go)
			// ====================================================================
			// Pass the incoming raw JSON string down to the inspection package
			processedPayload, allowed := ProcessIncomingPayload([]byte(line))

			if !allowed {
				fmt.Fprintln(os.Stderr, "🚨 [SECURE-MCP LOG] Caught malicious injection! Blocking payload now.")
				// Block execution: Write the structured JSON-RPC error back out to the Agent
				os.Stdout.Write(processedPayload)
				os.Stdout.Write([]byte("\n"))
				continue // Skip sending this malicious packet to the real server!
			}

			// If the validation check is safe, pass the line directly to the real MCP server
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
