package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

const (
	IMAGE = "node:22-alpine"
)

var MCP_SERVER = []string{
	"npx",
	"-y",
	"@modelcontextprotocol/server-filesystem",
	"/workspace",
}

// --------------------------------------------------
// Docker Sandbox
// --------------------------------------------------

type MCPSandbox struct {
	client    *client.Client
	workspace string
	container string
}

// --------------------------------------------------
// Create Sandbox
// --------------------------------------------------

func NewMCPSandbox(workspace string) (*MCPSandbox, error) {

	// Resolve host path safely
	absPath, err := filepath.Abs(workspace)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve workspace: %w", err)
	}

	// Check that workspace exists
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf(
			"workspace does not exist: %s",
			absPath,
		)
	}

	// Check that it is a directory
	if !info.IsDir() {
		return nil, fmt.Errorf(
			"workspace is not a directory: %s",
			absPath,
		)
	}

	// Connect to Docker
	dockerClient, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to connect to Docker: %w",
			err,
		)
	}

	return &MCPSandbox{
		client:    dockerClient,
		workspace: absPath,
	}, nil
}

// --------------------------------------------------
// Start Sandbox
// --------------------------------------------------

func (s *MCPSandbox) Start(ctx context.Context) error {

	fmt.Fprintf(
		os.Stderr,
		"[sandbox] Host workspace: %s\n",
		s.workspace,
	)

	fmt.Fprintln(
		os.Stderr,
		"[sandbox] Starting isolated MCP container...",
	)

	// --------------------------------------------------
	// Container configuration
	// --------------------------------------------------

	containerConfig := &container.Config{

		// Lightweight image
		Image: IMAGE,

		// MCP filesystem server
		Cmd: MCP_SERVER,

		// MCP communicates through stdin/stdout
		OpenStdin:   true,
		AttachStdin: true,
		AttachStdout: true,
		AttachStderr: true,

		// Run as non-root user
		User: "node",

		// Read-only root filesystem
	}

	// --------------------------------------------------
	// Host configuration
	// --------------------------------------------------

	hostConfig := &container.HostConfig{

		// --------------------------------------------------
		// Filesystem isolation
		// --------------------------------------------------

		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: s.workspace,
				Target: "/workspace",
				ReadOnly: false,
			},
		},

		// Root filesystem cannot be modified
		ReadonlyRootfs: true,

		// --------------------------------------------------
		// Network isolation
		// --------------------------------------------------

		NetworkMode: "none",

		// --------------------------------------------------
		// Privilege isolation
		// --------------------------------------------------

		CapDrop: []string{"ALL"},

		SecurityOpt: []string{
			"no-new-privileges:true",
		},

		// --------------------------------------------------
		// Resource limits
		// --------------------------------------------------

		Memory: 512 * 1024 * 1024,

		NanoCPUs: 1_000_000_000,

		// --------------------------------------------------
		// Temporary writable directory
		// --------------------------------------------------

		Tmpfs: map[string]string{
			"/tmp": "rw,noexec,nosuid,size=64m",
		},

		// Do not automatically remove container
		// so it can be inspected/debugged.
		AutoRemove: false,
	}

	// --------------------------------------------------
	// Create container
	// --------------------------------------------------

	response, err := s.client.ContainerCreate(
		ctx,
		containerConfig,
		hostConfig,
		nil,
		nil,
		"",
	)

	if err != nil {
		return fmt.Errorf(
			"failed to create container: %w",
			err,
		)
	}

	s.container = response.ID

	// --------------------------------------------------
	// Start container
	// --------------------------------------------------

	err = s.client.ContainerStart(
		ctx,
		s.container,
		types.ContainerStartOptions{},
	)

	if err != nil {
		return fmt.Errorf(
			"failed to start container: %w",
			err,
		)
	}

	fmt.Fprintf(
		os.Stderr,
		"[sandbox] Container: %s\n",
		s.container[:12],
	)

	fmt.Fprintln(
		os.Stderr,
		"[sandbox] MCP server is running inside Docker.",
	)

	return nil
}

// --------------------------------------------------
// Stop Sandbox
// --------------------------------------------------

func (s *MCPSandbox) Stop(ctx context.Context) {

	if s.container == "" {
		return
	}

	timeout := 2

	err := s.client.ContainerStop(
		ctx,
		s.container,
		types.ContainerStopOptions{
			Timeout: &timeout,
		},
	)

	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"[sandbox] Failed to stop container: %v\n",
			err,
		)
	}

	fmt.Fprintln(
		os.Stderr,
		"[sandbox] Container stopped.",
	)

	s.container = ""
}

// --------------------------------------------------
// Kill Sandbox
// --------------------------------------------------

// This function can later be called by another
// security layer when malicious activity is detected.

func (s *MCPSandbox) Kill(ctx context.Context) {

	if s.container == "" {
		return
	}

	fmt.Fprintln(
		os.Stderr,
		"[sandbox] SECURITY EVENT: Killing container.",
	)

	err := s.client.ContainerKill(
		ctx,
		s.container,
		"SIGKILL",
	)

	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"[sandbox] Failed to kill container: %v\n",
			err,
		)
	}
}

// --------------------------------------------------
// Wait
// --------------------------------------------------

func (s *MCPSandbox) Wait(ctx context.Context) error {

	if s.container == "" {
		return nil
	}

	statusCh, errCh := s.client.ContainerWait(
		ctx,
		s.container,
		container.WaitConditionNotRunning,
	)

	select {

	case status := <-statusCh:

		fmt.Fprintf(
			os.Stderr,
			"[sandbox] Container exited with code %d\n",
			status.StatusCode,
		)

		return nil

	case err := <-errCh:

		return err
	}
}

// --------------------------------------------------
// Remove Container
// --------------------------------------------------

func (s *MCPSandbox) Remove(ctx context.Context) {

	if s.container == "" {
		return
	}

	err := s.client.ContainerRemove(
		ctx,
		s.container,
		types.ContainerRemoveOptions{
			Force: true,
		},
	)

	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"[sandbox] Failed to remove container: %v\n",
			err,
		)
	}

	s.container = ""
}

// --------------------------------------------------
// Main
// --------------------------------------------------

func main() {

	ctx := context.Background()

	// Current directory becomes the allowed workspace
	workspace, err := os.Getwd()

	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"Failed to get current directory: %v\n",
			err,
		)

		os.Exit(1)
	}

	// Create sandbox
	sandbox, err := NewMCPSandbox(workspace)

	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"Failed to create sandbox: %v\n",
			err,
		)

		os.Exit(1)
	}

	defer sandbox.client.Close()

	// Start sandbox
	err = sandbox.Start(ctx)

	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"Failed to start sandbox: %v\n",
			err,
		)

		os.Exit(1)
	}

	// Handle Ctrl+C
	signalChan := make(chan os.Signal, 1)

	signal.Notify(
		signalChan,
		os.Interrupt,
		syscall.SIGTERM,
	)

	// Wait for either:
	// 1. Container to exit
	// 2. Ctrl+C
	waitDone := make(chan struct{})

	go func() {

		sandbox.Wait(ctx)

		close(waitDone)

	}()

	select {

	case <-waitDone:

		fmt.Fprintln(
			os.Stderr,
			"[sandbox] Container exited.",
		)

	case <-signalChan:

		fmt.Fprintln(
			os.Stderr,
			"\n[sandbox] Shutdown requested...",
		)

		sandbox.Stop(ctx)
	}

	// Clean up container
	sandbox.Remove(ctx)
}