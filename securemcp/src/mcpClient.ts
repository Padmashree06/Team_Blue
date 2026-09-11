import * as cp from "child_process";
import * as vscode from "vscode";

/**
 * Talks to the local Python MCP server over stdio. Defaulting to stdio
 * for the base (simplest, no open port) — swap this for an HTTP/SSE
 * transport later if the server needs to serve multiple clients.
 */
export class McpClient {
  private process: cp.ChildProcessWithoutNullStreams | undefined;
  private buffer = "";
  private nextId = 1;
  private readonly pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: unknown) => void }
  >();

  constructor(private readonly output: vscode.OutputChannel) {}

  get isRunning(): boolean {
    return this.process !== undefined && !this.process.killed;
  }

  async start(command: string, args: string[], cwd?: string): Promise<void> {
    if (this.isRunning) {
      return;
    }

    this.process = cp.spawn(command, args, { cwd });

    this.process.stdout.on("data", (chunk: Buffer) => {
      this.buffer += chunk.toString("utf8");
      this.drainBuffer();
    });

    this.process.stderr.on("data", (chunk: Buffer) => {
      this.output.appendLine(`[mcp-server:stderr] ${chunk.toString("utf8").trim()}`);
    });

    this.process.on("exit", (code, signal) => {
      this.output.appendLine(`[mcp-server] exited (code=${code}, signal=${signal})`);
      this.process = undefined;
    });

    this.process.on("error", (err) => {
      this.output.appendLine(`[mcp-server] failed to start: ${err.message}`);
    });

    this.output.appendLine(`[mcp-client] started "${command} ${args.join(" ")}"`);
  }

  async stop(): Promise<void> {
    this.process?.kill();
    this.process = undefined;
  }

  /**
   * Send a JSON-RPC style request and wait for the matching response.
   * The actual method/param shapes will follow the MCP spec once the
   * server side exists — this just establishes the framing.
   */
  async request(method: string, params: unknown): Promise<unknown> {
    if (!this.process) {
      throw new Error("MCP server is not running");
    }

    const id = this.nextId++;
    const payload = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";

    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.process!.stdin.write(payload, (err) => {
        if (err) {
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }

  private drainBuffer(): void {
    let newlineIndex: number;
    while ((newlineIndex = this.buffer.indexOf("\n")) !== -1) {
      const line = this.buffer.slice(0, newlineIndex).trim();
      this.buffer = this.buffer.slice(newlineIndex + 1);
      if (!line) {
        continue;
      }
      this.handleLine(line);
    }
  }

  private handleLine(line: string): void {
    let message: { id?: number; result?: unknown; error?: unknown };
    try {
      message = JSON.parse(line);
    } catch {
      this.output.appendLine(`[mcp-client] non-JSON line from server: ${line}`);
      return;
    }

    if (message.id === undefined) {
      // Notification from the server (no matching request) — log for now.
      this.output.appendLine(`[mcp-client] notification: ${line}`);
      return;
    }

    const waiter = this.pending.get(message.id);
    if (!waiter) {
      return;
    }
    this.pending.delete(message.id);

    if (message.error) {
      waiter.reject(message.error);
    } else {
      waiter.resolve(message.result);
    }
  }
}