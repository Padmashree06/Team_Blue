import * as vscode from "vscode";
import { McpClient } from "./mcpClient";
import { AgentRegistry } from "./agentRegistry";

let client: McpClient | undefined;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("MCP Agent Security");
  const registry = new AgentRegistry();

  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.text = "$(circle-slash) MCP: disconnected";
  statusBarItem.command = "mcpAgentSecurity.connect";
  statusBarItem.show();

  context.subscriptions.push(
    output,
    statusBarItem,

    vscode.commands.registerCommand("mcpAgentSecurity.connect", async () => {
      const config = vscode.workspace.getConfiguration("mcpAgentSecurity");
      const command = config.get<string>("serverCommand", "python3");
      const args = config.get<string[]>("serverArgs", ["-m", "mcp_server"]);
      const activeAgentId = config.get<string>("activeAgent", "anthropic");

      const agent = registry.get(activeAgentId);
      if (!agent) {
        vscode.window.showErrorMessage(`Unknown agent provider: ${activeAgentId}`);
        return;
      }

      client = new McpClient(output);
      try {
        await client.start(command, args, vscode.workspace.workspaceFolders?.[0]?.uri.fsPath);
        statusBarItem.text = `$(check) MCP: ${agent.displayName}`;
        statusBarItem.command = "mcpAgentSecurity.disconnect";
        vscode.window.showInformationMessage(
          `MCP server started. Agent provider "${agent.displayName}" is a stub — wire up its connect() next.`
        );
      } catch (err) {
        output.appendLine(`[extension] connect failed: ${String(err)}`);
        vscode.window.showErrorMessage(`Failed to start MCP server: ${String(err)}`);
      }
    }),

    vscode.commands.registerCommand("mcpAgentSecurity.disconnect", async () => {
      await client?.stop();
      client = undefined;
      statusBarItem.text = "$(circle-slash) MCP: disconnected";
      statusBarItem.command = "mcpAgentSecurity.connect";
    }),

    vscode.commands.registerCommand("mcpAgentSecurity.showLogs", () => {
      output.show();
    })
  );
}

export function deactivate(): void {
  void client?.stop();
}