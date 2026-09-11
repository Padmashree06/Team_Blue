/**
 * Every AI agent (OpenAI, Claude, Copilot, ...) is adapted to this one
 * interface so the rest of the extension never branches on provider.
 *
 * These are intentionally thin stubs — real request/response handling,
 * auth, and streaming get filled in per-provider once the base is wired up.
 */

export interface AgentMessage {
  role: "user" | "assistant" | "tool";
  content: string;
}

export interface AgentProvider {
  readonly id: string;
  readonly displayName: string;

  isConfigured(): boolean;

  /** Establish whatever session/auth the provider needs. */
  connect(): Promise<void>;

  disconnect(): Promise<void>;

  /**
   * Send a message to the agent. mcpServerUri tells the agent where to
   * reach the local MCP server for tool calls (editor access, etc.).
   */
  send(messages: AgentMessage[], mcpServerUri: string): Promise<AgentMessage>;
}

class OpenAIAgentProvider implements AgentProvider {
  readonly id = "openai";
  readonly displayName = "OpenAI";

  isConfigured(): boolean {
    return false; // TODO: check for API key in secret storage
  }

  async connect(): Promise<void> {
    throw new Error("OpenAI provider not yet implemented");
  }

  async disconnect(): Promise<void> {}

  async send(): Promise<AgentMessage> {
    throw new Error("OpenAI provider not yet implemented");
  }
}

class AnthropicAgentProvider implements AgentProvider {
  readonly id = "anthropic";
  readonly displayName = "Claude";

  isConfigured(): boolean {
    return false; // TODO: check for API key in secret storage
  }

  async connect(): Promise<void> {
    throw new Error("Anthropic provider not yet implemented");
  }

  async disconnect(): Promise<void> {}

  async send(): Promise<AgentMessage> {
    throw new Error("Anthropic provider not yet implemented");
  }
}

class CopilotAgentProvider implements AgentProvider {
  readonly id = "copilot";
  readonly displayName = "GitHub Copilot";

  isConfigured(): boolean {
    // Copilot has no public request/response API from inside another
    // extension — this will likely need to go through the Copilot Chat
    // participant API instead of a direct provider call. Flagging this
    // as an open design question, not solved by this stub.
    return false;
  }

  async connect(): Promise<void> {
    throw new Error("Copilot provider not yet implemented");
  }

  async disconnect(): Promise<void> {}

  async send(): Promise<AgentMessage> {
    throw new Error("Copilot provider not yet implemented");
  }
}

export class AgentRegistry {
  private readonly providers = new Map<string, AgentProvider>();

  constructor() {
    this.register(new OpenAIAgentProvider());
    this.register(new AnthropicAgentProvider());
    this.register(new CopilotAgentProvider());
  }

  private register(provider: AgentProvider): void {
    this.providers.set(provider.id, provider);
  }

  get(id: string): AgentProvider | undefined {
    return this.providers.get(id);
  }

  list(): AgentProvider[] {
    return [...this.providers.values()];
  }
}