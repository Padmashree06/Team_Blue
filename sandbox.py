import docker
from pathlib import Path
import sys


# --------------------------------------------------
# Configuration
# --------------------------------------------------

IMAGE = "node:22-alpine"

MCP_SERVER = [
    "npx",
    "-y",
    "@modelcontextprotocol/server-filesystem",
    "/workspace",
]


# --------------------------------------------------
# Docker Sandbox
# --------------------------------------------------

class MCPSandbox:

    def __init__(self, workspace: str):

        self.client = docker.from_env()

        # Resolve host path safely
        self.workspace = Path(workspace).resolve()

        if not self.workspace.exists():
            raise ValueError(
                f"Workspace does not exist: {self.workspace}"
            )

        if not self.workspace.is_dir():
            raise ValueError(
                f"Workspace is not a directory: {self.workspace}"
            )

        self.container = None


    def start(self):

        print(
            f"[sandbox] Host workspace: {self.workspace}",
            file=sys.stderr
        )

        print(
            "[sandbox] Starting isolated MCP container...",
            file=sys.stderr
        )

        self.container = self.client.containers.run(

            # Lightweight container image
            image=IMAGE,

            # MCP filesystem server
            command=MCP_SERVER,

            # MCP uses stdin/stdout
            stdin_open=True,
            tty=False,

            # Delete container when it stops
            auto_remove=True,

            # ------------------------------------------
            # Filesystem isolation
            # ------------------------------------------

            volumes={
                str(self.workspace): {
                    "bind": "/workspace",
                    "mode": "rw",
                }
            },

            # Don't allow access to host networking
            network_disabled=True,

            # Root filesystem cannot be modified
            read_only=True,

            # ------------------------------------------
            # Privilege isolation
            # ------------------------------------------

            cap_drop=["ALL"],

            security_opt=[
                "no-new-privileges:true"
            ],

            # ------------------------------------------
            # Resource limits
            # ------------------------------------------

            mem_limit="512m",
            nano_cpus=1_000_000_000,

            # Temporary writable directory
            tmpfs={
                "/tmp": "rw,noexec,nosuid,size=64m"
            },

            # Run as non-root user
            user="node",

            detach=True,
        )

        print(
            f"[sandbox] Container: {self.container.short_id}",
            file=sys.stderr
        )


    def stop(self):

        if self.container is None:
            return

        try:
            self.container.stop(timeout=2)

        except docker.errors.NotFound:
            pass

        finally:
            self.container = None

            print(
                "[sandbox] Container stopped.",
                file=sys.stderr
            )


    def wait(self):

        if self.container is None:
            return

        return self.container.wait()


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():

    # Directory that the MCP server is allowed to access
    workspace = Path.cwd()

    sandbox = MCPSandbox(str(workspace))

    try:

        sandbox.start()

        print(
            "[sandbox] MCP server is running inside Docker.",
            file=sys.stderr
        )

        sandbox.wait()

    except KeyboardInterrupt:

        print(
            "\n[sandbox] Shutting down...",
            file=sys.stderr
        )

    finally:

        sandbox.stop()


if __name__ == "__main__":
    main()