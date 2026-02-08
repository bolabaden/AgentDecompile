# Ghidra API: Using / Logging into a Shared Project

This document summarizes how to connect to and open a **shared project** (Ghidra Server repository) via the Ghidra API, using the same docs referenced across `src/main/java/agentdecompile/**/*.java` and research from Context7, Tavily, and Firecrawl.

---

## Overview

- **Local projects**: Opened with `GhidraProject.openProject(projectDir, projectName, enableUpgrade)` — path and name only (what `ProjectUtil` does today).
- **Shared projects**: Live on a Ghidra Server. You must **connect to the server with credentials**, then **resolve the project via a Ghidra URL or repository handle**, and open it through the project manager. The batch-oriented `GhidraProject` class does **not** expose an overload that takes a server URL; shared-project flow uses the client/repository APIs and (for URL-based open) the Ghidra URL protocol.

---

## Environment variable configuration (AgentDecompile)

AgentDecompile configures shared-project authentication **automatically from environment variables** so that opening a shared project (e.g. a local `.gpr` that points to a Ghidra Server) works in headless/CLI mode without prompts.

| Variable | Purpose |
|----------|---------|
| `AGENT_DECOMPILE_PROJECT_PATH` | Path to a Ghidra project file (`.gpr`). For shared projects, use a local `.gpr` that references the server. |
| `AGENT_DECOMPILE_SERVER_USERNAME` | Username for Ghidra Server (password authentication). |
| `AGENT_DECOMPILE_SERVER_PASSWORD` | Password for Ghidra Server (password authentication). |
| `AGENT_DECOMPILE_SERVER_HOST` | Server host (for reference / future URL-based open). |
| `AGENT_DECOMPILE_SERVER_PORT` | Server port (default 13100 if unset). |
| `AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY` | Repository name on the server. |
| `AGENT_DECOMPILE_GHIDRA_SERVER_KEYSTORE_PATH` | PKI/SSH keystore path (alternative to username/password). |
| `AGENT_DECOMPILE_GHIDRA_SERVER_ALLOW_PASSWORD_PROMPT` | Set to `true` or `1` to allow console password prompts when using keystore. |
| `AGENT_DECOMPILE_FORCE_IGNORE_LOCK` | Set to `true` to force-ignore project lock files (risky). |

**Note:** All env vars use the `AGENT_DECOMPILE_` prefix (with underscore).

Authentication is applied **at headless startup** and again when using the project **open** tool, so that opening a shared project (local `.gpr` that connects to the server) succeeds without a GUI login.

Example MCP server configuration (e.g. in Cursor / Claude Code):

```json
{
  "mcpServers": {
    "reva": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/bolabaden/agentdecompile", "mcp-agentdecompile"],
      "env": {
        "AGENT_DECOMPILE_PROJECT_PATH": "C:/Users/you/AndastraGhidraProject.gpr",
        "GHIDRA_INSTALL_DIR": "C:/path/to/ghidra",
        "AGENT_DECOMPILE_SERVER_USERNAME": "your_username",
        "AGENT_DECOMPILE_SERVER_PASSWORD": "your_password",
        "AGENT_DECOMPILE_SERVER_HOST": "ghidra.example.com",
        "AGENT_DECOMPILE_SERVER_PORT": "13100",
        "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY": "MyRepo"
      }
    }
  }
}
```

For shared projects, use a **local project file** (`.gpr`) that was created by Ghidra when connecting to the server (e.g. “Open shared project” once in the GUI, then use that project path). The env vars above provide the credentials so that opening that project in headless mode works without a login dialog.

---

## 1. Connect to the Ghidra Repository Server

**API:** `ghidra.framework.client.ClientUtil`  
**Docs:** [ClientUtil](https://ghidra.re/ghidra_docs/api/ghidra/framework/client/ClientUtil.html)

```java
import ghidra.framework.client.ClientUtil;

// Connect; may prompt for password (Swing) if no headless authenticator is set
RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port);
// port: 0 = use default Ghidra Server port

// Force reconnect if previously disconnected
RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port, true);
```

Alternatively, via **ProjectManager** (e.g. `DefaultProjectManager` from `GhidraProject.getProjectManager()`):

```java
RepositoryServerAdapter server = projectManager.getRepositoryServerAdapter(host, portNumber, forceConnect);
```

- Returns a **handle to the remote server** (list of shared repositories).
- If the server requires authentication and no headless authenticator is installed, the default behavior is to show a **Swing login dialog**. For headless/CLI you must set credentials first (see below).

---

## 2. Setting Credentials (Login) for Headless / API Use

For environments without a GUI (e.g. headless analyzer, scripts, or AgentDecompile CLI), you must install an authenticator or set credentials **before** connecting so that the server connection can succeed without a dialog.

### Option A: Headless client authenticator (PKI/SSH or password prompt)

**API:** `ghidra.framework.client.HeadlessClientAuthenticator`  
**Docs:** [HeadlessClientAuthenticator](https://ghidra.re/ghidra_docs/api/ghidra/framework/client/HeadlessClientAuthenticator.html)

```java
import ghidra.framework.client.HeadlessClientAuthenticator;

// Install before any server connection (e.g. at startup)
HeadlessClientAuthenticator.installHeadlessClientAuthenticator(
    username,        // optional; null = use ClientUtil.getUserName()
    keystorePath,    // PKI/SSH keystore path, or resource path for SSH key
    allowPasswordPrompt  // if true, may prompt for passwords via console (echoed!)
);
```

- Used when “http/https connections require authentication” and no user info is provided.
- Supports **PKI/SSH** (keystore) and **password callbacks** (console prompt; Java console may echo input).
- Call **once** before calling `ClientUtil.getRepositoryServer(...)` or opening any shared project.

### Option B: GhidraScript – fixed username/password

**API:** `ghidra.app.script.GhidraScript`  
**Docs:** [GhidraScript](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html)

```java
// In a Ghidra script; primarily for headless
setServerCredentials(username, password);
// Returns true if active project is private or shared project is connected to its server repo
```

- Establishes **fixed** login credentials for the Ghidra Server.
- Username can be null to use default.

### Option C: Headless analyzer options (PKI/SSH)

**API:** `ghidra.app.util.headless.HeadlessOptions`  
**Docs:** [HeadlessOptions](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessOptions.html)

```java
headlessOptions.setClientCredentials(userID, keystorePath, allowPasswordPrompt);
// Throws IOException if keystore cannot be opened
```

- Used by the headless analyzer for **Ghidra Server client credentials** (PKI/SSH, optional password prompt).

---

## 3. Get a Repository (Shared Project Container)

A **repository** on the server is the container for one or more projects/content. You need a `RepositoryAdapter` for that repository.

**From batch-style helper:**

**API:** `ghidra.base.project.GhidraProject`  
**Docs:** [GhidraProject](https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html)

```java
import ghidra.base.project.GhidraProject;

RepositoryAdapter repo = GhidraProject.getServerRepository(
    host,
    port,           // 0 = default
    repositoryName,
    createIfNeeded  // true to create repository if it doesn't exist
);
```

**From server adapter:**

**API:** `ghidra.framework.client.RepositoryServerAdapter`  
**Docs:** [RepositoryServerAdapter](https://ghidra.re/ghidra_docs/api/ghidra/framework/client/RepositoryServerAdapter.html)

```java
RepositoryAdapter repo = server.getRepository(repositoryName);
// Returns null if not found; adapter may be disconnected until connect() or use
```

- Use the same **host/port** (and credentials) as in step 1 when using `GhidraProject.getServerRepository`.

---

## 4. Ghidra URL for Shared Content (Server Project Path)

**API:** `ghidra.framework.protocol.ghidra.GhidraURL`  
**Docs:** (Ghidra API – GhidraURL)

```java
URL url = GhidraURL.makeURL(host, port, repositoryName, repositoryPath);
// repositoryPath: absolute path within repository; folders should end with '/'
```

- Use this URL when the framework expects a **ghidra://** URL for a server project (e.g. open by URL, or when producing links to shared project content).
- `ProjectLocator.isTransient()` returns true for locators that “correspond to a transient project (e.g., corresponds to remote Ghidra URL)”.

---

## 5. Opening a Project (Local vs Shared)

**Local project (current AgentDecompile pattern):**

- `GhidraProject.openProject(projectLocationPath, projectName, enableUpgrade)`  
- Or `ProjectManager.openProject(projectLocator, doRestore, resetOwner)` with a **local** `ProjectLocator(path, name)`.

**Shared project:**

- The **GUI** typically opens shared projects via a **ghidra://** URL. The protocol connector (`GhidraProtocolConnector` / `DefaultLocalGhidraProtocolConnector` and server variants) handles **connect(readOnlyAccess)** and resolves to the underlying project/repository.
- **Programmatic** opening with the **ProjectManager** still uses `openProject(ProjectLocator, doRestore, resetOwner)`. For shared projects, the `ProjectLocator` is expected to carry the **URL** (protected constructor `ProjectLocator(path, name, URL)`); the actual locator is often produced by the **Ghidra URL connector** after a successful `connect()`, rather than by constructing a `ProjectLocator` directly in application code.
- **Creating** a new **shared** project:  
  `ProjectManager.createProject(projectLocator, repAdapter, remember)` with a non-null **RepositoryAdapter** (`repAdapter`).

So in practice: **set credentials → connect to server → get repository (and/or build Ghidra URL) → use framework’s URL/project open path** so that the correct `ProjectLocator` (with URL for shared) is produced and passed to `openProject`.

---

## 6. ProjectLocator and “Transient” (Remote) Projects

**API:** `ghidra.framework.model.ProjectLocator`  
**Docs:** [ProjectLocator](https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html)

- **Local:** `new ProjectLocator(path, name)` — path = directory, name = project name.
- **Shared:** There is a **protected** constructor `ProjectLocator(String path, String name, URL url)`. For remote projects, `isTransient()` returns true and the URL is used (e.g. for “transient project” corresponding to a remote Ghidra URL). Application code usually does not construct this directly; it is produced by the Ghidra URL/protocol handling.

---

## 7. Error Handling (aligned with ProjectUtil)

Your existing `ProjectUtil` already maps **authentication-style** failures when opening a project to a clear message:

- `NotOwnerException`, `NotFoundException`, `IOException` with message containing "authentication", "password", "login", "unauthorized", "Access denied", "Invalid credentials" → wrap in a single “Authentication failed for shared project” message and suggest verifying username/password.

So when you add shared-project support, reusing that pattern for any `openProject` or `connect()` path will keep behavior consistent.

---

## 8. Summary Checklist for “Login and Use Shared Project” via API

1. **Set credentials** (before any connection):
   - **Headless:** `HeadlessClientAuthenticator.installHeadlessClientAuthenticator(username, keystorePath, allowPasswordPrompt)` and/or script `setServerCredentials(username, password)` if applicable.
   - **Headless analyzer:** `HeadlessOptions.setClientCredentials(...)`.
2. **Connect to server:**  
   `ClientUtil.getRepositoryServer(host, port)` or `ProjectManager.getRepositoryServerAdapter(host, port, forceConnect)`.
3. **Get repository:**  
   `GhidraProject.getServerRepository(host, port, repositoryName, createIfNeeded)` or `serverAdapter.getRepository(repositoryName)`.
4. **Open project:**  
   Use the framework’s **Ghidra URL**–based open path (so that the correct transient `ProjectLocator` is produced) and then `ProjectManager.openProject(projectLocator, doRestore, resetOwner)`, or follow the same path the GUI uses for “Open shared project” (URL → connector → connect → open).
5. **Optional:** Build server URLs with `GhidraURL.makeURL(host, port, repositoryName, repositoryPath)` when you need to pass a ghidra:// URL.

---

## 9. References (same as in codebase)

| API | Doc link |
|-----|----------|
| GhidraProject | https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html |
| ProjectManager | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectManager.html |
| DefaultProjectManager | https://ghidra.re/ghidra_docs/api/ghidra/framework/project/DefaultProjectManager.html |
| ProjectLocator | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html |
| ClientUtil | https://ghidra.re/ghidra_docs/api/ghidra/framework/client/ClientUtil.html |
| HeadlessClientAuthenticator | https://ghidra.re/ghidra_docs/api/ghidra/framework/client/HeadlessClientAuthenticator.html |
| RepositoryServerAdapter | (Ghidra API – RepositoryServerAdapter) |
| RepositoryAdapter | (Ghidra API – RepositoryAdapter) |
| Ghidra API overview | https://ghidra.re/ghidra_docs/api/ |

---

*Researched via Context7 (Ghidra API), Tavily, and Firecrawl; aligned with the doc links used in `agentdecompile.**.java`.*
