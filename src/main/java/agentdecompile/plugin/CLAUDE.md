# CLAUDE.md - Plugin Package

This file provides guidance for working with the AgentDecompile plugin infrastructure components in `/src/main/java/agentdecompile/plugin/`.

## Quick Reference

| Item | Value |
|------|-------|
| **Plugin Type** | Two-tier (Application + Tool) |
| **Application Plugin** | `AgentDecompileApplicationPlugin` (persists across tools) |
| **Tool Plugin** | `AgentDecompilePlugin` (per-tool lifecycle) |
| **Configuration Backend** | Ghidra ToolOptions |
| **Program Manager** | `AgentDecompileProgramManager` (centralized access) |
| **Service Interface** | `AgentDecompileMcpService` |

## Package Overview

The `agentdecompile.plugin` package contains the core Ghidra plugin infrastructure that manages the AgentDecompile extension lifecycle, configuration, and program state. This package implements a two-tier plugin architecture:

1. **Application-level plugin** (`AgentDecompileApplicationPlugin`) - Manages MCP server at Ghidra application level
2. **Tool-level plugin** (`AgentDecompilePlugin`) - Handles program lifecycle in individual analysis tools

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Ghidra Application                            │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              AgentDecompileApplicationPlugin                          ││
│  │  - ApplicationLevelOnlyPlugin                               ││
│  │  - ProjectListener                                          ││
│  │  - Manages McpServerManager lifecycle                       ││
│  │  - Provides AgentDecompileMcpService                                  ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│                    AgentDecompileMcpService                                │
│                              │                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │  CodeBrowser │  │  CodeBrowser │  │  Other Tool │              │
│  │  (Tool #1)   │  │  (Tool #2)   │  │             │              │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │              │
│  │ │AgentDecompilePlugin│ │  │ │AgentDecompilePlugin│ │  │ │AgentDecompilePlugin│ │              │
│  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│         │                │                │                      │
│         └────────────────┼────────────────┘                      │
│                          │                                       │
│                          ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                  AgentDecompileProgramManager                         ││
│  │            (Centralized program tracking)                   ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Core Classes

| Class | Type | Purpose |
|-------|------|---------|
| `AgentDecompileApplicationPlugin` | ApplicationLevelOnlyPlugin | MCP server lifecycle, persists across tools |
| `AgentDecompilePlugin` | ProgramPlugin | Per-tool program tracking, MCP service integration |
| `ConfigManager` | OptionsChangeListener | Configuration with Ghidra ToolOptions backend |
| `AgentDecompileProgramManager` | Static utility | Centralized program access across all tools |
| `AgentDecompileInternalServiceRegistry` | Static registry | Service lookup for test environments |

## Plugin Architecture

### Two-Tier Plugin Design

AgentDecompile uses Ghidra's dual plugin architecture to ensure the MCP server persists across tool sessions:

```java
// Application-level: persists across tool sessions
@PluginInfo(status = PluginStatus.RELEASED, packageName = "AgentDecompile")
public class AgentDecompileApplicationPlugin extends Plugin implements ApplicationLevelOnlyPlugin, ProjectListener

// Tool-level: connects individual tools to the application-level service
@PluginInfo(status = PluginStatus.RELEASED, packageName = "AgentDecompile")
public class AgentDecompilePlugin extends ProgramPlugin
```

### Plugin Lifecycle

| Phase | Application Plugin | Tool Plugin |
|-------|-------------------|-------------|
| **Init** | Creates McpServerManager, registers services, starts MCP server | Connects to AgentDecompileMcpService, registers with server |
| **Project Events** | Handles open/close, keeps server running | N/A |
| **Program Events** | N/A | Notifies MCP service and program manager |
| **Shutdown** | Graceful server shutdown with priority hooks | Unregisters from MCP service |

## Configuration Management

### ConfigManager - Ghidra Options Integration

`ConfigManager` provides centralized configuration using Ghidra's official `OptionsChangeListener`:

```java
public class ConfigManager implements OptionsChangeListener {
    public static final String SERVER_OPTIONS = "AgentDecompile Server Options";

    private void registerOptionsWithGhidra() {
        HelpLocation help = new HelpLocation("AgentDecompile", "Configuration");
        toolOptions.registerOption(SERVER_PORT, DEFAULT_PORT, help,
            "Port number for the AgentDecompile MCP server");
    }
}
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `SERVER_PORT` | 8080 | MCP server port number |
| `SERVER_ENABLED` | true | Whether MCP server is enabled |
| `DEBUG_MODE` | false | Enable debug logging |
| `MAX_DECOMPILER_SEARCH_FUNCTIONS` | 1000 | Function limit for search operations |
| `DECOMPILER_TIMEOUT_SECONDS` | 10 | Decompiler operation timeout |

### Configuration Change Handling

The system supports two levels of configuration change listeners:

```java
// Ghidra's official callback - called for ANY configuration change
@Override
public void optionsChanged(ToolOptions options, String optionName,
        Object oldValue, Object newValue) {
    cachedOptions.put(optionName, newValue);
    notifyConfigChangeListeners(SERVER_OPTIONS, optionName, oldValue, newValue);
}

// Custom listener interface for application-specific handling
public interface ConfigChangeListener {
    void onConfigChanged(String category, String name, Object oldValue, Object newValue);
}
```

## Program State Management

### AgentDecompileProgramManager - Program Tracking

`AgentDecompileProgramManager` provides centralized access to open programs across all Ghidra tools:

```java
public class AgentDecompileProgramManager {
    // Get all open programs from any tool
    public static List<Program> getOpenPrograms()

    // Program lifecycle management
    public static void programOpened(Program program)
    public static void programClosed(Program program)

    // Program lookup by path
    public static Program getProgramByPath(String programPath)
}
```

### Program Caching Strategy

| Tier | Source | Use Case |
|------|--------|----------|
| 1 | Registered programs | Test environments, direct registration |
| 2 | Program cache | Cached by canonical path |
| 3 | Tool manager lookup | Active programs in running tools |
| 4 | Domain file opening | Open from project files on demand |

### Program Path Resolution

Always use canonical domain paths for consistent program identification:

```java
// Get canonical path for caching
public static String getCanonicalProgramPath(Program program) {
    return program.getDomainFile().getPathname();
}

// Program lookup supports multiple path formats:
// 1. Domain path: "/Hatchery.exe" (preferred)
// 2. Executable path: "/path/to/binary"
// 3. Program name: "Hatchery.exe"
```

## Service Registration

### Service Registration Pattern

Use Ghidra's service system for loose coupling between components:

```java
// Application plugin provides services
@PluginInfo(servicesProvided = { AgentDecompileMcpService.class })
public class AgentDecompileApplicationPlugin extends Plugin {
    @Override
    protected void init() {
        registerServiceProvided(AgentDecompileMcpService.class, serverManager);
        AgentDecompileInternalServiceRegistry.registerService(McpServerManager.class, serverManager);
    }
}

// Tool plugin consumes services
public class AgentDecompilePlugin extends ProgramPlugin {
    @Override
    public void init() {
        mcpService = tool.getService(AgentDecompileMcpService.class);

        // Fallback for testing environments
        if (mcpService == null) {
            mcpService = AgentDecompileInternalServiceRegistry.getService(AgentDecompileMcpService.class);
        }
    }
}
```

### Plugin Dependencies

```java
@PluginInfo(
    servicesProvided = { AgentDecompileMcpService.class },
    servicesRequired = { FrontEndService.class }  // Required for project events
)
```

## Event Handling

### Project Events (Application Plugin)

```java
@Override
public void projectOpened(Project project) {
    this.currentProject = project;
    // MCP server continues running across projects
}

@Override
public void projectClosed(Project project) {
    // Server remains active even when projects close
}
```

### Program Events (Tool Plugin)

```java
@Override
protected void programOpened(Program program) {
    AgentDecompileProgramManager.programOpened(program);
    if (mcpService != null) {
        mcpService.programOpened(program, tool);
    }
}

@Override
protected void programClosed(Program program) {
    AgentDecompileProgramManager.programClosed(program);
    if (mcpService != null) {
        mcpService.programClosed(program, tool);
    }
}
```

## Error Handling

### Configuration Validation

Use `OptionsVetoException` to prevent invalid configuration changes:

```java
@Override
public void optionsChanged(ToolOptions options, String optionName,
        Object oldValue, Object newValue) throws OptionsVetoException {
    if (SERVER_PORT.equals(optionName) && ((Integer) newValue) < 1) {
        throw new OptionsVetoException("Server port must be positive");
    }
}
```

### Service Availability

Always check for service availability with graceful degradation:

```java
if (mcpService == null) {
    Msg.error(this, "AgentDecompileMcpService not available - AgentDecompileApplicationPlugin may not be loaded");
    return;
}

try {
    mcpService.programOpened(program, tool);
} catch (Exception e) {
    Msg.error(this, "Failed to notify MCP service of program opening", e);
    // Continue operation - don't fail the entire plugin
}
```

### Resource Cleanup

```java
@Override
protected void dispose() {
    if (toolOptions != null) {
        toolOptions.removeOptionsChangeListener(this);
    }
    AgentDecompileInternalServiceRegistry.unregisterService(AgentDecompilePlugin.class);
    if (serverManager != null) {
        serverManager.shutdown();
    }
    super.dispose();
}
```

## Testing

### Test Environment Setup

```java
// Register program directly for tests
AgentDecompileProgramManager.registerProgram(testProgram);

// Register mock services
AgentDecompileInternalServiceRegistry.registerService(AgentDecompileMcpService.class, mockMcpService);

// Cleanup after tests
AgentDecompileProgramManager.cleanup();
AgentDecompileInternalServiceRegistry.clearAllServices();
```

### Integration Test Requirements

| Requirement | Value |
|-------------|-------|
| Headless mode | `java.awt.headless=false` required |
| Fork mode | `forkEvery=1` to prevent conflicts |
| Environment | Real Ghidra environment for lifecycle events |

## Troubleshooting

### Plugin Loading Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| AgentDecompilePlugin not loading | AgentDecompileApplicationPlugin not loaded | Ensure application plugin loads first |
| Service not found | Plugin not initialized | Check plugin loading order in logs |
| NullPointerException on service | Test environment without Ghidra | Use `AgentDecompileInternalServiceRegistry` fallback |

### Configuration Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Settings not persisting | Wrong ConfigManager mode | Ensure ToolOptions backend in GUI mode |
| OptionsVetoException | Invalid configuration value | Check validation logic and constraints |
| Config changes not applied | Missing listener registration | Verify `addOptionsChangeListener()` called |

### Program Tracking Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Program not found | Not in cache or tools | Use `programPath` from list-programs output |
| Stale program reference | Program closed but cached | Check `AgentDecompileProgramManager.programClosed()` called |
| Wrong program returned | Ambiguous name matching | Use full domain path (e.g., "/folder/program.exe") |

## Common Patterns

### Configuration Access

```java
ConfigManager config = new ConfigManager(tool);
int port = config.getServerPort();
boolean enabled = config.isServerEnabled();
config.setServerPort(8081);  // Triggers change events
```

### Service Lookup

```java
// Primary: Ghidra's service system
AgentDecompileMcpService service = tool.getService(AgentDecompileMcpService.class);

// Fallback: Internal registry for testing
if (service == null) {
    service = AgentDecompileInternalServiceRegistry.getService(AgentDecompileMcpService.class);
}
```

### Program Access

```java
List<Program> programs = AgentDecompileProgramManager.getOpenPrograms();
Program program = AgentDecompileProgramManager.getProgramByPath("/Hatchery.exe");
AgentDecompileProgramManager.registerProgram(testProgram);  // For tests
```

## Critical Implementation Notes

- **Thread safety**: Use `ConcurrentHashMap.newKeySet()` for listener collections
- **Memory management**: Always remove listeners and clear caches in disposal methods
- **Error isolation**: Catch and log individual listener failures without affecting others
- **Service lifecycle**: Application plugin manages service creation, tool plugins consume services
- **Configuration persistence**: Ghidra automatically persists registered options
- **Project independence**: MCP server runs at application level, independent of specific projects

## Related Documentation

- `/src/main/java/agentdecompile/server/CLAUDE.md` - MCP server architecture, McpServerManager
- `/src/main/java/agentdecompile/services/CLAUDE.md` - AgentDecompileMcpService interface definition
- `/src/main/java/agentdecompile/util/CLAUDE.md` - ProgramLookupUtil for program resolution
- `/src/main/java/agentdecompile/tools/CLAUDE.md` - Tool provider patterns
- `/CLAUDE.md` - Project-wide build commands and configuration
