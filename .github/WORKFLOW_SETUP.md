# GitHub Actions CI Workflows

This document explains the CI/CD workflows for the AgentDecompile project.

## Workflow Files

The workflows are defined in `.github/workflows/`:
- `test-ghidra.yml` - Extension build validation (Gradle)
- `test-headless.yml` - Headless MCP server tests (PyGhidra + Python)
- `publish-ghidra.yml` - Release publishing
- `publish-pypi.yml` - PyPI package publishing
- `docker-push.yml` - Docker image building

## Main Workflow: `test-ghidra.yml`

**Purpose**: Build the AgentDecompile extension across supported Ghidra versions.

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches

**What it does**:
- Sets up Java 21 and Ghidra
- Builds the extension using `gradle buildExtension`
- Uploads extension build artifacts

**Matrix**:
- OS: ubuntu-latest
- Ghidra: 12.0, latest

**Total jobs**: 2 (matrix by Ghidra version)

## Headless Workflow: `test-headless.yml`

**Purpose**: Test AgentDecompile MCP server in headless mode with PyGhidra.

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches
- Manual workflow dispatch (Actions tab → "Run workflow")

**What it does**:
- Sets up Java 21 (required for PyGhidra)
- Installs Ghidra
- Builds the extension with Gradle
- Sets up Python 3.10 and `uv`
- Installs PyGhidra from the local Ghidra installation
- Runs Python tests with `uv run pytest tests/`

**Matrix**:
- OS: [ubuntu-latest, macos-latest]
- Ghidra: [12.0, latest]

**Total jobs**: 4

## Release Publishing Workflow (`publish-ghidra.yml`)

Builds and publishes release artifacts.

**Triggers**:
- Manual workflow dispatch
- Release tags
## Running Tests Locally

Before pushing, test locally:

**Build extension (Gradle)**:
```bash
gradle clean buildExtension
gradle buildExtension
```

**Test headless server (Python/PyGhidra)**:
```bash
# Requires: GHIDRA_INSTALL_DIR set, Ghidra 12.0+
uv sync
uv run pytest tests/ -v
```

## Monitoring Workflows

1. Go to Actions tab in GitHub
2. Select a workflow name
3. View recent runs
4. Click on a run to see detailed logs

## Troubleshooting

### Workflow doesn't trigger

Check:
- Branch matches (main or develop)
- Workflow file is valid YAML
- GitHub Actions is enabled for the repository

### Tests fail in CI but pass locally

Common causes:
- Environment differences (Ghidra version, Java version, Python version)
- Missing dependencies (GHIDRA_INSTALL_DIR not set)
- Timeout too short (extension builds can take 10+ minutes)

### Build fails in CI

- Check Gradle logs for extension packaging errors
- Ensure Ghidra version matches (12.0+)
- Verify Java 21 is available

## CI Best Practices

1. **Run tests locally first** - both extension builds and headless tests
2. **Maintain backwards compatibility** - changes should work with Ghidra 12.0 and latest
3. **Keep extension builds fast** - avoid slow/large dependencies
4. **Add markers to Python tests** - `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.slow`, etc.
5. **Handle Ghidra API changes carefully** - maintain compatibility across versions
6. **Check CI status** before requesting review

## Build Environment

AgentDecompile is a hybrid Java/Python project:

- **Ghidra Extension Packaging**: Gradle-built, requires Java 21, Ghidra 12.0+
- **Python MCP Server**: Requires Python 3.10+, PyGhidra (depends on Ghidra installation)
- **CI Testing**: Headless functional tests run in `test-headless.yml`; `test-ghidra.yml` validates extension builds

## References

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Gradle Documentation](https://gradle.org/)
- [Ghidra Documentation](https://ghidra-sre.org/)
- [PyGhidra Documentation](https://github.com/dod-cyber-crime-center/pyghidra)
