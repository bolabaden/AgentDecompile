# GitHub Actions CI Workflows

This document describes the CI/CD workflows for AgentDecompile.

## Workflows Overview

### 1. `test-ghidra.yml` - Extension Build Validation (Gradle)

**Triggers**: Push/PR to main or develop branches

**What it does**:
- Builds AgentDecompile extension using Gradle
- Tests on multiple Ghidra versions (12.0, latest)
- Uploads extension build artifacts

**Jobs**:
- `test` - Builds extension (`gradle buildExtension`) on 2 Ghidra versions and uploads artifacts

**Duration**: ~5-10 minutes per matrix job

**Environment**:
- Java: 21 (Microsoft OpenJDK)
- Gradle: 8.14
- OS: Ubuntu only
- Xvfb: For headless testing UI components

### 2. `test-headless.yml` - Headless Mode Tests (Python/PyGhidra)

**Triggers**:
- Push/PR to main or develop
- Manual workflow dispatch

**What it does**:
- Builds AgentDecompile extension with Gradle (required for PyGhidra)
- Tests Python-based headless server via pytest
- Tests on multiple OS (Ubuntu, macOS)
- Tests on multiple Ghidra versions (12.0, latest)
- Uses Python 3.10

**Jobs**:
- `test-headless` - Matrix testing on Ubuntu/macOS × Ghidra versions

**Required Steps**:
1. Checkout code with LFS
2. Setup Java 21
3. Setup Python 3.10
4. Install Ghidra
5. Setup Gradle 8.14
6. Build extension (gradle clean buildExtension)
7. Install extension to Ghidra
8. Install uv package manager
9. Install Python dependencies (uv sync)
10. Install PyGhidra from local Ghidra installation
11. Run pytest (uv run pytest tests/ --timeout=180)

**Duration**: ~8-12 minutes per matrix job

**Environment**:
- Java: 21 (required for PyGhidra JVM)
- Python: 3.10
- Gradle: 8.14
- uv: Latest (from astral-sh/setup-uv)
- Timeout: 30 minutes per job

### 3. `publish-ghidra.yml` - Release Publishing

**Triggers**: Manual or release tags

**What it does**:
- Publishes release artifacts
- Creates GitHub releases
- Uploads extension zip files

**Duration**: ~5 minutes

### 4. `publish-pypi.yml` - PyPI Publishing

**Triggers**: Manual or releases

**What it does**:
- Builds Python package distribution
- Publishes to PyPI
- Uses Python 3.12

**Duration**: ~3-5 minutes

### 5. `docker-push.yml` - Docker Image Publishing

**Triggers**: Manual or tag pushes

**What it does**:
- Builds Docker images
- Pushes to container registry

**Duration**: ~10-15 minutes

### 6. `claude.yml` - Claude-Specific Integration

**Triggers**: Project-specific

**What it does**:
- Claude Code integration or automation
- Purpose varies by configuration

## Test Matrix Strategy

### Extension Tests (`test-ghidra.yml`)

```
Matrix:
  OS: [ubuntu-latest]
  Ghidra: [12.0, latest]

Total: 2 jobs
```

### Headless Mode Tests (`test-headless.yml`)

```
Matrix:
  OS: [ubuntu-latest, macos-latest]
  Ghidra: [12.0, latest]

Total: 4 jobs (2 OS × 2 Ghidra versions)
```

## Key Dependencies

### Gradle Build Chain
- Both workflows build the extension using Gradle
- Java 21 is required (Microsoft OpenJDK)
- Gradle 8.14
- Xvfb required on Ubuntu for UI-dependent extension operations

### Python Tests
- Python 3.10 is tested
- PyGhidra installed from local Ghidra installation
- uv package manager for dependency management
- pytest for test execution

## Workflow Optimization

### Parallelization

All matrix jobs run in parallel, significantly reducing total CI wall-clock time:
- test-ghidra.yml: 2 parallel jobs
- test-headless.yml: 4 parallel jobs

### Fail-Fast: Disabled

Both test workflows use `fail-fast: false` to ensure all matrix jobs complete regardless of failures. This provides complete visibility into which configurations pass/fail.

## Running Workflows Locally

### Extension Build Validation

```bash
# Build extension
gradle buildExtension
```

### Python/Headless Tests

```bash
# Install dependencies
uv sync

# Setup Ghidra (if GHIDRA_INSTALL_DIR not set)
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# Install extension to local Ghidra
unzip dist/*.zip -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/"

# Install PyGhidra
uv pip install "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg"

# Run tests
uv run pytest tests/ -v --timeout=180
```

## Manual Workflow Triggers

### Trigger headless tests from GitHub UI

1. Go to **Actions** tab
2. Select **Test Headless Mode 🤖** workflow
3. Click **Run workflow**
4. Select branch
5. Click green **Run workflow** button

This is useful for:
- Testing on feature branches
- Debugging CI issues
- Manual validation without pushing

## Debugging Failed Tests

### View Test Results

1. Click on failed workflow run
2. Click on failed job
3. Expand failing step to see full logs
4. Use Test Summary to identify failed tests

### Download Artifacts

Failed test runs upload:
- JUnit XML results
- Logs
- Pytest cache
- Test reports

Download via workflow run page → Artifacts section

### Common Issues

**Issue: Gradle build fails**
```
Error: Could not find or load main class org.gradle.wrapper.GradleWrapperMain
```
**Solution**: Ensure gradle wrapper is properly initialized or use gradle/actions/setup-gradle

**Issue: PyGhidra import fails**
```
ImportError: No module named 'pyghidra'
```
**Solution**: Verify PyGhidra installation step completed and Ghidra installation directory is accessible

**Issue: Ghidra not found**
```
Error: GHIDRA_INSTALL_DIR not set or not found
```
**Solution**: Verify setup-ghidra action completed successfully; check logs

**Issue: Tests timeout**
```
Error: Test script timed out after 30 minutes
```
**Solution**: Increase timeout value or profile slow tests locally

**Issue: Xvfb display issues (Linux)**
```
Error: Cannot connect to X display
```
**Solution**: Ensure Xvfb is installed and DISPLAY environment variable is set

## Performance Benchmarks

### Expected Durations

| Workflow | Jobs | Avg Time/Job | Total Time (parallel) |
|----------|------|--------------|----------------------|
| test-ghidra.yml | 2 | ~8 min | ~10 min |
| test-headless.yml | 4 | ~10 min | ~12 min |
| publish-ghidra.yml | 1 | ~5 min | ~5 min |
| publish-pypi.yml | 1 | ~4 min | ~4 min |

Matrix parallelization means all matrix jobs run simultaneously, so total time is ~max(job times) rather than sum.

## CI/CD Best Practices

### For Contributors

1. **Run tests locally before pushing**

  For extension build validation:
   ```bash
   gradle buildExtension
   ```

   For Python/Headless:
   ```bash
   uv sync
   uv run pytest tests/ -v
   ```

2. **Use draft PRs for work-in-progress** to avoid unnecessary CI runs

3. **Check CI status before requesting review**

4. **Add tests for new features** - both unit tests (matched to test type) and integration tests

### For Maintainers

1. **Review all CI results** before merging PRs

2. **Monitor workflow performance** and matrix configuration

3. **Update workflows when**:
   - New Ghidra version released
   - New Python version support needed
   - Dependencies updated
   - Build/test infrastructure changes

4. **Keep this documentation updated** when changing workflows

## Troubleshooting CI

### Workflow doesn't trigger

**Check**:
- Branch name matches trigger pattern (main, develop)
- File changes match any path filters
- Workflow file syntax is valid YAML

### Tests pass locally but fail in CI

**Common causes**:
- Environment differences (OS, versions, paths)
- Missing dependencies in CI workflow
- Timeout too short
- Race conditions in parallel tests

**Debug steps**:
1. Compare workflow environment with local setup
2. Check Ghidra/Java/Python versions match
3. Add logging/debugging to test code
4. Increase timeout values if needed
5. Use GitHub workflow dispatch to test specific branches

### Very long CI times

**Optimization**:
1. Reduce matrix size if not needed
2. Use caching for gradle/pip dependencies
3. Combine related steps
4. Profile slow tests and optimize

## Monitoring

### Workflow Status Badge

Add to README:
```markdown
![Test Ghidra Extension](https://github.com/bolabaden/agentdecompile/actions/workflows/test-ghidra.yml/badge.svg)
![Test Headless Mode](https://github.com/bolabaden/agentdecompile/actions/workflows/test-headless.yml/badge.svg)
```

### GitHub Notifications

GitHub sends notifications on:
- Workflow failures (to committer)
- Status changes (if repo is watched)

Configure in GitHub → Settings → Notifications

## References

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [setup-ghidra Action](https://github.com/antoniovazquezblanco/setup-ghidra)
- [Gradle Actions](https://github.com/gradle/actions)
- [PyGhidra Documentation](https://github.com/dod-cyber-crime-center/pyghidra)
- [uv Package Manager](https://docs.astral.sh/uv/)
