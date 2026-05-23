# AGENTS.md - Project Guidelines for AI Assistants

This file defines rules and best practices for AI assistants interacting with this repository.
These guidelines help ensure consistency, security, and maintainability.

---

## 🚨 Critical Rules (Non-Overridable)

### Git Configuration
- **NEVER modify git configuration** – User's git config (including GPG signing) is already properly set up
- **NEVER change** `commit.gpgsign`, `user.signingkey`, or any other git settings

### Git Workflow
- **NEVER push directly to `main`** – Always create a dedicated branch and use a Pull Request
- **Always create a Pull Request** to merge into `main`
- **Wait for at least 1 approval** before merging a PR
- **Always include tests** in PRs (when applicable)
- **Always update documentation** when needed

### Branches
- **Naming**: Use the following prefixes:
  - `feat/` for new features
  - `fix/` for bug fixes
  - `chore/` for maintenance
  - `docs/` for documentation
  - `refactor/` for refactoring
- **Example**: `feat/ipv6-support`, `fix/ptr-query-bug`, `docs/update-readme`

### Commits
- **Format**: `type: message` (e.g., `feat: add IPv6 support`)
- **Valid types**: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `style`
- **Message**: Clear, concise, in English

#### GPG Signing
- **Sign commits**: Always sign commits with GPG when configured
- **On GPG failure**: If commit signing fails, retry **once automatically**
- **After retry failure**: Ask the user to touch their YubiKey (the LED will blink when waiting for touch)
- **NEVER** use `--no-gpg-sign` flag to bypass signing

### Pull Requests
- **Title**: Clear and descriptive, prefer `type: description` format
- **Description**: Always include:
  - Description of changes
  - Motivation/context
  - Verification checklist (tests, documentation, etc.)
- **Labels**: Add appropriate labels (`enhancement`, `bug`, `documentation`, etc.)

---

## ⚙️ Project Configuration

### Language
- **Go**: Minimum version (see `go.mod`)
- **Style**: Follow Go conventions (`gofmt`, `go vet`)
- **Linter**: `golangci-lint` with project configuration
- **Tests**: Use `-race` for local/CI race testing and cover edge cases
- **Race detector note**: `-race` requires CGO enabled and may not work for cross-compiles

### Build
- **Static/Release builds**: Use `CGO_ENABLED=0`
- **Optimization**: Always use `-ldflags="-s -w"`
- **Multi-architecture**: Support `amd64`, `arm64`, `armv7`

### Tools
- **CI/CD**: GitHub Actions with CI, Lint, CodeQL, Release workflows
- **Dependency management**: `go mod` for Go dependencies
- **Release**: goreleaser for builds and publications

---

## 🎯 Best Practices

### Code
- **Avoid `any`/`interface{}`** without explicit necessity
- **Always handle errors** explicitly (no `_` to ignore)
- **Avoid global variables** – prefer composition
- **Comments**: Only to explain **why**, not **how**
- **Tests**: 1 test per public function, cover edge cases
- **Documentation**: Document public functions with Go comments (`// Function does...`)

### Documentation
- **Always update README** if API or configuration changes
- **Add examples** in documentation
- **Keep comments up to date** with code

### Security
- **Never commit secrets** (tokens, passwords, API keys, etc.)
- **Always use HTTPS** for API calls (unless explicit `insecure_http` config)
- **Validate user input** (e.g., CIDR, ports, etc.)
- **Minimum permissions**: Grant only necessary permissions

---

## 📝 Useful Commands

### Create a new branch
```bash
git checkout -b feat/my-new-feature
```

### Create a Pull Request
```bash
# After pushing the branch
gh pr create --base main --head feat/my-new-feature \
  --title "feat: my new feature" \
  --body "Description of changes..." \
  --label "enhancement"
```

### Run local tests
```bash
make test      # Run tests
make build     # Build the project
make vet       # Check with go vet
make race      # Run tests with race detector
```

### Build the project
```bash
make build           # Native build
make dist            # Build for all architectures
```

---

## 🔄 Typical Workflow

1. **Update local branch**:
   ```bash
   git pull origin main
   ```

2. **Create feature branch**:
   ```bash
   git checkout -b feat/xxx
   ```

3. **Make atomic commits**:
   ```bash
   git commit -m "feat: add YYY"
   ```

4. **Push branch**:
   ```bash
   git push origin feat/xxx
   ```

5. **Create Pull Request** on GitHub

6. **Wait for CI/Lint/CodeQL** (all must pass)

7. **Wait for review** (at least 1 approval)

8. **Merge PR**

---

## 🛑 Forbidden Actions

- ❌ `git push origin main` – Always use a branch + PR
- ❌ `git commit --amend` on already pushed commits (except to fix local commit)
- ❌ `git rebase` on shared branches
- ❌ Push secrets to the repo
- ❌ Merge PR without tests (when applicable)
- ❌ Merge PR with CI failures
- ❌ Ignore review comments without response

---

## 💡 Tips

- **Use `gh` CLI** to manage PRs:
  ```bash
  gh pr status         # Check PR status
  gh pr checkout 123   # Switch to a PR
  gh pr view 123       # View PR details
  ```

- **Check CI before push**:
  ```bash
  # Run the repository's existing local validation commands before pushing
  # (for example: the documented test, lint, or build commands that are actually defined)
  ```

- **Keep commits atomic**: 1 logical change = 1 commit
- **Write clear commit messages**: Explain the **why**, not the **what**

---

## 📚 Resources

- **Go Documentation**: https://golang.org/doc
- **Freebox API**: https://dev.freebox.fr/sdk/os/
- **Pi-hole Documentation**: https://docs.pi-hole.net/
- **GitHub CLI**: https://cli.github.com/
