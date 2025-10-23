# Contributing to Defenra Agent

Thank you for considering contributing to Defenra Agent! This document provides guidelines for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

---

## Code of Conduct

By participating in this project, you agree to:
- Be respectful and inclusive
- Provide constructive feedback
- Focus on what is best for the community
- Show empathy towards other community members

---

## Getting Started

1. **Fork the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/defenra-agent.git
   cd defenra-agent
   ```

2. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Write code
   - Add tests
   - Update documentation

4. **Test your changes**
   ```bash
   make test
   make lint
   ```

5. **Commit and push**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   git push origin feature/your-feature-name
   ```

6. **Create Pull Request**
   - Go to GitHub
   - Click "New Pull Request"
   - Describe your changes

---

## Development Setup

### Prerequisites

- Go 1.21 or higher
- Git
- Make (optional)

### Setup

```bash
# Clone repository
git clone https://github.com/defenra/agent.git
cd agent

# Download dependencies
go mod download

# Download GeoIP database
make geoip

# Build
make build

# Run tests
make test
```

### Running Locally

```bash
# Set environment variables
export AGENT_ID=test_agent
export AGENT_KEY=test_key
export CORE_URL=http://localhost:3000

# Run
./defenra-agent
```

---

## Coding Standards

### Go Style

Follow [Effective Go](https://golang.org/doc/effective_go) and [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).

**Key points:**
- Use `gofmt` for formatting
- Use meaningful variable names
- Add comments for exported functions
- Keep functions small and focused
- Use error handling consistently

**Example:**
```go
// GetDomain retrieves domain configuration by name.
// Returns nil if domain is not found.
func (cm *ConfigManager) GetDomain(domain string) *Domain {
    cm.mu.RLock()
    defer cm.mu.RUnlock()

    for i := range cm.config.Domains {
        if cm.config.Domains[i].Domain == domain {
            return &cm.config.Domains[i]
        }
    }
    return nil
}
```

### File Organization

```
agent/
├── main.go              # Entry point
├── config/              # Configuration management
│   ├── types.go
│   └── manager.go
├── dns/                 # DNS server
│   ├── server.go
│   ├── cache.go
│   └── geoip.go
├── proxy/               # HTTP/HTTPS/TCP/UDP proxy
│   ├── http.go
│   ├── https.go
│   └── tcp.go
├── waf/                 # Lua WAF
│   └── lua.go
└── health/              # Health check
    └── server.go
```

### Testing

- Write unit tests for all new functions
- Aim for > 80% code coverage
- Use table-driven tests where appropriate

**Example:**
```go
func TestGetDomain(t *testing.T) {
    tests := []struct {
        name     string
        domain   string
        expected *Domain
    }{
        {"existing domain", "example.com", &Domain{Domain: "example.com"}},
        {"non-existing domain", "notfound.com", nil},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := configMgr.GetDomain(tt.domain)
            if result != tt.expected {
                t.Errorf("expected %v, got %v", tt.expected, result)
            }
        })
    }
}
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(dns): add support for CAA records

Implement CAA record parsing and response generation
for DNS queries.

Closes #123
```

```
fix(proxy): handle connection timeout properly

Previously, connections would hang indefinitely.
Now they timeout after 30 seconds.

Fixes #456
```

---

## Submitting Changes

### Pull Request Process

1. **Update documentation**
   - Update README.md if needed
   - Update CHANGELOG.md
   - Add/update comments

2. **Ensure tests pass**
   ```bash
   make test
   make lint
   ```

3. **Create Pull Request**
   - Use descriptive title
   - Reference related issues
   - Describe changes clearly
   - Add screenshots if applicable

4. **Code Review**
   - Address reviewer feedback
   - Make requested changes
   - Keep discussion professional

5. **Merge**
   - Maintainer will merge once approved
   - Delete branch after merge

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added where needed
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests pass locally

## Related Issues
Closes #123
```

---

## Reporting Bugs

### Before Reporting

1. **Check existing issues**
   - Search for similar issues
   - Check if already fixed in latest version

2. **Reproduce the bug**
   - Verify bug exists
   - Create minimal reproduction steps

### Bug Report Template

```markdown
## Bug Description
Clear description of the bug

## Steps to Reproduce
1. Step one
2. Step two
3. Step three

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: Ubuntu 22.04
- Go version: 1.21
- Agent version: 1.0.0

## Logs
```
Include relevant logs here
```

## Additional Context
Any other relevant information
```

---

## Feature Requests

### Before Requesting

1. **Check existing requests**
   - Search for similar requests
   - Check roadmap

2. **Consider scope**
   - Is it aligned with project goals?
   - Would it benefit most users?

### Feature Request Template

```markdown
## Feature Description
Clear description of the feature

## Use Case
Why is this feature needed?

## Proposed Solution
How should it work?

## Alternatives Considered
Other approaches you've considered

## Additional Context
Any other relevant information
```

---

## Development Guidelines

### Adding New Features

1. **Plan the feature**
   - Discuss in GitHub issue first
   - Get maintainer approval
   - Design the solution

2. **Implement the feature**
   - Write clean, maintainable code
   - Follow coding standards
   - Add appropriate tests

3. **Document the feature**
   - Update README
   - Add inline comments
   - Update CHANGELOG

### Fixing Bugs

1. **Reproduce the bug**
   - Understand the issue
   - Create test case

2. **Fix the bug**
   - Make minimal changes
   - Don't introduce new features
   - Ensure fix works

3. **Test the fix**
   - Add regression test
   - Verify no side effects
   - Test edge cases

### Performance Improvements

1. **Benchmark before and after**
   ```bash
   go test -bench=. -benchmem
   ```

2. **Profile if needed**
   ```bash
   go test -cpuprofile=cpu.prof -memprofile=mem.prof
   go tool pprof cpu.prof
   ```

3. **Document improvements**
   - Show benchmark results
   - Explain optimization

---

## Code Review Guidelines

### As Reviewer

- Be constructive and respectful
- Focus on code, not author
- Explain reasoning for feedback
- Approve when satisfied
- Request changes when needed

### As Author

- Respond to all comments
- Make requested changes
- Explain your decisions
- Be open to feedback
- Thank reviewers

---

## Release Process

(For maintainers only)

1. **Version bump**
   - Update version in code
   - Update CHANGELOG.md

2. **Create release**
   - Tag version: `git tag v1.0.0`
   - Push tag: `git push origin v1.0.0`

3. **Build binaries**
   - Build for all platforms
   - Upload to releases page

4. **Announce release**
   - Update documentation
   - Notify users

---

## Questions?

If you have questions:
- Create GitHub discussion
- Email: support@defenra.com
- Check documentation: https://docs.defenra.com

Thank you for contributing! 🎉
