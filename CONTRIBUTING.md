# Contributing to CyberGuard AI

Thank you for your interest in contributing to CyberGuard AI! We welcome contributions from security researchers, developers, and anyone who wants to help make on-device AI threat detection better and more accessible.

Please read this guide before opening issues or submitting pull requests.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Commit Message Format](#commit-message-format)
- [Code Review Standards](#code-review-standards)

---

## Code of Conduct

This project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its standards. Please report unacceptable behavior to conduct@cyberguard.ai.

---

## Ways to Contribute

| Type | Description |
|---|---|
| 🐛 **Bug Reports** | Found something broken? Open a detailed issue |
| ✨ **Features** | Have an idea? Start with a feature request issue |
| 📝 **Documentation** | Improve clarity, fix typos, add examples |
| 🧪 **Tests** | Add missing test cases or improve coverage |
| 🔍 **Security Research** | See [SECURITY.md](SECURITY.md) for responsible disclosure |
| 🌍 **Translations** | Help translate documentation |
| 🎯 **AI Model** | Contribute training data or model improvements (see below) |

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/cyberguard-ai.git
   cd cyberguard-ai
   ```
3. **Set up** the development environment by following the [Developer Guide](docs/DEVELOPER_GUIDE.md)
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/bug-description
   ```
5. Make your changes, write tests, update docs
6. Submit a **Pull Request** to the `develop` branch

---

## Development Workflow

### Before Writing Code

- **Search existing issues** to avoid duplicates
- **For large changes**, open a GitHub Discussion or issue first to align on approach before writing code
- **For security-sensitive changes** (auth, kill logic, audit log), discuss in a private issue first

### During Development

Follow the standards in the [Developer Guide](docs/DEVELOPER_GUIDE.md):

```bash
# After making changes, verify everything passes
./scripts/ci-check.sh

# This runs:
# - Code formatting (black, ruff, prettier)
# - Type checking (mypy, tsc)
# - Unit tests
# - Lint checks
```

### Testing Requirements

| Change Type | Minimum Test Requirement |
|---|---|
| New feature | Unit tests + integration test for the happy path |
| Bug fix | Regression test that reproduces the bug |
| AI model change | Model validation showing TPR ≥ 90%, FPR ≤ 5% |
| Security-sensitive code | Two code reviewers required |

---

## Pull Request Guidelines

### PR Requirements (All)

- [ ] Branch is from `develop` (not `main`)
- [ ] All CI checks pass (no red X on GitHub)
- [ ] Code coverage does not decrease
- [ ] All new public functions have docstrings/JSDoc
- [ ] Relevant docs updated (README, API docs, etc. if affected)
- [ ] PR description explains **what** and **why** (not just what the code does)

### PR Requirements (Security-Sensitive Changes)

- [ ] Two approving reviews from core team members
- [ ] Security implications documented in PR description
- [ ] No new untested code paths in kill executor, auth, or audit log

### PR Size Guidelines

- **Small:** < 200 lines changed — fast to review, preferred
- **Medium:** 200–500 lines — acceptable with clear description
- **Large:** > 500 lines — split into smaller PRs if possible

### Draft PRs

Use a **Draft PR** when:
- You want early feedback before a feature is complete
- You're working on something complex and want to share progress

---

## Reporting Bugs

### Before Reporting

1. Check [existing issues](https://github.com/your-org/cyberguard-ai/issues)
2. Try to reproduce with the latest `main` branch
3. Check the [Troubleshooting section](docs/DEPLOYMENT_GUIDE.md#11-troubleshooting) in the Deployment Guide

### Bug Report Template

When opening a bug issue, include:

```
**Environment:**
- CyberGuard AI version: x.x.x
- OS (agent machine): Ubuntu 22.04 / Windows Server 2019 / etc.
- OS (API server): ...
- Agent count: ...

**Expected Behavior:**
What should have happened?

**Actual Behavior:**
What actually happened?

**Steps to Reproduce:**
1. ...
2. ...
3. ...

**Logs:**
Paste relevant log excerpts from:
- Agent log: /var/log/cyberguard-agent.log
- API server log (docker compose logs api)

**Additional Context:**
Screenshots, network diagrams, etc.
```

---

## Requesting Features

1. Check the [Roadmap](ROADMAP.md) to see if it's already planned
2. Open a **Feature Request** issue with:
   - **Problem statement:** What problem does this solve?
   - **Proposed solution:** What should the feature do?
   - **Alternatives considered:** Any other approaches?
   - **Priority / impact:** Who benefits and how much?

For large features, consider opening a GitHub Discussion first.

---

## Security Vulnerabilities

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please report security issues privately. See [SECURITY.md](SECURITY.md) for the full responsible disclosure process.

---

## Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body — explain why, not what]

[optional footer — issue references, breaking changes]
```

**Types:**
- `feat` — New feature
- `fix` — Bug fix
- `docs` — Documentation only
- `test` — Adding or updating tests
- `refactor` — Code change that doesn't add a feature or fix a bug
- `perf` — Performance improvement
- `chore` — Build process, dependency updates, config changes

**Scopes:** `agent`, `api`, `dashboard`, `ai-model`, `auth`, `kill`, `network`, `audit`, `docs`

**Examples:**
```bash
feat(agent): add DNS tunneling detection heuristic
fix(api): return 409 when kill is attempted on PID 1
docs(contributing): add AI model contribution guidelines
test(agent): add unit tests for heuristic CPU threshold rule
perf(agent): batch process inference to reduce AI latency by 30%
```

---

## Code Review Standards

### As an Author

- Respond to all review comments within 2 business days
- Mark resolved comments as resolved
- Don't close a PR without addressing or explaining why you disagree with a comment

### As a Reviewer

- Complete reviews within 2 business days
- Be specific — "this might have performance issues" is less useful than "this O(n²) loop will slow down when there are 500+ processes"
- Distinguish between: blocking issues (must fix), suggestions (optional), questions (just curious)
- Use the GitHub suggestion feature for simple fixes

---

## Contributing AI Model Improvements

We accept contributions to the AI threat detection model:

- **Training data:** Clean process behavioral datasets or (anonymized) malware behavioral data
- **Feature engineering:** New process telemetry features that improve classification
- **Model architecture:** Experiments with different model types (XGBoost, Random Forest, etc.)
- **Evaluation:** Better evaluation methodologies or test datasets

For model contributions:
1. Open a GitHub Discussion describing your contribution
2. Share evaluation results demonstrating improvement
3. Ensure no real malware samples are included in contributions (use behavioral features only)
4. Include model validation results in your PR

---

## License

By contributing to CyberGuard AI, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

---

*Thank you for making CyberGuard AI better for everyone.* 🛡️
