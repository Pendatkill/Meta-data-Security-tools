# Contributing to metadata-security-toolkit

Thank you for your interest in contributing. Contributions are welcome as long as they align with the educational and research purpose of this project.

---

## Ground Rules

- All contributions must comply with applicable laws and the project's [DISCLAIMER](DISCLAIMER.md).
- Do not submit code intended for malicious, illegal, or unethical use.
- Be respectful and constructive in all interactions.

---

## How to Contribute

### 1. Fork the repository

Click **Fork** on GitHub to create your own copy of the repository.

### 2. Create a feature branch

Use a descriptive branch name:

```bash
git checkout -b feature/your-feature-name
# or for bug fixes:
git checkout -b fix/short-description
```

### 3. Make your changes

- Keep commits focused and atomic (one logical change per commit).
- Add or update tests in `tests/` for any new or modified functionality.
- Run the test suite before submitting:

```bash
python -m pytest tests/ -v
```

### 4. Follow the code style

- PEP 8 — use 4-space indentation, no trailing whitespace.
- Every module/class/function should have a clear docstring.
- Include `# Developer: pendatkill` and a `# Module: ...` header comment at the top of new source files (maintaining project convention).
- Keep lines under 100 characters where possible.
- Do not introduce external dependencies without discussion — open an issue first.

### 5. Open a Pull Request

Push your branch and open a PR against `main`:

```bash
git push origin feature/your-feature-name
```

In the PR description include:
- A clear summary of what was changed and why.
- Steps to reproduce the issue fixed (for bug fixes).
- Any relevant test results or screenshots.

---

## Reporting Issues

Open a GitHub Issue with:
- A concise title.
- Steps to reproduce (for bugs).
- Expected vs. actual behaviour.
- Python version and OS.

---

## Code of Conduct

This project follows a simple standard: be respectful, be helpful, do not harass anyone. Contributions that violate these principles or the project's legal disclaimer will be rejected.
