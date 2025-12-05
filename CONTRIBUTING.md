# Contributing to pf-web-poly-compile-helper-runner

Thank you for your interest in contributing to this project! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to help us maintain a welcoming and inclusive community.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/pf-web-poly-compile-helper-runner.git
   cd pf-web-poly-compile-helper-runner
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/P4X-ng/pf-web-poly-compile-helper-runner.git
   ```

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- A clear and descriptive title
- Steps to reproduce the behavior
- Expected behavior vs actual behavior
- Your environment (OS, Python version, Node.js version, etc.)
- Any relevant logs or error messages

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- A clear and descriptive title
- Detailed description of the proposed enhancement
- Explanation of why this enhancement would be useful
- Examples of how it would work

### Contributing Code

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes
3. Add or update tests as needed
4. Ensure all tests pass
5. Commit your changes with a descriptive message
6. Push to your fork
7. Open a Pull Request

## Development Setup

### Prerequisites

- Linux (Ubuntu/Debian recommended) or macOS
- Python 3.10+
- Node.js 18+
- Git
- Docker or Podman (optional, for container-based development)

### Installation

```bash
# Install pf runner
sudo ./install.sh

# Or for user-level installation
./install.sh --prefix ~/.local

# Install Node.js dependencies
npm install

# Install Playwright for testing
npx playwright install
```

### Running the Development Server

```bash
pf web-dev
```

## Pull Request Process

1. **Update documentation** if your changes require it
2. **Add tests** for new functionality
3. **Ensure all tests pass**:
   ```bash
   pf web-test
   npm run test:unit
   ```
4. **Update the CHANGELOG.md** if applicable
5. **Request a review** from a maintainer
6. **Address feedback** promptly

### Commit Message Guidelines

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

## Coding Standards

### Python (pf-runner)

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write docstrings for public functions and classes

### JavaScript/TypeScript

- Use ESLint configuration (if present)
- Use meaningful variable and function names
- Write JSDoc comments for public APIs

### pf Task Files (.pf)

- Use `describe` for all tasks
- Include meaningful descriptions
- Follow the established DSL patterns

## Testing

### Running Tests

```bash
# Run all Playwright tests
pf web-test

# Run specific test file
npx playwright test tests/e2e/polyglot-plus-c.spec.ts

# Run unit tests
npm run test:unit

# Run with verbose output
npm run test:unit:verbose

# Debug tests
npx playwright test --debug
```

### Writing Tests

- Place E2E tests in `tests/e2e/`
- Place unit tests in appropriate subdirectories under `tests/`
- Use descriptive test names
- Test both success and failure cases

## Documentation

- Update README.md for significant changes
- Update QUICKSTART.md for user-facing changes
- Add to docs/ for new features or guides
- Keep documentation up-to-date with code changes

## Questions?

If you have questions, feel free to:

- Open an issue for discussion
- Check existing documentation in `pf-runner/README.md`
- Review example tasks in `Pfyfile.pf` files

Thank you for contributing! 🚀
