# Contributing Guidelines

Thank you for your interest in contributing!
This project is a **community-driven KSeF client written in Go**, and every contribution is welcome.

Please follow the guidelines below to help keep development efficient, clear, and consistent.

---

## 🚀 How You Can Contribute

You can help by:

- reporting bugs
- submitting fixes
- improving documentation
- adding tests
- proposing new features
- reviewing pull requests

If you are planning a larger change, please open an Issue first so we can discuss it.

---

## 🔀 Pull Request Guidelines

1. **Create an Issue** before starting major work.
2. Use **one PR per change** — it keeps the review simple.
3. Before submitting a PR, ensure that:
   - the code compiles
   - all tests pass:
     ```
     go test ./...
     ```
   - you have run `go vet` and `golangci-lint` (if the project uses it)
4. Clearly describe what the PR changes and why.

---

## 🧪 Tests

If you add new functionality, please include corresponding unit tests.

Run all tests with:

```
go test ./...
```

If you are unsure how to test a specific case, feel free to ask in the PR.

---

## 📦 Code Style

- Use **Go 1.25+**.
- Keep the code simple and idiomatic.
- Follow common Go conventions:
  - use lowercase for unexported symbols
  - keep functions small and readable
  - avoid unnecessary abstractions
- Add GoDoc-style comments for exported functions, structs, and interfaces.

Formatting:

```
go fmt ./...
```

Static analysis:

```
go vet ./...
```

---

## 🧰 Local Development Setup

You will need:

- Go 1.25 or newer
- Git
- Optional: access to KSeF test endpoints (for features that require integration testing)

If your changes affect communication with KSeF, please include a short explanation of what scenarios you tested.

---

## 🔐 Security

This project interacts with electronic invoicing systems.
Please follow these rules:

- **Never commit keys, credentials, tokens, NIP numbers, or any sensitive data.**
- Do not include real business documents or KSeF payloads in tests.
- Security-related discussions should be opened as Issues without sensitive details.

If necessary, maintainers may move a discussion to a private channel.

---

## 🌱 Project Status & Call for Contributors

This project is still in an early development phase.
Only a subset of KSeF endpoints is currently implemented, and **there is a lot of important work ahead**.

If you want to make a real impact on the Polish e‑invoicing ecosystem, this is a great place to contribute.

We especially welcome help in:

- implementing additional KSeF endpoints
- extending request/response models
- improving error handling and resilience
- expanding test coverage
- documenting behavior and edge cases
- reviewing and refining existing code
- proposing architectural improvements

Even small contributions move the project forward.  
If you're unsure where to start, feel free to open an Issue — we’ll happily guide new contributors.

---

## 📄 License

By submitting a contribution, you agree that your code will be licensed under the same license as the project.

---

## 🤝 Thank You

Thank you for contributing to this project.
Your help makes the world better for everyone!
