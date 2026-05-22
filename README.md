# depwatch

> Monitors Python project dependencies for outdated or vulnerable packages and sends alerts.

---

## Installation

```bash
pip install depwatch
```

---

## Usage

Run `depwatch` against your project's `requirements.txt` to check for outdated or vulnerable packages:

```bash
depwatch scan --file requirements.txt
```

**Example output:**

```
[OUTDATED]   requests 2.26.0  →  2.31.0
[VULNERABLE] Pillow 9.0.0     →  CVE-2023-44271
[OK]         flask 2.3.2
```

You can also enable alerts via email or Slack webhook:

```bash
depwatch scan --file requirements.txt --notify slack --webhook-url https://hooks.slack.com/...
```

Schedule automatic checks using the built-in watch mode:

```bash
depwatch watch --file requirements.txt --interval 24h
```

### Options

| Flag | Description |
|------|-------------|
| `--file` | Path to requirements file |
| `--notify` | Alert method (`slack`, `email`) |
| `--interval` | Watch mode check interval (e.g. `12h`, `1d`) |
| `--ignore` | Comma-separated list of packages to skip |

---

## Contributing

Pull requests are welcome. Please open an issue first to discuss any major changes.

---

## License

This project is licensed under the [MIT License](LICENSE).