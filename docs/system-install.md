# Install MOP

## Install the monitor

With [uv](https://docs.astral.sh/uv/getting-started/installation/) installed:

```bash
uv tool install "git+https://github.com/mode-io/mop.git"
mop
```

This installs `mop`, `hmop` and `bmop` in an isolated Python environment. Use your GitHub Git credentials while the repository is private. If needed, run `uv tool update-shell` once and reopen the terminal.

Update a tool installation with `uv tool upgrade modeio-mop`; remove it with `uv tool uninstall modeio-mop`.

## Full capture

The full setup targets Ubuntu 22.04+ / Debian, x86-64, Python 3.10+, systemd and a kernel with BTF. Run it as your normal user; it asks for sudo when installing system components.

```bash
git clone https://github.com/mode-io/mop.git
cd all-in-one-modeio
bash scripts/setup.sh
mop
```

Setup installs Python dependencies, background capture tools and the protocol proxy, then checks stdout and HTTPS capture. It preserves your configuration and reuses existing services. Tetragon adds [kernel events](tetragon.md) when installed.

Commands are available through `~/.local/bin`. If that directory is outside PATH, full setup adds links in `/usr/local/bin` when available. Existing unrelated commands are preserved. Setup prints the exact command to launch on your machine.

## Connect the guard

MOP uses a running vLLM-Jev service. The default is `http://127.0.0.1:18936`.

For a service on another machine:

```bash
bash scripts/setup.sh --model-url http://YOUR_SERVER:18936
mop check
```

This saves the endpoint in `config/mop.json`. Captured evidence goes to that service for review. For your own local model, see [model setup](jev-2b-batching.md). Setup installs MOP; model weights and the GPU runtime are provisioned separately.

## Use every day

```bash
mop                         # top-style view
hmop                        # htop-style view
bmop                        # btop-style view
mop-network status          # capture and service status
```

No `cd` or environment activation is needed. Background collectors gather activity; opening MOP starts AI review.

## Update a full installation

```bash
git pull
bash scripts/setup.sh
```

## Other setups

| Command | Use it for |
| --- | --- |
| `bash scripts/setup.sh --check` | Check installation and local model status |
| `bash scripts/setup.sh --core-only` | Install the monitor without sudo or system collectors |
| `bash scripts/setup.sh --offline` | Install from cached packages and archives |
| `bash scripts/setup.sh --rollback` | Undo tracked content-collector and eCapture changes from the last installation |

A core-only install prints an absolute launch path if `~/.local/bin` is outside PATH. Python environment support must already be installed for this mode.

Setup details are saved in `.runtime/installation/report.json`; Python installation errors are in `.runtime/installation/core.log`.

[What MOP captures](network-coverage.md) · [Collector reference](capture-reference.md)
