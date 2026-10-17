# gitconfig-hijack-scanner


## ⚡ GitHub Action

Run it in CI — fails the build on findings at or above your threshold:

```yaml
- uses: actions/checkout@v4
- uses: Iceman2050/gitconfig-hijack-scanner@v1
      with:
        target: '.'
        fail-on: 'CRITICAL,HIGH' # default
```

Full input reference: [`action.yml`](./action.yml).

**Your agent inherits your git config. Audit the hijack-grade keys before it does something with them.**

Git configuration is a persistence and execution vector hiding in plain sight. An October 2026 security report found **git configuration hijacking** among eight vulnerabilities across seven AI coding agents — agents that clone, init, or operate on repos inherit whatever the repo's `.git/config` (or your global config) tells them to do. `core.hooksPath` alone turns a repo clone into arbitrary code execution.

`gitconfig-hijack-scanner` deterministically audits `.git/config` and `~/.gitconfig` for hijack-grade keys — no heuristics, no ML, no network. It flags facts: the exact key, value, file, and line, with a severity per key.

## What it flags

| Severity | Key | Why |
|----------|-----|-----|
| `CRITICAL` | `core.hooksPath` | Redirects git hooks to an attacker-controlled directory — scripts execute on git operations |
| `HIGH` | `credential.helper` | Can shell out to an arbitrary command that receives your stored credentials |
| `HIGH` | `protocol.*.allow` | Re-enables dangerous transports like `ext::` (arbitrary command execution) |
| `HIGH` | `init.templateDir` | Copied into every repo you init/clone — poison it once, backdoor everything |
| `HIGH` | `core.fsmonitor` | Runs an arbitrary command on every `git status` — persistence hook |
| `MEDIUM` | `include.path` | Pulls in another config file — verify you trust the target |
| `MEDIUM` | `core.sshCommand` | Overrides SSH transport — can redirect/proxy your git traffic |
| `MEDIUM` | `url.<base>.insteadOf` | Silently rewrites remote URLs — fetches redirect to attacker remotes |
| `LOW` | `core.pager` | Command execution on log/diff output |

## What it does NOT do

- It does not fix your config — it reports. Removing a malicious `core.hooksPath` is one `git config --unset` away, and yours to decide.
- It does not scan for secrets in git history — that's a different tool's job.
- A clean scan is not proof of safety — it only covers the hijack-grade key list, not every misconfiguration.

## Usage

```bash
python3 gitconfig_hijack_scanner.py /path/to/repo --global --json
```

## Install

Zero dependencies — Python 3.8+ stdlib only.

```bash
git clone https://github.com/Iceman2050/gitconfig-hijack-scanner.git
cd gitconfig-hijack-scanner
python3 gitconfig_hijack_scanner.py --help
```

## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:
## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI


> Built by Ingenious AI with Muse — get free tokens with invite code `2HCQH1`
