# Releasing Moron Guard

Only maintainers can publish releases. The release workflow publishes the npm package first, then creates the matching GitHub release.

## One-time setup

1. Make the GitHub repository public.
2. Enable GitHub secret scanning, push protection, and private vulnerability reporting.
3. Create a GitHub environment named `npm`.
4. Restrict that environment to protected `v*` tags. Add reviewer approval if practical.
5. For the first publication, add a short-lived granular npm write token as the environment secret `NPM_TOKEN`.
6. After the first publication, configure npm Trusted Publishing for:
   - owner: `Jeecabs`
   - repository: `moron-guard`
   - workflow: `release.yml`
   - environment: `npm`
7. Revoke the bootstrap token and remove `NPM_TOKEN` after trusted publishing works.

## Release checklist

1. Update `version` in `package.json`.
2. Update the pinned npm and Git installation examples in `README.md` to the same version.
3. Move relevant changelog entries under that version and add the release date.
4. Run:

   ```bash
   pnpm install --frozen-lockfile
   pnpm verify
   pnpm audit --prod --audit-level high
   ```

5. Confirm that Git tracks the current `dist/` output. Commit it with its source changes. Git installations load these files without local build tools.
6. Merge the release changes into `main`.
7. Create a signed or annotated tag that exactly matches the package version:

   ```bash
   version="$(node -p 'require("./package.json").version')"
   git tag -s "v${version}" -m "moron-guard v${version}"
   git push origin "v${version}"
   ```

8. Approve the `npm` environment deployment when GitHub requests approval.
9. Verify the npm package, provenance statement, packed files, and generated GitHub release.

The workflow rejects a tag that does not match `package.json`. A prerelease version publishes with the npm `next` tag. Re-running a successful release is safe only when npm reports the same version and commit.

## Recovery

Do not delete or overwrite a published version. Fix the problem and publish a new patch version. Deprecate the affected npm version when necessary. If npm publication fails, the workflow does not create a GitHub release. Correct the problem and run the workflow again.
