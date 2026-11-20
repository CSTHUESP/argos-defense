# Repository setup (maintainers)

How the GitHub repository `CSTHUESP/argos-defense` is meant to be configured, how to apply each setting, and how to check it. The repository is **public**: anyone can read it, use the releases, open issues and propose changes.

Sections 1–3 are instructions and stay valid whatever the current state is. Section 4 records dated observations and is history, not a description of today's settings.

## 1. Settings

Every setting below is changed in the GitHub web interface by a repository administrator. Exact menu labels may move slightly as GitHub updates its interface.

### A. Private vulnerability reporting
- **Where:** Settings → *Security and quality* → *Advanced Security* → **Private vulnerability reporting** → **Enable**.
- **Check:** the repository's [Security tab](https://github.com/CSTHUESP/argos-defense/security) shows a **Report a vulnerability** button. Do not submit a test report.
- No documentation change is needed after enabling it: [SECURITY.md](../SECURITY.md) and the issue chooser already tell reporters to use that button when it is shown, and the fallback form when it is not (section 3).

### B. Discussions
- **Where:** Settings → General → *Features* → tick **Discussions**.
- **Check:** a **Discussions** tab appears next to Issues.
- The README does not link to Discussions. Add such a link only once the tab exists.

### C. Description and topics
- **Where:** repository home page → **About** → gear icon (⚙).
- **Description:** `Experimental defensive investigation framework for telemetry analysis, threat detection, and evidence-based assessment of automation and LLM involvement.`
- **Topics** (keep any other relevant topics already present): `cybersecurity`, `threat-hunting`, `incident-response`, `dfir`, `llm-security`, `detection-engineering`, `python`
- **Check:** the description and topic chips are shown in the About box on the home page.

### D. Protect `main` (solo-maintainer configuration)
- **Where:** Settings → Rules → Rulesets → **New ruleset** → **New branch ruleset**.
- **Values:**
  - Ruleset name: `main protection`
  - Enforcement status: **Active**
  - Bypass list: **empty**
  - Target branches: **Include default branch**
  - **Restrict deletions:** on
  - **Block force pushes:** on
  - **Require a pull request before merging:** on
    - Required approvals: **0**
    - Dismiss stale approvals, Require review from Code Owners, Require approval of the most recent reviewable push: **off**
  - **Require status checks to pass:** on
    - **Require branches to be up to date before merging:** on
    - Required checks, each with source **GitHub Actions**:
      - `tests (ubuntu-22.04, py3.11)`
      - `tests (ubuntu-22.04, py3.12)`
      - `tests (ubuntu-22.04, py3.13)`
      - `tests (windows-2022, py3.12)`
      - `tests (macos-15, py3.12)`
      - `tests (macos-15-intel, py3.12)`
      - `wheel/sdist build + install outside checkout`
  - Leave **Restrict updates**, **Require merge queue**, **Require deployments**, **Require signed commits** and **Require linear history** off. With an empty bypass list, *Restrict updates* would block every change to `main`.
- **Check:** Settings → Rules → Rulesets lists **main protection** as **Active**, targeting the default branch. The repository's branch page shows `main` as protected.
- The check names are the job names in [.github/workflows/ci.yml](../.github/workflows/ci.yml), matching the successful CI run [44794296126](https://github.com/CSTHUESP/argos-defense/actions/runs/44794296126). If a job is renamed or the matrix changes, update the required checks in the same pull request. Otherwise every pull request waits for a check that never reports.

### E. Protect version tags
- **Where:** Settings → Rules → Rulesets → **New ruleset** → **New tag ruleset**.
- **Values:**
  - Ruleset name: `release tags`
  - Enforcement status: **Active**
  - Bypass list: **empty**
  - Target tags: **Include by pattern** → `v*`
  - **Restrict updates:** on
  - **Restrict deletions:** on
  - **Restrict creations:** **off**, so `create-tag.yml` can still create new version tags.
- **Check:** the ruleset is listed as **Active** with target `v*`. Do not move or delete an existing tag to test it.

### F. Release immutability (future releases)
- **Where:** Settings → General → *Releases* → enable **release immutability**.
- **Check:** the setting stays enabled after reloading the page.
- **Scope:** immutability protects releases **published after** it is enabled: their assets and tag can no longer be changed. Releases that were already published, including **v0.3.1** (published before the setting existed here), are **not** made immutable retroactively. Do not delete, recreate or republish an existing release to change that.
- **Compatibility with the release workflow:** [release.yml](../.github/workflows/release.yml) already follows the sequence that immutable releases need:
  1. create a **draft** with the complete asset set (`gh release create --draft`);
  2. download the draft and verify every asset against expectations recorded before upload, then verify the provenance attestations;
  3. publish (`gh release edit --draft=false`).

  Nothing is uploaded or changed after publication. The only post-publication step downloads and checks the assets.

## 2. Maintenance workflow (one maintainer)

Once `main protection` is active, changes reach `main` only through a pull request whose required checks have passed:

1. Create a branch: `git switch -c docs/fix-typo`.
2. Commit and push the branch: `git push -u origin docs/fix-typo`.
3. Open a pull request against `main`. CI (`ci.yml`) runs on every pull request with read-only permissions.
4. Wait until the seven required checks are green. If `main` moved in the meantime, update the branch ("Update branch"), because branches must be up to date.
5. Merge the pull request yourself. No approving review is required.

Direct pushes to `main` are rejected while the ruleset is active, including for administrators, because the bypass list is empty.

**Releases** are unchanged: after the release commit is on `main` and its CI has passed, run *Actions → Create release tag* (`create-tag.yml`) with the version, the full commit SHA and `publish=true`. The tag ruleset allows creating the new `v*` tag and blocks later changes to it.

## 3. Security reporting

- **Private vulnerability reporting enabled:** reporters use **Report a vulnerability** on the Security tab. The report and the fix are coordinated in a private advisory.
- **Not enabled:** reporters open the [Security contact request (no details)](https://github.com/CSTHUESP/argos-defense/issues/new?template=security_contact.yml) form. That issue is **public** and asks only for two confirmations. It must not contain vulnerability details, reproduction steps, affected components, credentials, logs or investigation data. A maintainer then opens a draft GitHub security advisory (Security tab → *Advisories* → *New draft security advisory*) and adds the reporter as a collaborator, so technical details are exchanged only there.
- The contact form uses the `security-contact` label. Blank issues are disabled (`.github/ISSUE_TEMPLATE/config.yml`), so this form is the neutral way in.

## 4. Observations (dated history, not current configuration)

**2026-11-20, after publishing v0.3.1:**
- Visibility public; Issues enabled; Discussions disabled.
- No description or topics.
- Private vulnerability reporting disabled.
- No rulesets or branch protection.
- Release immutability disabled; v0.3.1 `immutable: false`.

The automation integration used to publish v0.3.1 could not change any of these settings. Each attempt was refused:
- repository settings (description, Discussions): "Repository settings writes are not permitted through this proxy";
- topics, private vulnerability reporting and rulesets: "Write access to this GitHub API path is not permitted through this proxy";
- release immutability: "Resource not accessible by integration".

An administrator applies sections 1A–1F directly in the web interface. This was a limitation of that integration's access, not of the release.
