# GitHub security cleanup report

Prepared locally on 2026-11-01. This report does not reproduce captured packets, blocklist targets, or the former Windows username. **No GitHub branch, visibility setting, firewall rule, or hosts-file entry was changed.**

## Original and backup

The original working repository remains at local `development` commit `6560f72`, one commit ahead of the public `origin/development` commit `61f2ff0`. Its pending README edits, original audit, ignored data, and unrelated untracked review-output file remain intact. The complete directory backup is `../ntc-security-20261101-161909/original-copy/`; the Git bundle of commit refs is `../ntc-security-20261101-161909/all-refs.bundle`. Bundle verification reported a complete commit history. The directory copy also preserves the non-commit Codex checkpoint refs. It has every original file with matching size, and SHA-256 matches were checked for README, audit, runtime blocklist, committed capture, both active models, and Git HEAD. The backup contains extra copies of ignored Streamlit skill files reached through `.agents`.

## Rewritten local repository

The disposable bare mirror is `../ntc-clean-mirror-20261101-161909.git/`; its validation worktree is `../ntc-clean-checkout-20261101-161909/`. `git-filter-repo` 2.47.0 rewrote eight of nine commits across the mirrored history, reporting `5bad429` as the first changed commit. The cleanup removed these exact paths from every reachable commit:

- `data/blocklist.json` (first added in `4a5b7d0`; contained a reserved example domain, a public service domain, and private blocklist event history)
- `temp_upload/pcap.pcapng` (first added in `5bad429`; uploaded traffic of unverified public provenance)
- `data/flows.csv` (empty generated file)
- `src/__pycache__/extract.cpython-313.pyc`
- `src/__pycache__/predict.cpython-313.pyc`

A text replacement removed the old Windows user-specific path from historical code and redacted the specific observed hostname in the unpublished release commit. A deterministic test now uses a synthetic provider subdomain. Two Codex checkpoint refs pointed directly to an uncommitted tree and could not be rewritten by `git-filter-repo`; they were removed **only from the disposable mirror** after the original copy and bundle were verified. Six unreachable objects left by those refs were pruned in the mirror; a subsequent `git fsck --no-reflogs --unreachable` reported zero. The remaining mirror refs are the rewritten `main`, `master`, and `development` branches. No tags were present.

An all-object scan of the rewritten reachable refs found none of the five removed paths, the former username, or the redacted observed hostname. The release branch retains all 77 original tracked files before this report was added; only README and the deterministic test fixture differed from the original release tree. `main` went from 17 to 13 files by removal of the four generated/capture paths present on that branch. The active RF and XGBoost models, dashboard, capture code, and prediction code matched their original release blobs byte for byte.

## Validation and artifact limits

The cleaned checkout passed **77 automated tests**, including both optional PCAPNG integrations supplied from an existing local file outside the checkout. All **42 Python files** parsed, direct imports and `pip check` succeeded, and headless Streamlit served HTTP 200 for health and root. The test run used locally generated, ignored RF feature tables and the separately installed Scenario B archive; a bare clone needs the README's public-dataset fixture instructions to reproduce the full count. No live hardware capture was repeated during this cleanup.

All eight tracked `.pkl` files were scanned as raw bytes for the former username, Windows user path, Npcap adapter identifiers, GitHub-token prefixes, private-key headers, and the redacted hostname; none matched. This does **not** rule out encoded or compressed sensitive content, model memorization, or the general risk of loading untrusted pickle files. The 61 RF feature names include `ip_version` but no source/destination address, hostname, or user-agent feature. The active RF model is 28,746,337 bytes and XGBoost model 8,092,727 bytes, below GitHub's 100 MB per-object limit but above its 1 MB recommendation. No raw training archive is tracked. UNB permits redistribution of its dataset with citation to the dataset and paper; the README now includes both. The project itself has no `LICENSE` file.

## Publication boundary

The cleaned mirror is a **local candidate**, not a GitHub update. Public `main` and `development` still expose old commits. Before publishing, freeze collaborator pushes, review current remote refs and protected-branch rules, inspect the final mirror trees and test log, and obtain explicit owner approval for a force update. Use explicit leases against the current remote branch IDs; never push every local mirror ref blindly. Afterward, collaborators must re-clone or clean old clones. GitHub cached views and pull-request refs may require GitHub Support. A rewrite cannot retract copies already downloaded.

The following PowerShell commands are **recommendations only** and were not executed. Recheck the remote IDs immediately before using them; the explicit leases will reject a changed branch:

```powershell
$mirror = (Resolve-Path '..\ntc-clean-mirror-20261101-161909.git').Path
git ls-remote https://github.com/Mahesh032R/network_traffic_classifier.git refs/heads/main refs/heads/development
git -C $mirror remote add github https://github.com/Mahesh032R/network_traffic_classifier.git
git -C $mirror push --force-with-lease=refs/heads/main:5bad42925823af6fd06b6c36993387da19beaa66 --force-with-lease=refs/heads/development:61f2ff0ed342ecb58f0c6657aacd6b8d97e4f40f github refs/heads/main:refs/heads/main refs/heads/development:refs/heads/development
```

References: [GitHub sensitive-data removal](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository), [git-filter-repo manual](https://github.com/newren/git-filter-repo/blob/main/Documentation/git-filter-repo.txt), [UNB dataset terms](https://www.unb.ca/cic/datasets/), [GitHub repository limits](https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits).
