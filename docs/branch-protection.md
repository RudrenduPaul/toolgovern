# Branch protection for `main`

This documents the exact steps to require pull-request review before merging to `main`, require
the CI status check to pass, and block force-pushes. **Applied, with `enforce_admins` off.** `main`
currently requires 1 approving review before merging and disallows force-pushes and branch
deletion; `enforce_admins` is `false`, so a repo admin can still push directly to `main` in an
emergency or for solo maintenance -- the rule binds outside contributors, not the maintainer.
A required CI status check has not been added yet -- see the "Option A"/"Option B" steps below to
add one once a workflow's job name is confirmed.

## Prerequisites

- Admin access to `RudrenduPaul/toolgovern` on GitHub.
- The CI workflow (`.github/workflows/ci.yml`) has run at least once on `main` so its check name is
  known to GitHub. As of this writing the workflow is named `CI` and its single job is named `ci`;
  confirm the exact name in the "Checks" tab of a recent commit or run before entering it below,
  since the branch-protection API matches on the literal job name, not the workflow name.

## Option A: GitHub Settings UI

1. Go to `https://github.com/RudrenduPaul/toolgovern/settings/branches`.
2. Under "Branch protection rules," click **Add branch protection rule** (or **Add rule**).
3. Branch name pattern: `main`.
4. Enable **Require a pull request before merging**.
   - Set **Required number of approvals before merging** to `1`.
   - Optionally enable **Dismiss stale pull request approvals when new commits are pushed**.
5. Enable **Require status checks to pass before merging**.
   - Enable **Require branches to be up to date before merging**.
   - Search for and select the CI check (the job name from `.github/workflows/ci.yml`, confirmed
     in the prerequisites step above).
6. Enable **Do not allow bypassing the above settings** if you want the rule to apply to repo
   admins too, not just external contributors. Leave it off if maintainers should be able to
   override in an emergency.
7. Under **Rules applied to everyone including administrators**, leave force-push and branch
   deletion unchecked (i.e. leave them disallowed) -- by default, branch protection already blocks
   force-pushes and deletion of a protected branch unless you explicitly opt back in, so no extra
   action is needed to block them.
8. Click **Create** (or **Save changes**).

## Option B: `gh api` (scriptable, same effect as Option A)

Requires the GitHub CLI (`gh`) authenticated with an account that has admin rights on the repo.

```bash
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  /repos/RudrenduPaul/toolgovern/branches/main/protection \
  -f required_status_checks[strict]=true \
  -f 'required_status_checks[contexts][]=ci' \
  -f enforce_admins=false \
  -f required_pull_request_reviews[required_approving_review_count]=1 \
  -f required_pull_request_reviews[dismiss_stale_reviews]=true \
  -f restrictions='null' \
  -f allow_force_pushes=false \
  -f allow_deletions=false
```

Notes on the flags:

- `required_status_checks[contexts][]=ci` -- replace `ci` with the actual CI job name
  confirmed in the prerequisites step; the branch-protection API rejects a context name that
  hasn't reported a status on the repo yet.
- `enforce_admins=false` -- matches leaving "Do not allow bypassing" unchecked in Option A. Set to
  `true` if the rule should also bind repo admins.
- `restrictions='null'` -- no additional user/team push restrictions beyond the PR-review
  requirement itself. Replace with a JSON object naming specific users/teams if you want to
  further restrict who can push directly (irrelevant once PR review is required, but the field is
  mandatory in the API call).
- `allow_force_pushes=false` and `allow_deletions=false` are the defaults; listed explicitly here
  so the command is self-documenting rather than relying on an implicit default.

## Verifying it's active

```bash
gh api /repos/RudrenduPaul/toolgovern/branches/main/protection
```

A `200` response confirms a protection rule is live on `main`; check which pieces it covers from
the fields present. Today that response includes a populated `required_pull_request_reviews` (1
approval) and `allow_force_pushes`/`allow_deletions` both `false`, but no `required_status_checks`
key at all -- no CI check is wired into branch protection yet, only PR review. A `404` means no
protection rule exists on `main`.

## Removing it

```bash
gh api --method DELETE /repos/RudrenduPaul/toolgovern/branches/main/protection
```

## Current status and what's left

PR-review protection is on now that the project accepts outside contributions. The remaining step
in Option A/B above -- wiring a required CI status check into the rule -- is still open; add it
once the CI workflow's job name is confirmed. `enforce_admins` stays `false` by design: the
maintainer can still push directly to `main` for solo iteration without opening a PR, and outside
contributors go through PR review.
