# Session 12 Assignment: Migrate, Harden, and Hunt

You take the glc_v1 gateway, run it on Modal yourself, fix the security issues the session hands you, and then find new ones. You work alone, on your own Modal account.

## Setup (do this first)

- Clone `glc_v1` and create your own Modal account.
- Use **mock keys only**. Never put real provider keys on Modal.
- One deployment per student, scale-to-zero, so you stay on the free tier.
- The migration steps are in Session 12, Section 6 (the `modal_app.py` wrapper, the Secret, the deploy). Confirm your gateway is live with `curl <url>/healthz`.

## Part 1: harden it (required)

Fix every finding in Session 12:

- Section 6, groups A and C (the deployment and endpoint issues).
- Section 7, the ten code leaks.

For each finding:

1. Reproduce it against your own deployment. Use `curl` for the HTTP findings, and the two-file `gateway.py` plus adapter harness from Section 2 for the in-process leaks.
2. Fix it. Make a commit that names the invariant (Section 4) it broke and shows the fix.
3. Re-run the reproduction and confirm the attack now fails.

Deliverable: your migrated, hardened `glc_v1` repository, plus a `FINDINGS.md` that lists each finding, the invariant it broke, and your fix. Part 1 is the floor. A submission that does not clear it does not score.

## Part 2: find something new (100 points each)

Anything already in Sections 6 or 7 earns nothing. A genuinely new bug is worth **100 points when your pull request both proves it and fixes it**.

Open a pull request against `glc_v2` (the reference repository) that includes:

- a one-paragraph description of the bug and the invariant it breaks,
- a reproduction that runs from a fresh checkout,
- the fix that closes it.

A PR that does not reproduce, or that reports a bug without fixing it, does not score. On duplicates, the first PR filed wins, so check the open pull requests before you start.

## How to reproduce a finding

- HTTP findings: `curl` your gateway's endpoints directly.
- In-process leaks: run the snippet inside the gateway process using the two-file `gateway.py` plus adapter harness from Section 2.

## Rules

Work only against your own deployment and the `glc_v2` repository. Do not attack another student's Modal account, the school's other properties, or the real upstream providers. Keep every deployment on mock keys. A pull request that restates another student's earlier find does not score. Keep exploits inside the assignment.

## Deadline

One week from Saturday. Late pull requests are accepted for a further 48 hours at a 30% penalty.
