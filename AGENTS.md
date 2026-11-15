# Workspace Rules — Version & Changelog Tracking

Whenever making any functional update, bugfix, UI improvement, or deployment preparation (`git commit` / `git push`) in this repository:

1. **Bump `APP_VERSION`** (SemVer `vMAJOR.MINOR.PATCH`) and **prepend a new release entry** to `APP_CHANGELOG` inside the changelog IIFE at the bottom of `2mybebi.html`, keeping the badge `#changelog-pill-ver` fallback text matched to `APP_VERSION`.
2. **Prepend the matching release section** to `CHANGELOG.md` with date (`DD/MM/YYYY`), tag, title, and concise bullet items matching `APP_CHANGELOG`.
3. **Never introduce `60 MB` or `60MB` anywhere in `2mybebi.html`**, and **keep inline `<script>` count at strictly 3**.
4. **Run `node tests/verify-security-and-ai.mjs`** before committing/pushing to confirm version consistency and all automated checks pass.
