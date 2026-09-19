# Publishing

Step-by-step for the owner to publish the three packages at **0.1.0**. Nothing here has been published yet: no GitHub repository, no npm, no PyPI.

| Package | Registry | Directory |
|---|---|---|
| `@catalisa/biometrics` | npm | `packages/node` |
| `@catalisa/biometrics-web` | npm (+ jsDelivr/unpkg automatically) | `packages/web` |
| `catalisa-biometrics` | PyPI | `packages/python` |

## 0. Pre-publication checklist

- [ ] **Public base URL is live.** The SDKs default to `https://api.biometrics.catalisa.app/v1`, which has **no DNS record yet** (checked 2026-09-19). Either create the edge route (`api.biometrics.catalisa.app/v1/*` → `biometrics.bb.catalisa.app/biometrics/api/v1/*`) before publishing, or change `DEFAULT_BASE_URL` in `packages/node/src/http.ts` and `packages/python/src/catalisa_biometrics/client.py`.
- [ ] **CDN origin for the capture page.** Integrators must list their origin in the provider's `allowedEmbedHosts`; confirm the production `captureUrl` host (`BIOMETRICS_PUBLIC_URL`) is the one documented in the guide.
- [ ] **License.** Packages declare MIT (same as `@catalisa/panel-sdk`). Confirm, or change `license` in the three manifests and the `LICENSE` files.
- [ ] **npm scope.** You are logged in to npm (`npm whoami`) with publish rights on the `@catalisa` scope, with 2FA.
- [ ] **PyPI.** A PyPI account with an API token for `catalisa-biometrics` (the name is free as of 2026-09-19 — confirm with `pip index versions catalisa-biometrics`).
- [ ] **Repository URL.** When the GitHub repository exists, add `"repository"` to both `package.json` files and `[project.urls] Source` to `pyproject.toml`.
- [ ] **Subaccounts.** The SDKs handle `QUOTA_EXCEEDED`/`SUBACCOUNT_SUSPENDED` and `X-Subaccount-Id` already; publish only after the subaccounts branch is merged if the guide documents it.
- [ ] Everything green (step 1).

## 1. Verify

```bash
npm ci
npm run typecheck
npm test                                   # node + web (vitest)
cd packages/python && python3 -m venv .venv && .venv/bin/pip install pytest && .venv/bin/python -m pytest -q && cd ../..
npm run build                              # dist/ for node (ESM+CJS+d.ts) and web (ESM+CJS+UMD)
node scripts/verify-snippets.mjs           # every server snippet, 8 languages (needs docker for php/go/ruby/C#)
node scripts/verify-web-snippets.mjs       # web snippets in jsdom
```

Optional: regenerate the crypto vectors with the building block's own code (needs `~/Projects/building-blocks-v2` with `node_modules`, and `bun`):

```bash
scripts/bb-vector.sh static vectors/vectors.json && npm test
```

## 2. Inspect what will be uploaded

```bash
(cd packages/node && npm pack --dry-run)
(cd packages/web && npm pack --dry-run)
```

Each tarball must contain only `dist/`, `README.md`, `LICENSE` and `package.json`.

## 3. Publish to npm

```bash
cd packages/node && npm publish --access public && cd ../..
cd packages/web  && npm publish --access public && cd ../..
```

`prepublishOnly` runs clean + typecheck + tests + build again. After a few minutes the UMD bundle is served at:

- `https://cdn.jsdelivr.net/npm/@catalisa/biometrics-web@0.1.0/dist/biometrics-web.umd.js`
- `https://unpkg.com/@catalisa/biometrics-web@0.1.0/dist/biometrics-web.umd.js`

## 4. Publish to PyPI

```bash
cd packages/python
python3 -m venv .venv-release && . .venv-release/bin/activate
pip install --upgrade build twine
python -m build                    # dist/catalisa_biometrics-0.1.0.tar.gz and .whl
twine check dist/*
twine upload --repository testpypi dist/*   # optional dry run on TestPyPI
twine upload dist/*
```

## 5. After publishing

- [ ] `npm view @catalisa/biometrics version` and `npm view @catalisa/biometrics-web version` show `0.1.0`.
- [ ] `pip install catalisa-biometrics==0.1.0` in a clean venv and `python -c "import catalisa_biometrics as c; print(c.__version__)"`.
- [ ] Open the jsDelivr URL and confirm the banner `@catalisa/biometrics-web v0.1.0`.
- [ ] Tag the repository: `git tag v0.1.0 && git push --tags`.
- [ ] Point the developer guide snippets (`snippets/index.json`) at the published versions.

## Next versions

Bump the version in `packages/node/package.json`, `packages/node/src/http.ts` (`SDK_VERSION`), `packages/web/package.json`, `packages/web/src/index.ts` (`VERSION`), `packages/python/pyproject.toml` and `packages/python/src/catalisa_biometrics/client.py` (`VERSION`), then repeat steps 1–5.
