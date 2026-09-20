# Publishing

Step-by-step for the owner to publish the three packages at **0.1.0**. Nothing here has been published yet: no GitHub repository, no npm, no PyPI.

| Package | Registry | Directory |
|---|---|---|
| `@catalisa/biometrics` | npm | `packages/node` |
| `@catalisa/biometrics-web` | npm (+ jsDelivr/unpkg automatically) | `packages/web` |
| `catalisa-biometrics` | PyPI | `packages/python` |

## 0. Pre-publication checklist

- [x] **Public base URL is live.** `https://api.biometrics.catalisa.app/v1` is in production and answering (verified 2026-09-19 with the node SDK against the real API: session created, read back, typed 401 and 404).
- [x] **Capture page host.** Production issues `captureUrl` on `https://biometrics.bb.catalisa.app` (verified 2026-09-19), the host the guide documents for `allowedEmbedHosts`.
- [ ] **License.** Packages declare MIT (same as `@catalisa/panel-sdk`). Confirm, or change `license` in the three manifests and the `LICENSE` files.
- [ ] **npm scope.** You are logged in to npm (`npm whoami`) with publish rights on the `@catalisa` scope, with 2FA.
- [ ] **PyPI.** A PyPI account with an API token for `catalisa-biometrics` (name still free on 2026-09-19: `pip index versions catalisa-biometrics` finds nothing).
- [x] **Repository URL.** `https://github.com/catalisaio/catalisa-biometrics-sdk` (private), wired into both `package.json` files and `pyproject.toml`.
- [x] **Subaccounts.** Merged and in production (building-blocks-v2#404); the SDKs handle `QUOTA_EXCEEDED`/`SUBACCOUNT_SUSPENDED` and `X-Subaccount-Id`.
- [x] **Test environment.** The sandbox is in production (building-blocks-v2#408/#409): a `test` key runs the simulated engine, spends no allowance and is never billed. Documented in the node and python READMEs; `environment` is typed in the node envelope.
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
