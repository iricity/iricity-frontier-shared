# Release Playbook

How the primitive package reaches npm, how the Python implementation reaches PyPI, and what "done" means before either happens. The order matters: freeze, then publish JavaScript, then prove portability with Python, then publish Python.

## 0. What "done" means (the 0.1 freeze)

Do not publish anything until every line below is true. Publishing is permanent on npm and PyPI; unpublishing is restricted and leaves holes in version history.

- [ ] Protocol name final: trademark search done in the key markets, domain registered, ADR 0004 updated from `proposed` to `final`, and `name_status` in the state stack set to `final`.
- [ ] Specification tagged: `iricity-state-stack` tags `spec-v0.1.0` on the commit whose `docs/spec/protocol-v0.1.md` and `schemas/` are frozen. Wire tags stay `state-envelope/1` and `state-receipt/1`.
- [x] Vectors pinned (version 3, 75 cases, 2026-10-27): `conformance/vectors.json` carries `vectors_version: "3"` and `conformance/vectors.lock.json` its SHA-256 (a test fails if they diverge). A change to any vector is a new `vectors_version` with a new lock, never an edit. The Python repository vendors the same file under `src/frontier_shared/vectors/v3/` and carries the same hash; both implementations pass 75 of 75 with no suite skipped.
- [x] Workspace check green (2026-10-27): every suite passes in all five repositories (primitives JS and Python, state stack, space stack, space node) and both conformance runners print `RESULT: conformant`.
- [x] Package hygiene (2026-10-27): `npm pack --dry-run` lists only `src/`, `conformance/run.js`, `conformance/vectors.json`, `conformance/vectors.lock.json`, `LICENSE`, `README.md`, `CHANGELOG.md`, `package.json` (17 files, 33 kB). The Python `python -m build` plus `twine check` pass. Neither tarball contains a secret, an internal name or attribution (scanned).
- [x] No internal names (2026-10-20, rescanned 2026-10-27): the full history of every repository, the pre-rewrite backups, the published SDK versions and the unpublished tarballs carry no secret, no private project name and no attribution.
- [x] History is clean (2026-10-17 content rewrite; 2026-10-20 author rewrite to the GitHub noreply address): fresh clones of all repositories show zero internal-name hits and no personal email. Backups are in the private notes folder under repo-backups.
- [ ] Residue only a fresh repository clears: GitHub still serves the pre-rewrite head commits of `iricity-frontier-shared`, `iricity-frontier-shared-py` and `iricity-state-stack` by SHA (checked 2026-10-27), and the space stack's merged pull requests keep theirs. Publication therefore uses fresh repositories: rename each existing private repository to `<name>-private-archive` (or delete it once nothing points at it), create a new repository with the original name, public from the start, and push the clean history from this machine. Trusted publishers are name-based (owner and repository name), so they bind to the new repositories unchanged. The space stack stays private, so its residue never matters; the node repository has been clean since its first commit.
- [ ] CHANGELOG entry for the version being published (add `CHANGELOG.md` with this release if it does not exist yet).
- [ ] The production node still verifies: a pass prediction from `https://iricity.space/space/nodes/node_zone_001_delhi/passes` verifies with `verifyEnvelope` from the exact commit being published.

## 1. Versioning

Semantic versioning. The first published version of both implementations is `0.5.0`: it carries vectors version 3 and the regulator-issued credential layer, and the two implementations are aligned on it.

- `0.x.y`: wire formats may still gain fields; a breaking change to canonical form, envelope or receipt bumps the wire tag (`/2`) and the minor version.
- `1.0.0`: the first version published after `spec-v1.0.0` is tagged. Not before.
- Python and JavaScript carry the same major and minor; patch numbers may differ.

## 2. First npm publish (one time, manual, from the `iricity` npm account)

npm trusted publishing can only be attached to a package that already exists, so the first version is published by hand. Everything after that goes through GitHub Actions. Order on the day: fresh public repositories first (section 0, last line), then this publish, then the trusted publisher (section 3), then the tag.

1. On a machine you trust, log in as the account that owns the `@iricity` scope:
   ```
   npm login
   npm whoami          # must print: iricity
   ```
   The CLI on the workspace laptop is logged in as a different user and cannot publish to the scope; use `npm login` to switch, or publish from another machine.
2. Check out the frozen commit and verify it is clean:
   ```
   git status --short   # empty
   npm ci
   npm test
   npm run conformance
   npm pack --dry-run
   ```
3. Publish with provenance (public scope, signed build attestation):
   ```
   npm publish --access public --provenance
   ```
   `--provenance` works from a local machine only when the environment supports it; if the command refuses, publish without the flag this one time. Every later publish from Actions carries provenance automatically.
4. Confirm:
   ```
   npm view @iricity/frontier-shared version dist.tarball
   npx -y @iricity/frontier-shared@latest node -e "import('@iricity/frontier-shared').then(m=>console.log(m.ENVELOPE_VERSION))"
   ```
5. Tag the commit `v<version>` from your machine and push the tag. The publish workflow is tag-triggered and no-ops on a version that already exists. (Tags created by a workflow with the default token do not trigger other workflows, which is why there is no tag-creating workflow in this repository.)

## 3. Set up trusted publishing (so no token ever lives on a laptop or in a secret)

1. On npmjs.com, open the package page, Settings, Trusted Publisher, Add GitHub Actions.
2. Organization or user: `iricity`. Repository: `iricity-frontier-shared`. Workflow filename: `publish.yml`. Environment: `npm`.
3. On GitHub, open the repository Settings, Environments, create `npm`, and add yourself as a required reviewer. Every publish then waits for one click of approval. Note: on the GitHub Free plan this reviewer gate is available only on public repositories. While the repository is private the workflow still runs and the environment is created implicitly; the gate is that only a collaborator can push a release tag. Add the reviewer rule once the repository is public.
4. Nothing else: the workflow in `.github/workflows/publish.yml` already requests an OIDC token and runs `npm publish --access public --provenance`.

## 4. Every later npm release

1. Update the version: `npm version patch` (or `minor`), which commits and tags.
2. Push the commit and the tag: `git push origin main --follow-tags`.
3. Approve the `npm` environment run in the Actions tab.
4. Check `npm view @iricity/frontier-shared version` and the provenance badge on the package page.
5. Re-vendor the consumers, or move them to the registry version (section 5).

## 5. Move the consumers off the vendored tarball

Today `iricity-state-stack` and `iricity-space-stack` depend on `file:vendor/iricity-frontier-shared-<version>.tgz`. After the first publish:

1. In each consumer: `npm install @iricity/frontier-shared@<version>`, delete `vendor/`, commit `package.json` and `package-lock.json`.
2. Run the consumer's tests and the workspace check.
3. Retire `scripts/vendor-frontier-shared.ps1` and the vendoring note in `WORKSPACE_CI.md`.

For the space stack, that commit deploys to production on push. Do it when you can watch the deploy.

## 6. The Python implementation (the portability proof)

Purpose: a second implementation, in a different language, that passes `conformance/vectors.json` byte for byte. Until this exists the specification is a JavaScript program with a document attached; after it, the specification is real.

Repository: `iricity/iricity-frontier-shared-py`. Package name on PyPI: `iricity-frontier-shared`. Module name: `frontier_shared`. Status 2026-10-17: implemented, 23 of 23 vectors with no suite skipped, 8 tests, `python -m build` and `twine check` pass, and it verifies live envelopes produced by the JavaScript node. Local repository initialized; it needs the GitHub repository created under the org and `parthod0x` added as a collaborator before it can be pushed.

Scope, nothing more:

| Module | Contents | Vector suite |
| --- | --- | --- |
| `frontier_shared.canonical` | `canonical_json(value)` per RFC 8785 | `canonical_json` |
| `frontier_shared.hashing` | `hash_payload`, `hash_record`, `hash_bytes`, `sha256_hex` | `canonical_json` (expected_hash) |
| `frontier_shared.base58` | `base58_encode`, `base58_decode` | `base58btc` |
| `frontier_shared.keys` | `KeyPair.from_seed`, `did_from_public_key_bytes`, `public_key_bytes_from_did`, `sign_bytes`, `verify_bytes` | `did_key`, `ed25519` |
| `frontier_shared.envelope` | `create_envelope`, `verify_envelope` | `envelope` |
| `frontier_shared.receipt` | `create_receipt_record`, `verify_receipt_record`, `verify_receipt_chain` | `receipt` |
| `frontier_shared.conformance` | `run_conformance(vectors)` with `load_vectors(path)`; console script `frontier-shared-conformance [path]` | all |

Rules that make it pass:

- Numbers: RFC 8785 number formatting is the ECMAScript algorithm. Do not use Python's `repr`. Implement the shortest round-trip form with ECMAScript exponent rules (`1e+21`, `1e-7`, no `+` in mantissa, `-0` prints as `0`). The vectors `numbers` and `rfc8785-sample` catch every mistake here.
- Strings: escape only `"`, `\`, and control characters below U+0020 (`\b \f \n \r \t`, others as `\u00XX` lowercase). Do not escape `/` or non-ASCII.
- Key order: sort by UTF-16 code units, not by Unicode code points. In Python, sort by `key.encode('utf-16-be')`. The `unicode-key-order` vector has a supplementary-plane key for exactly this reason.
- Ed25519: use `cryptography` (`Ed25519PrivateKey.from_private_bytes(seed)`); signatures are raw 64 bytes, base64url without padding.
- `did:key`: multicodec prefix bytes `ed 01`, base58btc, leading `z`.
- Envelope and receipt signing inputs are the domain tag plus the canonical JSON of the header or core, exactly as in `src/crypto/envelope.js` and `src/records/receipt.js`. Field order does not matter because canonical JSON sorts; field set does.

Definition of done for the Python package: `frontier-shared-conformance ../iricity-frontier-shared/conformance/vectors.json` prints `RESULT: conformant` with zero skipped suites, and its own tests cover tampering and chain verification the way `tests/records.test.js` does.

## 7. First PyPI publish

Follow the same shape as the JavaScript SDK release in `iricity-webapp/docs/SDK_RELEASE_PLAYBOOK.md`.

1. `pyproject.toml` with name `iricity-frontier-shared`, version matching the JavaScript minor, license `Apache-2.0`, `cryptography` as the only runtime dependency, and the console script.
2. Register a Trusted Publisher on PyPI for the project before the first upload (PyPI allows pending publishers for names that do not exist yet): owner `iricity`, repository `iricity-frontier-shared-py`, workflow `publish.yml`, environment `pypi`. The same GitHub Free note applies: the `pypi` environment exists implicitly while the repository is private; add the required-reviewer rule when it is public.
3. The committed `publish.yml` builds with `python -m build`, runs `twine check dist/*`, runs the conformance script against the vendored vectors (a test asserts the vendored copy matches the lock from the JavaScript repository), then uses `pypa/gh-action-pypi-publish@release/v1` with `id-token: write` and environment `pypi`.
4. Tag `v<version>`, push, approve the environment run.
5. Confirm: `pip install iricity-frontier-shared==<version>` in a fresh virtual environment, then run the conformance console script against the vectors.

## 8. After both are published

- Add a "Implementations" table to `iricity-state-stack/docs/spec/README.md` listing both packages, their versions, and the vectors version they pass.
- Add the Python conformance run to the state stack's CI as a second check, so a vectors change can never pass in one language and fail in the other.
- Only then consider the specification 0.1 frozen in public, and move ADR 0005's governance items onto the roadmap when outside contributors appear.
