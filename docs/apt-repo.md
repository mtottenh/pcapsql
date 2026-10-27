# apt repository

Each tagged release publishes a signed apt repository to GitHub Pages
(`gh-pages` branch, served at `https://<owner>.github.io/pcapsql/`). One
suite per distro release: `focal`, `jammy`, `noble` (Ubuntu) and
`bullseye`, `bookworm`, `trixie` (Debian).

The pipeline lives in the `apt-repo` job in
[`.github/workflows/release.yml`](../.github/workflows/release.yml). It
re-uses the `.deb` artifacts built by the `build-deb` matrix job, adds
them to a [reprepro](https://wiki.debian.org/DebianRepository/SetupWithReprepro)
tree, signs it, and pushes the result to `gh-pages`. The branch is
checked out first, so old package versions remain installable.

## One-time maintainer setup

1. **Generate a signing key** (no passphrase — the workflow cannot
   answer GPG prompts):

   ```sh
   gpg --batch --quick-gen-key "pcapsql apt repo <your-email>" rsa4096 sign never && \
     KEYID=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/ {print $5; exit}') && \
     echo "KEYID=$KEYID"
   ```

2. **Add the private key as a GitHub secret** named
   `APT_REPO_GPG_PRIVATE_KEY` (note: `KEYID` is only set in the shell
   where you ran the previous step):

   ```sh
   gpg --armor --export-secret-key "$KEYID" | gh secret set APT_REPO_GPG_PRIVATE_KEY
   ```

3. **Enable GitHub Pages** for the repo (Settings → Pages → Source:
   "Deploy from a branch"). The first `v*` tag build creates the
   `gh-pages` branch; select it there once it exists.

That's it — subsequent releases update the repository automatically.

The `apt-repo` job downloads the `.deb` assets from the GitHub release
itself (not the build-job artifacts), so the apt repository and the
release page always serve identical packages.

To republish the repository for an **existing** tag, run the Release
workflow manually. The build and release jobs are skipped; only the apt
repository is refreshed from the release assets:

```sh
gh workflow run release.yml -f tag=v1.2.3
```

(Manual dispatch becomes available once the workflow file containing
the `workflow_dispatch` trigger is on the default branch.)

## User installation

```sh
# Trust the repository key
curl -fsSL https://<owner>.github.io/pcapsql/pcapsql.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/pcapsql.gpg

# Add the repository (pick your distro codename, e.g. noble or bookworm)
echo "deb [signed-by=/usr/share/keyrings/pcapsql.gpg] \
https://<owner>.github.io/pcapsql/ noble main" \
  | sudo tee /etc/apt/sources.list.d/pcapsql.list

sudo apt update
sudo apt install pcapsql-datafusion
```

Codenames by release: Ubuntu 20.04 `focal`, 22.04 `jammy`, 24.04
`noble`; Debian 11 `bullseye`, 12 `bookworm`, 13 `trixie`.

## Verifying a release locally

```sh
KEYID=<key id from workflow log>
gpg --armor --export "$KEYID" | gpg --keyring ./trusted.gpg
# Fetch for a suite:
#   https://<owner>.github.io/pcapsql/dists/<codename>/Release{,.gpg}
gpgv --keyring ./trusted.gpg Release.gpg Release
```
