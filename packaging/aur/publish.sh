#!/usr/bin/env bash
set -euo pipefail
repo=$(git -C "$(dirname -- "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
revision=$(git -C "$repo" rev-parse HEAD)
upstream=https://github.com/originalsouth/browser-relay.git
is_current() {
    local latest
    latest=$(git ls-remote "$upstream" refs/heads/main | cut -f1) || {
        echo 'Could not check current main; publication stopped.' >&2
        exit 1
    }
    [[ -n "$latest" ]] || { echo 'Main was not found; publication stopped.' >&2; exit 1; }
    [[ "$latest" == "$revision" ]]
}
if ! is_current; then
    echo 'Skipping AUR publication: this is no longer the current main commit.'
    exit 0
fi
: "${AUR_SSH_PRIVATE_KEY:?Set the aur environment SSH private-key secret.}"
: "${AUR_KNOWN_HOSTS:?Set the aur environment verified known-hosts secret.}"
: "${AUR_GIT_NAME:?Set the aur environment commit-author name.}"
: "${AUR_GIT_EMAIL:?Set the aur environment commit-author email.}"
umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
printf '%s\n' "$AUR_SSH_PRIVATE_KEY" > "$work/key"
printf '%s\n' "$AUR_KNOWN_HOSTS" > "$work/known_hosts"
unset AUR_SSH_PRIVATE_KEY AUR_KNOWN_HOSTS
ssh-keygen -y -P '' -f "$work/key" >/dev/null
ssh-keygen -F aur.archlinux.org -f "$work/known_hosts" >/dev/null
cat > "$work/ssh_config" <<EOF_CONFIG
Host aur.archlinux.org
    HostName aur.archlinux.org
    User aur
    IdentityFile "$work/key"
    IdentitiesOnly yes
    IdentityAgent none
    BatchMode yes
    StrictHostKeyChecking yes
    UserKnownHostsFile "$work/known_hosts"
    GlobalKnownHostsFile /dev/null
    ConnectTimeout 20
EOF_CONFIG
cat > "$work/ssh" <<'EOF_SSH'
#!/usr/bin/env bash
exec ssh -F "$AUR_SSH_CONFIG" "$@"
EOF_SSH
chmod 700 "$work/ssh"
export AUR_SSH_CONFIG="$work/ssh_config"
export GIT_SSH="$work/ssh"
export GIT_SSH_VARIANT=ssh
unset GIT_SSH_COMMAND
# No artifact extraction or execution of the remote repository's PKGBUILD.
git clone --no-checkout ssh://aur@aur.archlinux.org/browser-relay-git.git "$work/aur"
cd "$work/aur"
if git show-ref --verify --quiet refs/remotes/origin/master; then
    git checkout -B master --track origin/master
elif [[ -z $(git for-each-ref --format='%(refname)' refs/remotes/origin/) ]]; then
    git symbolic-ref HEAD refs/heads/master
else
    echo 'AUR repository has an unexpected branch layout; refusing to replace it.' >&2
    exit 1
fi
python3 "$repo/packaging/aur/sync-recipe.py" "$repo/packaging/aur/browser-relay-git" "$PWD"
git add -- PKGBUILD .SRCINFO browser-relay.desktop
if git diff --cached --quiet; then
    echo 'AUR is already up to date.'
    exit 0
fi
git -c user.name="$AUR_GIT_NAME" -c user.email="$AUR_GIT_EMAIL" \
    commit -m "Update browser-relay-git from $revision"
if ! is_current; then
    echo 'Skipping push: main advanced while preparing the AUR update.'
    exit 0
fi
# A concurrent AUR edit must reject this push, never be overwritten.
git push origin HEAD:refs/heads/master
