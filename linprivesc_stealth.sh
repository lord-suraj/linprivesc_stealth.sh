#!/usr/bin/env bash
# Linux PrivEsc Stealth Enumerator (Pure Red Team)
# Focus: misconfigured binaries, writable paths, cron/systemd, capabilities, groups, containers, creds
# Output: results folder under /tmp with findings + quick on-screen summary
# Banner: Dark Lord

banner() {
cat <<'EOF'
 _______       ___      .______      __  ___ 
|       \     /   \     |   _  \    |  |/  / 
|  .--.  |   /  ^  \    |  |_)  |   |  '  /  
|  |  |  |  /  /_\  \   |      /    |    <   
|  '--'  | /  _____  \  |  |\  \----|  .  \  
|_______/ /______  \.______| `._________\__\ 
|  |      /  __  \  |   _  \    |       \    
|  |     |  |  |  | |  |_)  |   |  .--.  |   
|  |     |  |  |  | |      /    |  |  |  |   
|  `----.|  `--'  | |  |\  \----|  '--'  |   
|_______| \______/  | _| `._____|_______/    
                                             
    PrivEsc Enumerator - Dark Lord ⚔️

EOF
}

banner   # show banner at start

set -u

START_TS="$(date +%s)"
HOST="$(hostname)"
OUTDIR="/tmp/rt-linpx-${HOST}-$(date +%s)"
mkdir -p "$OUTDIR"

# -------- Helpers --------
sec() { printf "\n===== %s =====\n" "$1" | tee -a "$OUTDIR/summary.txt"; }
say() { echo "$@" | tee -a "$OUTDIR/summary.txt"; }
log() { echo "$@" >>"$OUTDIR/run.log"; }
have() { command -v "$1" >/dev/null 2>&1; }
save() { # cmd, file
  local _cmd="$1"; local _file="$2"
  bash -c "$_cmd" >"$_file" 2>/dev/null
}

# Small safe prune set (avoid noisy/volatile FS)
PRUNE_DIRS="-path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap"

# -------- 0. Context --------
sec "Context"
{
  echo "[*] When prompt shows '$' you are NOT root. Root should be '#'."
  echo "[*] Always verify with: id -u  (0 means root)."
} | tee "$OUTDIR/README.txt"

{
  echo "Time:           $(date -Is)"
  echo "User:           $(whoami)"
  echo "UID,GIDs:       $(id)"
  echo "Hostname:       $HOST"
  echo "Kernel:         $(uname -a)"
  echo "OS:             $( (cat /etc/os-release || true) | tr -d '\r')"
  echo "Groups:         $(groups 2>/dev/null || true)"
  echo "PATH:           $PATH"
} | tee "$OUTDIR/context.txt"

# -------- 1. SUID / SGID Binaries --------
sec "SUID / SGID binaries"
SUID_FILE="$OUTDIR/suid.txt"
SGID_FILE="$OUTDIR/sgid.txt"

# Limit to current filesystem with -xdev; prune volatile dirs
save "find / -xdev \\( $PRUNE_DIRS \\) -prune -o -perm -4000 -type f -printf '%M %u:%g %p\n'" "$SUID_FILE"
save "find / -xdev \\( $PRUNE_DIRS \\) -prune -o -perm -2000 -type f -printf '%M %u:%g %p\n'" "$SGID_FILE"

say "[+] SUID count: $(wc -l <"$SUID_FILE" 2>/dev/null || echo 0)  -> $SUID_FILE"
say "[+] SGID count: $(wc -l <"$SGID_FILE" 2>/dev/null || echo 0)  -> $SGID_FILE"

# Flag likely-interesting SUIDs (GTFOBins suspects)
grep -E '/(bash|sh|find|vim|less|more|nmap|tar|cp|mv|python|perl|ruby|awk|tee|mount|umount|pkexec)$' "$SUID_FILE" >"$OUTDIR/suid_suspects.txt" || true
if [ -s "$OUTDIR/suid_suspects.txt" ]; then
  say "[!] Suspicious SUID candidates (check GTFOBins): $OUTDIR/suid_suspects.txt"
fi

# -------- 2. Writable Files & Dirs (Privilege Boundaries) --------
sec "Writable files & directories (focus paths)"
WRIT_DIRS="$OUTDIR/writable_dirs_focus.txt"
WRIT_FILES="$OUTDIR/writable_files_focus.txt"

# Focus common escalation zones only (stealth): /etc, /usr/local, /opt, /var/www, /home
save "find /etc /usr/local /opt /var/www /home -xdev \\( $PRUNE_DIRS \\) -prune -o -type d -writable -printf '%M %u:%g %p\n'" "$WRIT_DIRS"
save "find /etc /usr/local /opt /var/www /home -xdev \\( $PRUNE_DIRS \\) -prune -type f -writable -printf '%M %u:%g %p\n'" "$WRIT_FILES"

say "[+] Writable dirs (focus): $(wc -l <"$WRIT_DIRS" 2>/dev/null || echo 0)"
say "[+] Writable files (focus): $(wc -l <"$WRIT_FILES" 2>/dev/null || echo 0)"

# -------- 3. Cron & Timers --------
sec "Cron jobs & systemd timers"
CRON_OUT="$OUTDIR/cron.txt"
save "crontab -l" "$OUTDIR/crontab_user.txt"
save "ls -la /etc/cron.* /var/spool/cron 2>/dev/null" "$CRON_OUT"
save "grep -R --line-number --null-data . /etc/cron.* 2>/dev/null" "$OUTDIR/cron_grep.txt"

say "[+] User crontab: $OUTDIR/crontab_user.txt"
say "[+] System cron listings: $CRON_OUT"

# systemd timers & enabled units
if have systemctl; then
  save "systemctl list-timers --all" "$OUTDIR/systemd_timers.txt"
  save "systemctl list-unit-files --type=service --state=enabled" "$OUTDIR/systemd_enabled.txt"
  say "[+] systemd timers: $OUTDIR/systemd_timers.txt"
  say "[+] Enabled services: $OUTDIR/systemd_enabled.txt"
  # Extract ExecStart targets and check writability
  EXEC_LIST="$OUTDIR/systemd_execstart.txt"
  save "grep -R '^ExecStart=' /etc/systemd/system /lib/systemd/system 2>/dev/null | sed 's/^.*ExecStart=\\(\\S\\+\\).*$/\\1/' | sort -u" "$EXEC_LIST"
  # Check if any ExecStart targets live in writable dirs/files we control
  join -1 1 -2 1 <(awk '{print $3}' "$WRIT_DIRS" | sort -u) <(dirname $(cat "$EXEC_LIST" 2>/dev/null) 2>/dev/null | sort -u) >/dev/null 2>&1 || true
  say "[i] ExecStart targets enumerated: $EXEC_LIST (manually check if any path is writable)"
fi

# -------- 4. Capabilities --------
sec "File capabilities"
if have getcap; then
  CAP_FILE="$OUTDIR/capabilities.txt"
  save "getcap -r / 2>/dev/null" "$CAP_FILE"
  say "[+] Capabilities: $CAP_FILE"
  # Flag dangerous ones
  grep -E 'cap_(setuid|setgid|sys_admin|dac_override|dac_read_search|net_raw|\ball\b)' "$CAP_FILE" >"$OUTDIR/capabilities_suspects.txt" 2>/dev/null || true
  if [ -s "$OUTDIR/capabilities_suspects.txt" ]; then
    say "[!] Suspicious capabilities: $OUTDIR/capabilities_suspects.txt"
  fi
else
  say "[i] getcap not present."
fi

# -------- 5. PATH Hijack Opportunities --------
sec "PATH hijack opportunities"
PATH_DIRS_FILE="$OUTDIR/path_dirs.txt"
echo "$PATH" | tr ':' '\n' | awk 'NF' | sed 's#/$##' | sort -u >"$PATH_DIRS_FILE"
WRIT_IN_PATH="$OUTDIR/writable_path_dirs.txt"
> "$WRIT_IN_PATH"
while IFS= read -r d; do
  [ -d "$d" ] || continue
  [ -w "$d" ] && printf "%s\n" "$d" >>"$WRIT_IN_PATH"
done <"$PATH_DIRS_FILE"

say "[+] PATH dirs listed: $PATH_DIRS_FILE"
if [ -s "$WRIT_IN_PATH" ]; then
  say "[!] Writable PATH dirs (potential command hijack): $WRIT_IN_PATH"
fi

# -------- 6. Groups & Special Subsystems --------
sec "Privileged groups & subsystems"
GRP_NOTE="$OUTDIR/groups_note.txt"
{
  echo "Groups: $(id -nG 2>/dev/null || true)"
  echo "Docker socket: $( [ -S /var/run/docker.sock ] && echo 'PRESENT' || echo 'not present' )"
  echo "User in docker group? $(id -nG | grep -qw docker && echo yes || echo no)"
  echo "User in lxd group?    $(id -nG | grep -qw lxd && echo yes || echo no)"
  echo "NFS mounts: $(mount | grep -i nfs | wc -l) found"
} | tee "$GRP_NOTE"

# Quick container breakout hints (do not execute)
HINTS="$OUTDIR/quick_hints.txt"
{
  echo "[Hints] If in 'docker' group: you can start a privileged container and mount / to write /etc/sudoers or /root/.ssh."
  echo "[Hints] If in 'lxd' group: init + image import + mount host paths for write access."
} > "$HINTS"
say "[i] Subsystem hints recorded: $HINTS"

# -------- 7. Credentials of Interest (stealth-limited search) --------
sec "Credentials (limited, focused)"
CREDS_OUT="$OUTDIR/creds_grep.txt"
# limit to shallow depths to stay stealthy
{ 
  grep -RniE 'pass(word)?=|token=|secret=|aws_secret|aws_access|authorization:|x-api-key' /etc /opt /var/www 2>/dev/null | head -n 500
  find /home -maxdepth 3 -type f -name ".*" -o -name "*.env" -o -name "*.ini" -o -name "*.conf" 2>/dev/null | xargs -r grep -niE 'pass|token|secret' 2>/dev/null | head -n 500
} > "$CREDS_OUT"
say "[+] Cred grep (limited) saved: $CREDS_OUT"

# SSH keys & known_hosts
save "find /home -maxdepth 3 -type f -name 'id_rsa' -o -name 'id_ed25519' -o -name 'known_hosts' -o -name 'authorized_keys'" "$OUTDIR/ssh_artifacts.txt"
say "[+] SSH artifacts: $OUTDIR/ssh_artifacts.txt"

# -------- 8. Services/Listening (for pivots) --------
sec "Listening sockets (pivot awareness)"
if have ss; then
  save "ss -tulnp" "$OUTDIR/listen.txt"
  say "[+] Listening sockets: $OUTDIR/listen.txt"
else
  save "netstat -tulnp" "$OUTDIR/listen.txt"
  say "[+] Listening sockets (netstat): $OUTDIR/listen.txt"
fi

# -------- 9. Kernel (for LPE last resort) --------
sec "Kernel & potential LPE (last resort)"
KERN_FILE="$OUTDIR/kernel.txt"
{
  uname -a
  command -v lsmod >/dev/null && lsmod | head -n 50
} >"$KERN_FILE" 2>/dev/null
say "[i] Kernel info saved: $KERN_FILE (use only safe, approved LPEs if ROE allows)."

# -------- 10. Quick Findings Summary --------
sec "Actionable Summary"
FINDINGS="$OUTDIR/FINDINGS.txt"
> "$FINDINGS"

add_finding() { echo "FINDING: $*" | tee -a "$FINDINGS" >/dev/null; }

# 10.1 Suspicious SUIDs
if [ -s "$OUTDIR/suid_suspects.txt" ]; then
  add_finding "Suspicious SUID binaries present -> $OUTDIR/suid_suspects.txt (try GTFOBins shell escapes)."
fi

# 10.2 Writable PATH dirs
if [ -s "$WRIT_IN_PATH" ]; then
  add_finding "One or more PATH directories are writable -> $WRIT_IN_PATH (potential command hijack if root executes relative commands)."
fi

# 10.3 Writable cron/system paths
grep -E '^.*/(cron|systemd)/' "$WRIT_FILES" >/dev/null 2>&1 && \
  add_finding "Writable files under cron/system paths (check $WRIT_FILES) — if executed by root, inject payload."

# 10.4 Capabilities suspects
if [ -s "$OUTDIR/capabilities_suspects.txt" ]; then
  add_finding "Dangerous file capabilities -> $OUTDIR/capabilities_suspects.txt (cap_setuid/sys_admin/etc)."
fi

# 10.5 Docker/LXD
id -nG | grep -qw docker && add_finding "User is in docker group — container breakout to root is likely."
id -nG | grep -qw lxd    && add_finding "User is in lxd group — LXD breakout is likely."

# 10.6 SSH artifacts
[ -s "$OUTDIR/ssh_artifacts.txt" ] && add_finding "SSH private keys/authorized_keys/known_hosts found -> $OUTDIR/ssh_artifacts.txt (try lateral)."

# 10.7 Creds
[ -s "$CREDS_OUT" ] && add_finding "Potential credentials in configs -> $CREDS_OUT (review carefully; pivot or escalate)."

# 10.8 Writable in /usr/local/bin (often used by services)
grep -q "/usr/local/bin" "$WRIT_FILES" 2>/dev/null && \
  add_finding "Writable files in /usr/local/bin -> $WRIT_FILES (check if referenced by systemd ExecStart/cron)."

# 10.9 NFS
mount | grep -qi nfs && add_finding "NFS mounts present — check export options (no_root_squash misconfigs)."

# Final pointers
echo "
[Next Steps Guidance]
- If SUID suspect present: look up exact GTFOBins primitive for that binary; prefer non-interactive shell escapes.
- If writable PATH dir: identify any root-executed scripts/cron/services that call commands without absolute paths; place shim.
- If cron/systemd writable script: inject minimal one-liner (e.g., add SSH key / run bash with setuid), then restore.
- If capabilities suspect (cap_setuid etc.): attempt setuid(0) in the interpreter to pop root.
- If docker/lxd group: perform benign breakout (mount /, write authorized_keys for root).
- If creds found: try SSH/reuse for lateral; re-check sudo -l under new users.
" | tee -a "$FINDINGS" >/dev/null

say "[✔] Done. All artifacts under: $OUTDIR"
END_TS="$(date +%s)"
say "[i] Runtime: $((END_TS-START_TS))s"
