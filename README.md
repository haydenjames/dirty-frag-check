# Dirty Frag check (CVE-2026-43284 / CVE-2026-43500)

Read-only checker for the "Dirty Frag" Linux kernel local-root vulns
([CVE-2026-43284](https://access.redhat.com/security/cve/CVE-2026-43284),
[CVE-2026-43500](https://access.redhat.com/security/cve/CVE-2026-43500)).
Looks at running kernel version vs the vendor-published fix, the load
state of the affected IPsec / AF\_RXRPC modules, KernelCare livepatch
state, and any modprobe blacklist you've put in place, then prints a
verdict. It does not run exploit code.

Companion to [CVE-2026-31431-check](https://github.com/haydenjames/CVE-2026-31431-check).

> Heads up: this is a heuristic. A green verdict isn't a guarantee. Cross-reference
> with your distro's advisory before you call a host safe. MIT, no warranty.

## Quick run

Always-latest release (recommended — auto-tracks bug fixes):

```bash
curl -fsSL https://github.com/haydenjames/dirty-frag-check/releases/latest/download/dirty-frag-check.sh | bash
```

If you'd rather read it first (sensible on production):

```bash
curl -fsSLO https://github.com/haydenjames/dirty-frag-check/releases/latest/download/dirty-frag-check.sh
less dirty-frag-check.sh
chmod +x dirty-frag-check.sh && ./dirty-frag-check.sh
```

For change-control or audit (immutable, won't pick up future fixes), pin
to a specific release tag instead — e.g.
`https://raw.githubusercontent.com/haydenjames/dirty-frag-check/v1.0.0/dirty-frag-check.sh`.

`-q` gives a one-line summary for fleet runs. `-h` for help. Exit 0 ok, 1 vulnerable, 2 unknown.

## Fleet usage

```bash
# parallel-ssh
parallel-ssh -h hosts.txt -i 'bash -s -- -q' < dirty-frag-check.sh

# ansible
ansible all -m script -a "dirty-frag-check.sh -q"
```

Exit codes (0 ok, 1 vulnerable, 2 unknown) work with anything that aggregates by status.

## Requirements

bash 4+, plus the usual `awk`/`grep`/`sed`/`lsmod`/`modprobe`. No root
required for the check itself. Applying mitigations does need root.

## What it checks

1. **Module state.** Whether the modules implicated by the advisory —
   `esp4`, `esp6`, `ipcomp`, `ipcomp6` (CVE-2026-43284) and `rxrpc`
   (CVE-2026-43500) — are loaded, available, or absent.
2. **Mitigations.** Looks for modprobe blacklist files and verifies the
   blacklist actually wins via `modprobe -n -v`. Reports SELinux and
   AppArmor status. Detects KernelCare livepatch via `kcarectl --patch-info`.
3. **Kernel package vs running.** Catches the case where you've installed
   a patched kernel but haven't rebooted into it.
4. **Running kernel vs known-fixed version.** For RHEL-family distros
   (AlmaLinux, Rocky, RHEL, CloudLinux), compares `uname -r` against the
   vendor-published fixed version for that release. Best-effort; verify
   against your distro tracker.

## Verdicts

- **OK** — KernelCare livepatch is applied, the running kernel is at or
  after the published fix, or all relevant modules are blacklisted.
- **REBOOT NEEDED** — patched kernel installed, you're still on the old one.
- **VULNERABLE** — affected module loaded with no fixed kernel running.
- **LIKELY PATCHED** — module loaded but the running kernel is at the
  fixed version. The script can't introspect a loaded module to tell a
  fixed version from a vulnerable one, so this verdict defers to the
  package metadata.
- **AT RISK** — affected modules loadable and nothing's stopping them.
- **UNKNOWN** — manual check needed.

## Stopgap mitigation

For CVE-2026-43500 (rxrpc) the upstream fix has lagged on some distros
at time of writing. If you need to close the second exploit path before
a kernel update is available, blacklist the modules:

```bash
sudo tee /etc/modprobe.d/disable-dirty-frag.conf <<'EOF'
install esp4 /bin/false
install esp6 /bin/false
install ipcomp /bin/false
install ipcomp6 /bin/false
install rxrpc /bin/false
EOF
sudo rmmod rxrpc ipcomp6 ipcomp esp6 esp4 2>/dev/null || true
```

If `rmmod` says "module is in use", something on the box actively uses
IPsec or AF\_RXRPC (some VPNs, AFS clients, strongSwan, Libreswan).
Don't force-unload it. Patch the kernel and reboot instead.

KernelCare / TuxCare ELS users: livepatches for CVE-2026-43284 cover
this without a reboot. Check `kcarectl --patch-info`.

## Targets

Aimed at AlmaLinux 8/9/10, Rocky, RHEL, CloudLinux 8/9/10, Ubuntu,
Debian, and CentOS 7 (TuxCare ELS / KernelCare). The fixed-version
table is RHEL-family-specific; Ubuntu/Debian fall back to
package-manager freshness. Confirm any green verdict against your
distro's tracker.

## Discussion

- AlmaLinux advisory: [Dirty Frag](https://almalinux.org/blog/2026-05-07-dirty-frag/)
- CloudLinux / KernelCare: [mitigation and kernel update](https://blog.cloudlinux.com/dirty-frag-mitigation-and-kernel-update)
- cPanel: [security advisory](https://support.cpanel.net/hc/en-us/articles/40313772552727)
- Companion checker: [CVE-2026-31431-check](https://github.com/haydenjames/CVE-2026-31431-check)
- Issues: [GitHub](https://github.com/haydenjames/dirty-frag-check/issues)

## License

MIT — see [LICENSE](LICENSE).
