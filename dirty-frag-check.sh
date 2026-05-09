#!/bin/bash
# dirty-frag-check.sh
# Quick check for the "Dirty Frag" Linux kernel local root vulns
# (CVE-2026-43284, IPsec esp4/esp6/ipcomp; CVE-2026-43500, AF_RXRPC).
# Safe to run anywhere, doesn't run exploit code, just inspects kernel
# version, module state, and any mitigations you've put in place.
#
# Usage:
#   ./dirty-frag-check.sh           # full report
#   ./dirty-frag-check.sh -q        # one-line summary (good for fleet runs)
#   ./dirty-frag-check.sh -h        # help
#
# Exit: 0 ok, 1 vulnerable, 2 unknown

set -u

QUIET=0
case "${1:-}" in
    -q|--quiet) QUIET=1 ;;
    -h|--help)
        sed -n '2,13p' "$0" | sed 's/^# \?//'
        exit 0
        ;;
esac

if [ -t 1 ] && [ "$QUIET" -eq 0 ]; then
    R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[0;33m'
    C=$'\033[0;36m'; B=$'\033[1m'; N=$'\033[0m'
else
    R=''; G=''; Y=''; C=''; B=''; N=''
fi

say() { [ "$QUIET" -eq 0 ] && echo -e "$@"; }
hr()  { say "${C}========================================================${N}"; }

host=$(hostname)
kernel=$(uname -r)
distro_id=$(awk -F= '/^ID=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release 2>/dev/null)
distro_ver=$(awk -F= '/^VERSION_ID=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release 2>/dev/null)
distro=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2); print $2}' /etc/os-release 2>/dev/null)
[ -z "$distro" ] && distro="unknown"

els=""
case "$kernel" in
    *tuxcare*|*.els*) els="TuxCare ELS" ;;
    *lve*|*plus*)     els="possibly CloudLinux/KernelCare" ;;
esac

hr
say "${B}${C} Dirty Frag / CVE-2026-43284 + CVE-2026-43500${N}"
hr
say "${B}Host:${N}    $host"
say "${B}Distro:${N}  $distro"
say "${B}Kernel:${N}  $kernel"
[ -n "$els" ] && say "${B}Support:${N} $els (confirm CVE coverage with vendor)"
say "${B}Date:${N}    $(date '+%Y-%m-%d %H:%M:%S %Z')"
say ""

# Vendor-published fixed kernel versions. Update as new advisories ship.
# Format: distro_id|major|fixed_version_substring
# Verify against your distro tracker; treat as best-effort.
fixed_for_running=""
case "${distro_id:-}" in
    almalinux|rhel|rocky|centos|cloudlinux)
        case "${distro_ver%%.*}" in
            8)  fixed_for_running="4.18.0-553.123.2.el8_10" ;;
            9)  fixed_for_running="5.14.0-611.54.3.el9_7" ;;
            10) fixed_for_running="6.12.0-124.55.2.el10_1" ;;
        esac
        ;;
esac

# --- 1. Vulnerable modules state ---
say "${B}[1] Vulnerable modules${N}"
mods="esp4 esp6 ipcomp ipcomp6 rxrpc"
loaded_list=""
available_list=""
for m in $mods; do
    if lsmod | awk '{print $1}' | grep -qx "$m"; then
        loaded_list="${loaded_list:+$loaded_list }$m"
    elif modinfo "$m" >/dev/null 2>&1; then
        available_list="${available_list:+$available_list }$m"
    fi
done

if [ -n "$loaded_list" ]; then
    say "    ${Y}loaded:${N}    $loaded_list"
fi
if [ -n "$available_list" ]; then
    say "    available: $available_list"
fi
if [ -z "$loaded_list" ] && [ -z "$available_list" ]; then
    say "    none of the relevant modules are loadable"
fi
say ""

# --- 2. Mitigations ---
say "${B}[2] Mitigations in place${N}"
found=0
blacklist_ok=""

# Authoritative: ask modprobe whether each module would load.
for m in $mods; do
    # only check ones that are at least available
    case " $available_list $loaded_list " in
        *" $m "*) ;;
        *) continue ;;
    esac
    mp_out=$(modprobe -n -v "$m" 2>&1)
    if echo "$mp_out" | grep -qE '(/bin/(false|true)|^install /bin|is blacklisted)'; then
        say "    ${G}modprobe blocked ($m)${N}"
        blacklist_ok="${blacklist_ok:+$blacklist_ok }$m"
        found=1
    fi
done

# Also list explicit blacklist files
for d in /etc/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d /run/modprobe.d; do
    [ -d "$d" ] || continue
    for f in "$d"/*.conf; do
        [ -f "$f" ] || continue
        if grep -qE '(install|blacklist)[[:space:]]+(esp4|esp6|ipcomp|ipcomp6|rxrpc)' "$f" 2>/dev/null; then
            say "    blacklist file: $f"
            found=1
        fi
    done
done

# KernelCare livepatch state (CloudLinux / TuxCare ELS / KernelCare+)
kc_present=0
kc_patched=0
if command -v kcarectl >/dev/null 2>&1; then
    kc_info=$(kcarectl --patch-info 2>/dev/null)
    [ -n "$kc_info" ] && kc_present=1
    if echo "$kc_info" | grep -qiE 'CVE-2026-43284|CVE-2026-43500|dirty.?frag'; then
        say "    ${G}KernelCare livepatch applied for Dirty Frag${N}"
        kc_patched=1
        found=1
    elif [ "$kc_present" -eq 1 ]; then
        say "    ${Y}KernelCare present, no Dirty Frag patch listed yet${N}"
    fi
fi

if command -v getenforce >/dev/null 2>&1; then
    say "    SELinux: $(getenforce)"
fi
if command -v aa-status >/dev/null 2>&1 && aa-status --enabled 2>/dev/null; then
    say "    AppArmor: enabled"
fi

[ "$found" -eq 0 ] && say "    none specific to these CVEs"
say ""

# --- 3. Kernel package vs running ---
say "${B}[3] Kernel package${N}"
pending_reboot=0
if [ -f /etc/debian_version ] && command -v dpkg >/dev/null 2>&1; then
    pkg_mgr=dpkg
elif command -v rpm >/dev/null 2>&1 && rpm -q kernel >/dev/null 2>&1; then
    pkg_mgr=rpm
elif command -v rpm >/dev/null 2>&1 && rpm -q kernel-core >/dev/null 2>&1; then
    pkg_mgr=rpm
elif command -v dpkg >/dev/null 2>&1; then
    pkg_mgr=dpkg
else
    pkg_mgr=""
fi

latest=""
if [ "$pkg_mgr" = "rpm" ]; then
    latest=$(rpm -q kernel --last 2>/dev/null | head -1 | awk '{print $1}')
    [ -z "$latest" ] && latest=$(rpm -q kernel-core --last 2>/dev/null | head -1 | awk '{print $1}')
    say "    installed: ${latest:-unknown}"
    say "    running:   $kernel"
    if [ -n "$latest" ] && ! echo "$latest" | grep -q "$kernel"; then
        say "    ${Y}newer kernel installed but not running, reboot needed${N}"
        pending_reboot=1
    fi
elif [ "$pkg_mgr" = "dpkg" ]; then
    installed=$(dpkg -l 2>/dev/null | awk '/^ii  linux-image-[0-9]/{print $2}' | sort -V | tail -3)
    say "    installed images:"
    [ "$QUIET" -eq 0 ] && echo "$installed" | sed 's/^/      /'
    say "    running:   $kernel"
    if [ -f /var/run/reboot-required ]; then
        say "    ${Y}/var/run/reboot-required exists, reboot needed${N}"
        pending_reboot=1
    fi
fi
say ""

# --- 4. Compare running kernel to vendor-fixed version (RHEL family only) ---
kver_ok=2  # 0 = older than fix, 1 = at/after fix, 2 = unknown
if [ -n "$fixed_for_running" ]; then
    say "${B}[4] Running kernel vs known fixed${N}"
    say "    expected at/after: $fixed_for_running"
    # rpmdev-vercmp / sort -V works well enough for el-style versions
    if printf '%s\n%s\n' "$fixed_for_running" "$kernel" | sort -V -C 2>/dev/null; then
        say "    ${G}running kernel is at or after the published fix${N}"
        kver_ok=1
    else
        say "    ${R}running kernel is older than the published fix${N}"
        kver_ok=0
    fi
    say ""
fi

# Check if a newer kernel package is available from the repo
on_latest=0
if command -v dnf >/dev/null 2>&1; then
    if dnf check-update kernel --quiet 2>/dev/null | grep -q '^kernel'; then
        on_latest=0
    else
        on_latest=1
    fi
elif command -v yum >/dev/null 2>&1; then
    if yum check-update kernel --quiet 2>/dev/null | grep -q '^kernel'; then
        on_latest=0
    else
        on_latest=1
    fi
elif command -v apt >/dev/null 2>&1; then
    if apt list --upgradable 2>/dev/null | grep -qE '^linux-image-[0-9]'; then
        on_latest=0
    else
        highest=$(dpkg -l 2>/dev/null | awk '/^ii  linux-image-[0-9]/{print $2}' | \
                  sed 's/^linux-image-//' | sort -V | tail -1)
        if [ -n "$highest" ] && [ "$highest" = "$kernel" ]; then
            on_latest=1
        fi
    fi
fi

# --- verdict ---
hr
say "${B} VERDICT${N}"
hr

verdict_text=""
exit_code=2

# Are all loadable modules blacklisted?
all_blocked=1
for m in $loaded_list $available_list; do
    case " $blacklist_ok " in
        *" $m "*) ;;
        *) all_blocked=0 ;;
    esac
done
[ -z "$loaded_list$available_list" ] && all_blocked=0

stopgap_block() {
    say "Stopgap (blacklist the affected modules):"
    say "    cat > /etc/modprobe.d/disable-dirty-frag.conf <<EOF"
    say "    install esp4 /bin/false"
    say "    install esp6 /bin/false"
    say "    install ipcomp /bin/false"
    say "    install ipcomp6 /bin/false"
    say "    install rxrpc /bin/false"
    say "    EOF"
    say "    rmmod rxrpc ipcomp6 ipcomp esp6 esp4 2>/dev/null"
}
upgrade_cmd() {
    if   command -v dnf >/dev/null 2>&1; then say "    dnf update kernel -y && reboot"
    elif command -v yum >/dev/null 2>&1; then say "    yum update kernel -y && reboot"
    elif command -v apt >/dev/null 2>&1; then say "    apt update && apt upgrade -y && reboot"
    fi
}

# Strongest signals first.
if [ "$kc_patched" -eq 1 ]; then
    verdict_text="${G}OK${N} - KernelCare livepatch covers Dirty Frag"
    exit_code=0
elif [ "$all_blocked" -eq 1 ] && [ -z "$loaded_list" ] && [ -n "$available_list" ]; then
    # Every reach-in module is blacklisted and none are loaded.
    # Bug can't be triggered regardless of kernel patch state.
    verdict_text="${Y}MITIGATED${N} - vulnerable modules blacklisted, cannot load"
    say "$verdict_text"
    say ""
    if [ "$kver_ok" -eq 0 ]; then
        say "Kernel is older than the published fix. Patch when you can:"
        upgrade_cmd
    elif [ "$kc_present" -eq 1 ]; then
        say "KernelCare livepatch for Dirty Frag not yet applied. Re-check later:"
        say "    kcarectl --update && kcarectl --patch-info"
    fi
    exit_code=0
elif [ "$kver_ok" -eq 0 ] && [ -n "$loaded_list" ] && [ "$on_latest" -eq 1 ]; then
    # Vendor lag: distro hasn't shipped the fix yet (or backports under a different build).
    verdict_text="${R}WAITING ON VENDOR PATCH${N} - kernel older than upstream fix, modules loaded ($loaded_list), no kernel upgrade available"
    say "$verdict_text"
    say ""
    say "Either your distro hasn't shipped the patched build yet, or it has"
    say "backported the fix under a different version. Cross-reference:"
    say "  https://access.redhat.com/security/cve/CVE-2026-43284"
    say ""
    stopgap_block
    exit_code=1
elif [ "$kver_ok" -eq 0 ] && [ -n "$loaded_list" ]; then
    verdict_text="${R}VULNERABLE${N} - kernel older than fix, modules loaded ($loaded_list), kernel upgrade available"
    say "$verdict_text"
    say ""
    say "Fix:"
    upgrade_cmd
    say ""
    stopgap_block
    exit_code=1
elif [ "$kver_ok" -eq 0 ] && [ "$on_latest" -eq 1 ]; then
    # Vendor lag: kernel is older than the AlmaLinux-published fix, but
    # no upgrade is available. Common on Rocky/CloudLinux which can trail
    # AlmaLinux by a build, or when the distro has backported under a
    # different version string. Don't claim VULNERABLE — we can't tell.
    verdict_text="${Y}WAITING ON VENDOR PATCH${N} - kernel older than upstream fix, no kernel upgrade available"
    say "$verdict_text"
    say ""
    say "Either your distro hasn't shipped the patched build yet, or it has"
    say "backported the fix under a different version. Cross-reference:"
    say "  https://access.redhat.com/security/cve/CVE-2026-43284"
    say ""
    say "Re-check later: dnf check-update kernel"
    say ""
    stopgap_block
    exit_code=1
elif [ "$kver_ok" -eq 0 ]; then
    verdict_text="${R}VULNERABLE${N} - running kernel is older than the published fix, kernel upgrade available"
    say "$verdict_text"
    say ""
    say "Fix:"
    upgrade_cmd
    say ""
    stopgap_block
    exit_code=1
elif [ "$pending_reboot" -eq 1 ]; then
    verdict_text="${Y}REBOOT NEEDED${N} - newer kernel installed, reboot to activate"
    say "$verdict_text"
    say ""
    say "Run: reboot"
    exit_code=1
elif [ "$kc_present" -eq 1 ] && [ "$kc_patched" -eq 0 ]; then
    # KernelCare-managed but the patch isn't in the livepatch set yet.
    # On these hosts the kernel package usually trails; livepatch is the canonical fix.
    verdict_text="${R}AT RISK${N} - KernelCare-managed host, Dirty Frag livepatch not yet applied"
    say "$verdict_text"
    say ""
    say "On KernelCare/TuxCare-managed hosts the fix arrives via livepatch."
    say "Re-check later (kcarectl --update; kcarectl --patch-info)."
    say ""
    stopgap_block
    exit_code=1
elif [ "$kver_ok" -eq 1 ] && [ -z "$loaded_list" ]; then
    verdict_text="${G}OK${N} - kernel at/after fixed version, no vulnerable modules loaded"
    exit_code=0
elif [ "$kver_ok" -eq 1 ]; then
    verdict_text="${G}LIKELY PATCHED${N} - kernel at/after fixed version (modules loaded but running kernel contains the fix)"
    say "$verdict_text"
    exit_code=0
elif [ "$all_blocked" -eq 1 ] && [ -z "$loaded_list" ]; then
    verdict_text="${G}OK${N} - all relevant modules blacklisted, cannot load"
    exit_code=0
elif [ -n "$loaded_list" ]; then
    if [ "$on_latest" -eq 1 ]; then
        verdict_text="${Y}LIKELY PATCHED${N} - modules loaded ($loaded_list), no kernel upgrade pending"
        say "$verdict_text"
        say ""
        say "Can't introspect a loaded module's patch level. Verify against your distro's tracker:"
        say "  https://ubuntu.com/security/CVE-2026-43284"
        say "  https://access.redhat.com/security/cve/CVE-2026-43284"
        exit_code=1
    else
        verdict_text="${R}VULNERABLE${N} - modules loaded ($loaded_list), kernel upgrade available"
        say "$verdict_text"
        say ""
        say "Fix:"
        upgrade_cmd
        say ""
        stopgap_block
        exit_code=1
    fi
elif [ -n "$available_list" ] && [ "$on_latest" -eq 1 ]; then
    # No fixed-version table for this distro (Ubuntu/Debian, TuxCare ELS, etc.).
    # Modules ship as available on every host — normal, not vulnerable.
    # Honest verdict is "we couldn't verify"; point to the right tracker.
    verdict_text="${Y}UNKNOWN${N} - kernel patch status not verifiable from version alone"
    say "$verdict_text"
    say ""
    say "Running: $kernel"
    say "Cross-reference to confirm the fix is in this kernel:"
    if [ "$els" = "TuxCare ELS" ]; then
        say "  https://tuxcare.com/cve/CVE-2026-43284"
        say "  (TuxCare ELS uses its own backport versioning; upstream version comparison won't apply.)"
    elif [ "${distro_id:-}" = "ubuntu" ] || [ "${distro_id:-}" = "debian" ]; then
        say "  https://ubuntu.com/security/CVE-2026-43284"
    else
        say "  https://access.redhat.com/security/cve/CVE-2026-43284"
    fi
    exit_code=2
elif [ -n "$available_list" ]; then
    verdict_text="${Y}AT RISK${N} - vulnerable modules available, kernel upgrade pending"
    say "$verdict_text"
    say ""
    say "Fix:"
    upgrade_cmd
    say ""
    stopgap_block
    exit_code=1
else
    verdict_text="${Y}UNKNOWN${N} - manual check needed"
    say "$verdict_text"
    exit_code=2
fi

# Branches that don't say verdict_text inline get it printed here.
# (kc_patched OK, kver_ok=1+no loaded OK, all_blocked+no loaded OK)
case "$verdict_text" in
    *"OK"*) say "$verdict_text" ;;
esac

say ""
say "Refs:"
say "  https://access.redhat.com/security/cve/CVE-2026-43284"
say "  https://access.redhat.com/security/cve/CVE-2026-43500"
say "  https://ubuntu.com/security/CVE-2026-43284"
say "  https://almalinux.org/blog/2026-05-07-dirty-frag/"
say "  https://blog.cloudlinux.com/dirty-frag-mitigation-and-kernel-update"
[ -n "$els" ] && say "  https://tuxcare.com/cve/CVE-2026-43284"
say ""

if [ "$QUIET" -eq 1 ]; then
    clean=$(echo -e "$verdict_text" | sed 's/\x1b\[[0-9;]*m//g')
    printf '%-40s %s\n' "$host" "$clean"
fi

exit $exit_code
