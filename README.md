# php2shell-check

Fast local triage for PHP2Shell (CVE-2026-109618 and CVE-2026-109619). Run it on a host you have access to and it tells you, in Metasploit CheckCode terms, whether the PHP is actually exploitable. Single-file Ruby, standard library only, no gems.

## PHP2Shell

Two PHP core flaws, CVE-2026-109618 and CVE-2026-109619, CVSS v4.0 9.2, chained for unauthenticated RCE. Fixed upstream on 2026-10-21 in 8.2.35, 8.3.36, 8.4.27, and 8.5.12. The bug is in the interpreter, so any app on an unpatched build is a target regardless of its own code.

## Usage

```
ruby php2shell_check.rb                   # every PHP on PATH
ruby php2shell_check.rb /usr/bin/php8.3   # one binary
ruby php2shell_check.rb --plain           # non-msf output
```

## Output

```
[*] /usr/bin/php - PHP 8.4.26 (cli)
[+] /usr/bin/php - The target is vulnerable. 8.4.26 is below the upstream fix 8.4.27 and no package changelog names the CVE
```

Verdicts map to msf CheckCode: a finding is `The target is vulnerable.` (green `[+]`), a patched host is `The target is not exploitable.` (`[*]`), and anything it cannot confirm is `Cannot reliably check exploitability.`

## Exit codes

Worst result sets the code, so you can fan it out across a fleet:

- 0, all patched
- 1, at least one vulnerable
- 2, review needed, or no PHP found

## No false positives on backported builds

`php -v` lies on Debian, Ubuntu, and RHEL. They backport the fix and keep the old version string, so a patched box still prints something like `8.3.6`, far below the `8.3.36` upstream fix. A version-only check reports that as vulnerable and you burn an engagement chasing a dead lead. When the version looks low, this reads the dpkg or rpm changelog for the CVE IDs before calling it. If the fix is backported, it says so. Clean findings, no false positives to walk back in the report.

## Scope

- Local only. Run it on a foothold or an authorized host, not against a URL.
- Detection only. No network traffic, no exploitation.
- Authorized use only.
