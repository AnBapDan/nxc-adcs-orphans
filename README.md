# NetExec `adcs_orphans`

Detect orphaned AD CS certificate templates in Active Directory and optionally generate LDIF artifacts that may help recreate them when appropriate permissions exist.

`adcs_orphans` is a NetExec LDAP enumeration module for identifying **orphaned certificate templates**: templates that are still published by one or more Enterprise CAs but no longer exist in the `Certificate Templates` container in Active Directory. 
NetExec is an open-source network execution and assessment tool, and this module is intended to extend LDAP-based AD CS assessment capabilities.

## Why this matters

In some AD CS environments, a CA can continue to reference certificate templates that no longer have a corresponding `pKICertificateTemplate` object in the directory. 
That mismatch can expose interesting configuration drift, weak change control, or paths worth reviewing during an AD CS security assessment.

This module helps operators quickly answer:

- Which templates are published by the CA.
- Which templates actually exist in AD.
- Which published templates are orphaned.

## Features

- Enumerate published certificate templates from Enterprise CA objects.
- Enumerate existing certificate template objects from the AD CS configuration partition.
- Identify orphaned published templates.
- Optionally generates LDIF files for:
  - `msPKI-Enterprise-Oid` objects
  - `pKICertificateTemplate` objects
- Prints example `impacket-dacledit` commands to help review ACLs on relevant AD CS containers.

## Quick start

Basic enumeration:

```bash
nxc ldap <DC_IP> -u <USERNAME> -p '<PASSWORD>' -M adcs_orphans
```

Generate LDIF artifacts:

```bash
nxc ldap <DC_IP> -u <USERNAME> -p '<PASSWORD>' -M adcs_orphans -o GENERATE_FILES=TRUE
```

Example:

```bash
nxc ldap 10.10.10.10 -u auditor -p 'Password123!' -M adcs_orphans
```

Example with file generation:

```bash
nxc ldap 10.10.10.10 -u auditor -p 'Password123!' -M adcs_orphans -o GENERATE_FILES=TRUE
```

## Example output

```text
Orphaned published templates:
    OldCertificateTemplate

Base enterprise OID: 1.3.6.1.4.1.311.21.8.1234567

LDIF written to oid_ldif_OldCertificateTemplate.ldif
LDIF written to template_ldif_OldCertificateTemplate.ldif

To Check for ACLs that allow for OID creation, use:
impacket-dacledit -target-dn 'CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' 'corp.local/user' -dc-ip 10.10.10.10

To Check for ACLs that allow for Template creation, use:
impacket-dacledit -target-dn 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' 'corp.local/user' -dc-ip 10.10.10.10
```

## How it works

The module performs three main checks:

1. Queries `CN=Enrollment Services,...` for `certificateTemplates` values published by Enterprise CA objects.
2. Queries `CN=Certificate Templates,...` for existing `pKICertificateTemplate` objects.
3. Compares both lists and reports templates that are published but missing from the template container.

When `GENERATE_FILES=TRUE` is enabled, the module also:

1. Retrieves an enterprise OID base from the AD CS OID container.
2. Generates a unique OID per orphaned template.
3. Builds LDIF content for a new `msPKI-Enterprise-Oid` object.
4. Builds LDIF content for a new `pKICertificateTemplate` object.
5. Writes helper binary files referenced by the template LDIF.

## Options

| Option | Default | Description |
|---|---:|---|
| `GENERATE_FILES` | `FALSE` | When set to `TRUE`, writes LDIF files and supporting binary files for each orphaned template. |

## Generated files

When file generation is enabled, the module may create:

```text
oid_ldif_<TemplateName>.ldif
template_ldif_<TemplateName>.ldif
pKIExpirationPeriod.bin
pKIOverlapPeriod.bin
```

These artifacts are intended as scaffolding for further **authorized** testing. They do not bypass Active Directory permissions, CA configuration, enrollment controls, or issuance requirements.

## Permissions and validation

Detecting an orphaned template does **not** automatically mean the condition is exploitable.

For practical follow-up, the testing account would typically need sufficient rights over one or both of these containers:

```text
CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,<DOMAIN_DN>
```

```text
CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<DOMAIN_DN>
```

The module prints `impacket-dacledit` examples so you can review whether the current principal has relevant rights such as object creation or other impactful delegated permissions.

## Use cases

This module may be useful during:

- AD CS posture reviews
- Active Directory configuration drift analysis
- Red team infrastructure assessments
- Certificate Services attack-surface mapping
- Lab research into dangling template recovery scenarios

It is especially useful when you suspect template cleanup was incomplete and want to verify whether a CA still references objects that are no longer present in the directory.

## Installation

Save the module as:

```text
adcs_orphans.py
```

Then place it in your NetExec modules path, commonly something like:

```bash
~/.nxc/modules/
```

Directory layout and module-loading behavior can vary by installation, so adapt the path to your local NetExec setup.

## Notes

- The generated template LDIF uses a basic client-authentication-style template structure.
- OIDs are generated randomly and checked for collision before files are written.
- If an OID collision is detected, rerun the module.
- Always review generated LDIF content before using it.
- Test in a controlled environment first.

## Educational use and disclaimer

This module is provided **for educational purposes, authorized security testing, and defensive AD CS research only**.

Do not use it against systems, domains, or certificate services infrastructure without explicit permission. You are solely responsible for how you use this code, and the author is **not responsible** for misuse, damage, unauthorized activity, or any consequences resulting from its use.

## References

- [NetExec GitHub](https://github.com/Pennyw0rth/NetExec)
- [NetExec Wiki](https://www.netexec.wiki/)