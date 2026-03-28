# Disconnected RSAT 

## Introduction

Disconnected RSAT is a launcher for the official Group Policy Manager, Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in.  

The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user.  Hooks are also placed on the `NtCreateFile` API to redirect file paths that would typically be resolved via DFS to a specific domain controller.

## Prerequisites  

Since Disconnected RSAT relies on the official snap-ins, you'll first need to install the Windows Remote Server Administration Tools (RSAT) on the non domain joined host you'll be operating from.

## Usage

mmc.exe is marked for auto elevation, therefore launching of `DRSAT.exe` should be performed from an elevated command prompt that has either got a relevant TGT with correct permissions imported into the same luid session or alternatively the session has been created using `runas /netonly`.  This will ensure that the relevant Kerberos tickets will be fetched automatically or NTLM credentials are used for outbound network connections when `runas /netonly` has been used.

### Launching Group Policy Manager

To launch GPM to target a specific Active Directory domain, simply supply the DNS domain name of the target.

```
DRSAT gpo ad.target.com
```

### Launching Certificate Authority

Whilst the certificate authority snap-in works when disconnected from the domain, template resolution doesn't work correctly, this can be solved by launching via DRSAT

```
DRSAT cert ad.target.com
```

### Launching Certificate Template editor

You can also directly edit certificate templates by using the following command

```
DRSAT template ad.target.com
```

## SOCKS Proxy / TCP-Only Environments

DRSAT supports operating through TCP-only SOCKS proxies where UDP traffic (and therefore cLDAP) cannot be routed.

### Domain Controller Discovery

When only a domain name is supplied, DRSAT uses a tiered discovery approach:

1. **cLDAP (UDP)** - The standard `DsGetDcNameW` API is attempted first. This works in direct network environments but will fail through TCP-only SOCKS proxies.
2. **TCP LDAP fallback** - If cLDAP fails, DRSAT falls back to connecting to `LDAP://{domain}/RootDSE` over TCP port 389 to resolve the serving domain controller via the `dnsHostName` attribute.
3. **Manual specification** - If both methods fail, the user is prompted to supply the DC hostname explicitly.

This same fallback logic applies both during initial startup and at runtime when MMC snap-ins internally call `DsGetDcNameW`.

### Explicit DC Mode

When a DC hostname is already known, it can be supplied directly. In this mode, all `DsGetDcNameW` calls within MMC are fully fabricated without any network calls, avoiding cLDAP entirely:

```
DRSAT gpo ad.target.com dc01.ad.target.com
```

This is the recommended approach when operating through a SOCKS proxy, as it eliminates all UDP dependencies.

### Release

Precompiled binaries can be found on the [Releases](https://github.com/CCob/DRSAT/releases) page





