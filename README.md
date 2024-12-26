# Disconnected RSAT 

## Introduction

Disconnected RSAT is a launcher for the official Group Policy Manager, Certificate Authority and Certificat Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in.  

The tool works by injecting a C# library into MMC that will hook the `GetUserNameExW` API calls to trick MMC into believing that the logged on user is a domain user.  Hooks are also placed on the `NtCreateFile` API to redirect file paths that would typically be resolved via DFS to a specific domain controller instead.

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

### Launching Certifictate Template edittor

You can also directly edit certificate templates by usin the following command

```
DRSAT template ad.target.com
```

### Release

Precompiled binaries can be found on the [Releases](https://github.com/CCob/DRSAT/releases) page





