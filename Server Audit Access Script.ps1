<#
.SYNOPSIS
    Audit who can access this Windows server locally and via Remote Desktop.
    Ver 2.0 Alan Obrien
    aobrien@ehs.com

.DESCRIPTION
    This script collects:
    - Members of key local groups (Administrators, Users, Remote Desktop Users)
    - User Rights Assignments (who is allowed/denied logon locally and via RDP) with friendly names
    - Currently logged in users
    - Recent successful logon events (Security Event Log)
    - Definition for user: The CLIUSR account is a local user account created by the Failover Clustering feature when it is installed on Windows Server.

    Handles:
    - Well-known SIDs
    - Normal SIDs
    - Raw usernames (ex: CLIUSR)
    -For extra SID values go to here: https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids

    Must be run as Administrator.
#>

Write-Host "==============================="
Write-Host " SERVER ACCESS AUDIT SCRIPT"
Write-Host "===============================" -ForegroundColor Cyan

# -------------------------------
# 1. Local Group Memberships
# -------------------------------
Write-Host "`n[1] LOCAL GROUP MEMBERSHIPS" -ForegroundColor Yellow

$groups = @("Administrators","Remote Desktop Users","Users")

foreach ($group in $groups) {
    Write-Host "`nGroup: $group" -ForegroundColor Green

    $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue

    if ($members) {
        $members | Format-Table Name, ObjectClass, PrincipalSource -AutoSize
    }
    else {
        Write-Host "No members found (access may be controlled by User Rights Assignment or GPO)" -ForegroundColor DarkYellow
    }
}

# -------------------------------
# 2. User Rights Assignment
# -------------------------------
Write-Host "`n[2] USER RIGHTS ASSIGNMENTS (Logon Permissions)" -ForegroundColor Yellow

$tempFile = "$env:TEMP\secpol.cfg"
secedit /export /cfg $tempFile | Out-Null

$rights = @(
    "SeInteractiveLogonRight",
    "SeDenyInteractiveLogonRight",
    "SeRemoteInteractiveLogonRight",
    "SeDenyRemoteInteractiveLogonRight"
)

# Well-known SID mapping
$WellKnownSIDs = @{
    "S-1-5-32-544" = "BUILTIN\Administrators"
    "*S-1-5-32-544" = "BUILTIN\Administrators"
    "S-1-5-32-545" = "BUILTIN\Users"
    "*S-1-5-32-545" = "BUILTIN\Users"
    "S-1-5-32-551" = "BUILTIN\Backup Operators"
    "*S-1-5-32-551" = "BUILTIN\Backup Operators"
    "S-1-5-32-555" = "BUILTIN\Remote Desktop Users"
    "*S-1-5-32-555" = "BUILTIN\Remote Desktop Users"
    "S-1-5-32-546" = "BUILTIN\Guests"
    "*S-1-5-32-546" = "BUILTIN\Guests"
    "S-1-5-32-547" = "BUILTIN\Power Users"
    "*S-1-5-32-547" = "BUILTIN\Power Users"
    "S-1-5-9" = "BUILTIN\SECURITY_ENTERPRISE_CONTROLLERS_RID"
    "*S-1-5-9" = "BUILTIN\SECURITY_ENTERPRISE_CONTROLLERS_RID"
    "S-1-5-32-548" = "BUILTIN\DOMAIN_ALIAS_RID_ACCOUNT_OPS"
    "*S-1-5-32-548" = "BUILTIN\DOMAIN_ALIAS_RID_ACCOUNT_OPS"
    "S-1-5-32-549" = "BUILTIN\DOMAIN_ALIAS_RID_SYSTEM_OPS"
    "*S-1-5-32-549" = "BUILTIN\DOMAIN_ALIAS_RID_SYSTEM_OPS"
    "S-1-5-32-550" = "BUILTIN\DOMAIN_ALIAS_RID_PRINT_OPS"
    "*S-1-5-32-550" = "BUILTIN\DOMAIN_ALIAS_RID_PRINT_OPS"
}

foreach ($right in $rights) {

    Write-Host "`n$right :" -ForegroundColor Green
    $matches = Select-String -Path $tempFile -Pattern $right

    if ($matches) {
        foreach ($match in $matches) {

            $line = $match.Line -replace "$right\s*=\s*\*",""
            $entries = $line.Split(",") | ForEach-Object { $_.Trim() }

            foreach ($entry in $entries) {

                if (-not $entry) { continue }

                # Well-known SID
                if ($WellKnownSIDs.ContainsKey($entry)) {
                    Write-Host "$entry -> $($WellKnownSIDs[$entry])"
                }

                # Looks like a SID
                elseif ($entry -like "S-1-*") {
                    try {
                        $name = (New-Object System.Security.Principal.SecurityIdentifier $entry).Translate([System.Security.Principal.NTAccount])
                        Write-Host "$entry -> $name"
                    }
                    catch {
                        Write-Host "$entry -> <Unknown/Unable to resolve>" -ForegroundColor DarkYellow
                    }
                }

                # Otherwise treat as username (ex: CLIUSR)
                else {
                    $resolved = "$env:COMPUTERNAME\$entry"
                    Write-Host "$entry -> $resolved"
                }
            }
        }
    }
    else {
        Write-Host "<none>" -ForegroundColor DarkYellow
    }
}

# -------------------------------
# 3. Currently Logged-On Users
# -------------------------------
Write-Host "`n[3] CURRENTLY LOGGED-IN USERS" -ForegroundColor Yellow

try {
    quser
}
catch {
    Write-Host "Could not retrieve active user sessions." -ForegroundColor Red
}

# -------------------------------
# 4. Recent Successful Logons
# -------------------------------
Write-Host "`n[4] RECENT SUCCESSFUL LOGONS (Event ID 4624)" -ForegroundColor Yellow

Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20 |
ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Account     = $_.Properties[5].Value
        LogonType   = $_.Properties[8].Value
        Workstation = $_.Properties[11].Value
    }
} | Format-Table -AutoSize

# -------------------------------
# 5. Cleanup
# -------------------------------
Remove-Item $tempFile -ErrorAction SilentlyContinue

Write-Host "`n==============================="
Write-Host " AUDIT COMPLETE"
Write-Host "===============================" -ForegroundColor Cyan
