<#
.SYNOPSIS
    Verschiebt verwaiste FSLogix-Profile aus dem Report in einen Quarantaeneordner.

.DESCRIPTION
    Liest den vom Find-OrphanedFSLogixProfiles.ps1 erzeugten Report und verschiebt
    die ausgewaehlten Profile in eine datierte Quarantaene-Unterstruktur.
    Standardmaessig werden nur Profile mit Status 'Deleted' verschoben.
    Mit -IncludeStatus kannst du zusaetzlich 'Disabled' beruecksichtigen.
    'Renamed' und 'ADError' werden nie automatisch verschoben.

    Unterstuetzt -WhatIf und -Confirm. Schreibt eine CSV-Audit-Logdatei mit dem
    Resultat jeder Operation.

.PARAMETER ReportCsv
    Pfad zur FSLogix-Report-*.csv aus dem Find-Skript.

.PARAMETER ProfileRoot
    Wurzelpfad mit den FSLogix-Profilordnern (selber Wert wie im Find-Skript).
    Vollpfad wird aus ProfileRoot + FolderName gebildet.

.PARAMETER QuarantineRoot
    Wurzelpfad fuer die Quarantaene. Eine Unterstruktur \yyyyMMdd-HHmmss\ wird angelegt.

.PARAMETER IncludeStatus
    Zu verschiebende Statuswerte. Default: Deleted. Erlaubt: Deleted, Disabled, Renamed.
    Renamed = der alte Profilordner nach einem AD-Account-Rename. FSLogix hat parallel
    einen neuen Ordner '<NeuerSam>_<SID>' angelegt, der alte ist physisch verwaist.

.PARAMETER CheckOpenFiles
    Prueft ueber Get-SmbOpenFile, ob die VHDX/VHD im Profil aktuell geoeffnet ist.
    Funktioniert nur, wenn das Skript auf dem Fileserver mit den Freigaben laeuft.

.EXAMPLE
    .\Move-OrphanedFSLogixProfiles.ps1 -ReportCsv .\FSLogix-Report-20260506-093000.csv `
        -ProfileRoot 'D:\FSLogixProfiles' -QuarantineRoot 'D:\FSLogix-Quarantine' -WhatIf

.EXAMPLE
    .\Move-OrphanedFSLogixProfiles.ps1 -ReportCsv .\FSLogix-Report-20260506-093000.csv `
        -ProfileRoot 'D:\FSLogixProfiles' -QuarantineRoot 'D:\FSLogix-Quarantine' `
        -IncludeStatus Deleted,Disabled
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)]
    [string]$ReportCsv,

    [Parameter(Mandatory)]
    [string]$ProfileRoot,

    [Parameter(Mandatory)]
    [string]$QuarantineRoot,

    [ValidateSet('Deleted','Disabled','Renamed')]
    [string[]]$IncludeStatus = @('Deleted'),

    [switch]$CheckOpenFiles
)

if (-not (Test-Path $ProfileRoot)) { throw "ProfileRoot nicht gefunden: $ProfileRoot" }

if (-not (Test-Path $ReportCsv)) { throw "ReportCsv nicht gefunden: $ReportCsv" }

# Relativen Pfad zu absolut aufloesen, sonst liefert Split-Path -Parent einen
# leeren String und das Audit-Log-Pfad-Bauen schlaegt fehl.
$ReportCsv = (Resolve-Path -LiteralPath $ReportCsv).ProviderPath

$rows = Import-Csv -Path $ReportCsv -Encoding UTF8
$candidates = $rows | Where-Object { $_.Status -in $IncludeStatus }

if (-not $candidates) {
    Write-Host "Keine Profile mit Status $($IncludeStatus -join '/') im Report. Nichts zu tun."
    return
}

$session       = Get-Date -Format 'yyyyMMdd-HHmmss'
$sessionDir    = Join-Path $QuarantineRoot $session
$auditLogPath  = Join-Path (Split-Path $ReportCsv -Parent) "FSLogix-Move-$session.log.csv"

if ($PSCmdlet.ShouldProcess($sessionDir, 'Quarantaene-Sessionordner anlegen')) {
    New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null
}

Write-Host ""
Write-Host "Verschiebe $($candidates.Count) Profile (Status: $($IncludeStatus -join ', '))"
Write-Host "Quelle (Beispiel): $(Join-Path $ProfileRoot $candidates[0].FolderName)"
Write-Host "Ziel:              $sessionDir"
Write-Host ""

$auditRows = New-Object System.Collections.Generic.List[object]

foreach ($row in $candidates) {
    $src = Join-Path $ProfileRoot $row.FolderName
    $dst = Join-Path $sessionDir $row.FolderName

    $entry = [ordered]@{
        Timestamp     = (Get-Date).ToString('s')
        Status        = $row.Status
        FolderName    = $row.FolderName
        SamFromFolder = $row.SamFromFolder
        Source        = $src
        Destination   = $dst
        Result        = $null
        Note          = $null
    }

    if (-not (Test-Path -LiteralPath $src)) {
        $entry.Result = 'Skipped'
        $entry.Note   = 'Quelle nicht mehr vorhanden'
        $auditRows.Add([pscustomobject]$entry)
        Write-Warning "[$($row.FolderName)] Quelle fehlt - uebersprungen"
        continue
    }

    if ($CheckOpenFiles) {
        try {
            $open = Get-SmbOpenFile -ErrorAction Stop |
                    Where-Object { $_.Path -like "$src*" }
            if ($open) {
                $entry.Result = 'Skipped'
                $entry.Note   = "VHDX in Benutzung ($($open.Count) offene Handles)"
                $auditRows.Add([pscustomobject]$entry)
                Write-Warning "[$($row.FolderName)] VHDX gerade gemountet - uebersprungen"
                continue
            }
        } catch {
            Write-Verbose "Get-SmbOpenFile nicht verfuegbar: $($_.Exception.Message)"
        }
    }

    if ($PSCmdlet.ShouldProcess($src, "Move to $dst")) {
        try {
            Move-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
            $entry.Result = 'Moved'
        } catch {
            $entry.Result = 'Failed'
            $entry.Note   = $_.Exception.Message
            Write-Warning "[$($row.FolderName)] Fehler: $($_.Exception.Message)"
        }
    } else {
        $entry.Result = 'WhatIf'
    }

    $auditRows.Add([pscustomobject]$entry)
}

if ($auditRows.Count -gt 0) {
    $auditRows | Export-Csv -Path $auditLogPath -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "Audit-Log: $auditLogPath"

    $auditRows | Group-Object Result | Sort-Object Name |
        Select-Object @{N='Result';E={$_.Name}}, Count |
        Format-Table -AutoSize | Out-String | Write-Host
}
