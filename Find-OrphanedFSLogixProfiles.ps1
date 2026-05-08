<#
.SYNOPSIS
    Findet FSLogix-Profilordner, deren AD-Konto fehlt, deaktiviert oder umbenannt wurde.

.DESCRIPTION
    Liest Unterordner im FSLogix-Profilpfad. Beruecksichtigt nur Ordner im Format
    <sAMAccountName>_S-1-5-21-..., alles andere wird ignoriert.
    Nachschlagen erfolgt per SID (unveraenderlich), dadurch werden auch Konten
    erkannt, deren sAMAccountName sich nach Heirat o. ae. geaendert hat.

    Erzeugt zwei CSVs:
      - Inventory : alle erkannten FSLogix-Ordner
      - Report    : alle nicht-aktiven Profile (Disabled / Deleted / Renamed)

.PARAMETER ProfileRoot
    Wurzelpfad mit den FSLogix-Profilordnern, z. B. \\fileserver\FSLogix$

.PARAMETER OutputDir
    Zielverzeichnis fuer die Reports (Default: aktuelles Verzeichnis).

.PARAMETER Server
    FQDN eines DCs der zu pruefenden Domaene, z. B. dc01.contoso.com
    Notwendig, wenn das ausfuehrende Konto nicht Mitglied der Zieldomaene ist.

.PARAMETER Credential
    Anmeldedaten fuer die Zieldomaene. Wird mit Get-Credential abgefragt, wenn
    -Credential ohne Wert angegeben wird.

.PARAMETER AssumeOtherDomainDeleted
    Markiert OtherDomain-Profile als 'kann geloescht werden'. Sinnvoll, wenn die
    Quelldomain (z. B. nach einer Migration) nicht mehr existiert.

.PARAMETER SkipSize
    Ueberspringt die Groessenmessung (schneller, aber HTML-Summen sind dann leer).
    Standard: Groesse wird ermittelt. Pro Profilordner i. d. R. 1-2 VHDX-Dateien,
    deshalb meist auch ueber SMB akzeptabel schnell.

.EXAMPLE
    .\Find-OrphanedFSLogixProfiles.ps1 -ProfileRoot '\\fs01\FSLogix$'

.EXAMPLE
    .\Find-OrphanedFSLogixProfiles.ps1 -ProfileRoot '\\fs01\FSLogix$' `
        -Server dc01.contoso.com -Credential (Get-Credential CONTOSO\admin)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ProfileRoot,

    [string]$OutputDir = (Get-Location).Path,

    [string]$Server,

    [pscredential]$Credential,

    [switch]$AssumeOtherDomainDeleted,

    [switch]$SkipSize
)

if (-not (Test-Path $ProfileRoot)) {
    throw "ProfileRoot nicht gefunden: $ProfileRoot"
}

$timestamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$inventoryCsv  = Join-Path $OutputDir "FSLogix-Inventory-$timestamp.csv"
$reportCsv     = Join-Path $OutputDir "FSLogix-Report-$timestamp.csv"
$reportHtml    = Join-Path $OutputDir "FSLogix-Report-$timestamp.html"

# 1) FSLogix-Ordner identifizieren und sAMAccountName + SID extrahieren.
#    Alles ohne SID-Suffix wird ignoriert (z. B. Logs, Temp, Admin-Ordner).
$fsRegex = '^(?<sam>.+?)_(?<sid>S-1-5-21-\d+-\d+-\d+-\d+)$'

$folders = @(Get-ChildItem -Path $ProfileRoot -Directory | Where-Object { $_.Name -match $fsRegex })
$total   = $folders.Count
$idx     = 0

$inventory = foreach ($folder in $folders) {
    $idx++
    if (-not $SkipSize) {
        Write-Progress -Activity 'FSLogix-Ordner pruefen' `
            -Status "$idx von $total : $($folder.Name)" `
            -PercentComplete (($idx / [Math]::Max($total,1)) * 100)
    }

    [void]($folder.Name -match $fsRegex)

    $sizeBytes = $null
    if (-not $SkipSize) {
        try {
            $sizeBytes = (Get-ChildItem -LiteralPath $folder.FullName -File -Recurse -Force -ErrorAction Stop |
                          Measure-Object -Property Length -Sum).Sum
            if (-not $sizeBytes) { $sizeBytes = 0 }
        } catch {
            Write-Verbose "Size-Fehler bei '$($folder.FullName)': $($_.Exception.Message)"
            $sizeBytes = $null
        }
    }

    [pscustomobject]@{
        FolderName     = $folder.Name
        FullPath       = $folder.FullName
        SamFromFolder  = $Matches.sam
        Sid            = $Matches.sid
        LastWriteTime  = $folder.LastWriteTime
        SizeBytes      = $sizeBytes
    }
}
Write-Progress -Activity 'FSLogix-Ordner pruefen' -Completed

$inventory | Export-Csv -Path $inventoryCsv -NoTypeInformation -Encoding UTF8
Write-Host "FSLogix-Profilordner erkannt: $($inventory.Count) -> $inventoryCsv"

if ($inventory.Count -eq 0) {
    Write-Warning "Keine FSLogix-Ordner gefunden. Skript endet."
    return
}

# 2) AD-Lookup per LDAP (Port 389/636) - kein ADWS, kein RSAT-Modul noetig.
function Get-LdapUserBySid {
    param(
        [Parameter(Mandatory)][string]$Sid,
        [System.DirectoryServices.DirectoryEntry]$Root
    )
    # SID-String -> escaped Binary fuer LDAP-Filter (\01\05\00\00...)
    $secId = New-Object System.Security.Principal.SecurityIdentifier $Sid
    $bytes = New-Object byte[] $secId.BinaryLength
    $secId.GetBinaryForm($bytes, 0)
    $ldapBin = ($bytes | ForEach-Object { '\{0:X2}' -f $_ }) -join ''

    $searcher = if ($Root) {
        New-Object System.DirectoryServices.DirectorySearcher($Root)
    } else {
        New-Object System.DirectoryServices.DirectorySearcher
    }
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(objectSid=$ldapBin))"
    foreach ($p in 'samAccountName','userAccountControl','lastLogonTimestamp','distinguishedName') {
        [void]$searcher.PropertiesToLoad.Add($p)
    }
    $searcher.SizeLimit = 1

    try { $r = $searcher.FindOne() } finally { $searcher.Dispose() }
    if (-not $r) { return $null }

    # Defensive Property-Reads: fehlende Werte fuehren zu null statt Exception.
    $sam = if ($r.Properties['samaccountname'].Count) { [string]$r.Properties['samaccountname'][0] } else { $null }
    $uac = if ($r.Properties['useraccountcontrol'].Count) { [int]$r.Properties['useraccountcontrol'][0] } else { 0 }
    $dn  = if ($r.Properties['distinguishedname'].Count) { [string]$r.Properties['distinguishedname'][0] } else { $null }
    $llt = $r.Properties['lastlogontimestamp']
    $lastLogon = if ($llt -and $llt.Count -and $llt[0]) { [DateTime]::FromFileTime([Int64]$llt[0]) } else { $null }

    [pscustomobject]@{
        SamAccountName    = $sam
        Enabled           = -not [bool]($uac -band 0x2)
        LastLogonDate     = $lastLogon
        DistinguishedName = $dn
    }
}

# Optionaler Such-Root, falls -Server oder -Credential gesetzt sind.
$ldapRoot = $null
if ($Server -or $Credential) {
    $path = if ($Server) {
        "LDAP://$Server"
    } else {
        "LDAP://$(([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name)"
    }
    $ldapRoot = if ($Credential) {
        New-Object System.DirectoryServices.DirectoryEntry(
            $path, $Credential.UserName, $Credential.GetNetworkCredential().Password
        )
    } else {
        New-Object System.DirectoryServices.DirectoryEntry($path)
    }
}

# Such-Domain ermitteln (defaultNamingContext + Domain-SID).
# Damit koennen wir SIDs aus fremden Domains erkennen statt sie als 'Deleted' zu klassifizieren.
try {
    $rootDsePath = if ($Server) { "LDAP://$Server/RootDSE" } else { 'LDAP://RootDSE' }
    $rootDse     = [adsi]$rootDsePath
    $defaultNc   = [string]$rootDse.defaultNamingContext

    $domainPath  = if ($Server) { "LDAP://$Server/$defaultNc" } else { "LDAP://$defaultNc" }
    $domainEntry = if ($Credential) {
        New-Object System.DirectoryServices.DirectoryEntry(
            $domainPath, $Credential.UserName, $Credential.GetNetworkCredential().Password
        )
    } else {
        [adsi]$domainPath
    }
    $sidBytes  = $domainEntry.Properties['objectSid'].Value
    $domainSid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
} catch {
    throw "LDAP-Verbindung fehlgeschlagen: $($_.Exception.Message). Pruefe -Server / -Credential."
}

Write-Host "Such-Domaene:    $defaultNc"
Write-Host "Domain-SID:      $domainSid"
Write-Host ""

$adBySid = @{}
foreach ($sid in ($inventory.Sid | Select-Object -Unique)) {

    # SID einer fremden Domain? -> ohne Lookup als OtherDomain markieren.
    if ($sid -notlike "$domainSid-*") {
        $adBySid[$sid] = [pscustomobject]@{
            Found = 'OtherDomain'; CurrentSam = $null; Enabled = $null
            LastLogonDate = $null; DistinguishedName = $null
        }
        continue
    }

    try {
        $u = Get-LdapUserBySid -Sid $sid -Root $ldapRoot
        if ($u) {
            $adBySid[$sid] = [pscustomobject]@{
                Found             = $true
                CurrentSam        = $u.SamAccountName
                Enabled           = $u.Enabled
                LastLogonDate     = $u.LastLogonDate
                DistinguishedName = $u.DistinguishedName
            }
        } else {
            $adBySid[$sid] = [pscustomobject]@{
                Found = $false; CurrentSam = $null; Enabled = $null
                LastLogonDate = $null; DistinguishedName = $null
            }
        }
    }
    catch {
        Write-Warning "LDAP-Fehler bei SID '$sid': $($_.Exception.Message)"
        $adBySid[$sid] = [pscustomobject]@{
            Found = '?'; CurrentSam = $null; Enabled = $null
            LastLogonDate = $null; DistinguishedName = $null
        }
    }
}

# 3) Status pro Profil bestimmen.
$result = foreach ($item in $inventory) {
    $ad = $adBySid[$item.Sid]

    # Wichtig: String LINKS bei -eq, sonst macht PowerShell aus 'OtherDomain'
    # einen Bool ($true) und matcht $true -eq $true.
    $status = switch ($true) {
        ('OtherDomain' -eq [string]$ad.Found)                          { 'OtherDomain' ; break }
        ('?'           -eq [string]$ad.Found)                          { 'ADError'     ; break }
        ($ad.Found -is [bool] -and -not $ad.Found)                     { 'Deleted'     ; break }
        ($ad.Enabled -eq $false)                                       { 'Disabled'    ; break }
        ($ad.CurrentSam -and $ad.CurrentSam -ne $item.SamFromFolder)   { 'Renamed'     ; break }
        default                                                        { 'Active' }
    }

    # Renamed gilt jetzt als loeschbar: FSLogix legt nach Rename einen neuen
    # Ordner '<CurrentSam>_<SID>' an, der alte Ordner ist physisch verwaist.
    $canDelete = switch ($status) {
        'Deleted'     { 'Yes - Deleted'  ; break }
        'Disabled'    { 'Yes - Disabled' ; break }
        'Renamed'     { 'Yes - Renamed'  ; break }
        'OtherDomain' { if ($AssumeOtherDomainDeleted) { 'Yes - OtherDomain' } else { 'No' } ; break }
        default       { 'No' }
    }

    $sizeGb = if ($null -ne $item.SizeBytes) {
        [math]::Round($item.SizeBytes / 1GB, 2)
    } else { $null }

    [pscustomobject]@{
        Status          = $status
        CanBeDeleted    = $canDelete
        FolderName      = $item.FolderName
        SamFromFolder   = $item.SamFromFolder
        CurrentSamInAD  = $ad.CurrentSam
        ADEnabled       = $ad.Enabled
        LastLogonDate   = $ad.LastLogonDate
        FolderLastWrite = $item.LastWriteTime
        SizeGB          = $sizeGb
        SizeBytes       = $item.SizeBytes
    }
}

# 4) Report = alles ausser Active. Sortierung: nach Status, dann nach Aenderungsdatum.
$statusOrder = @{ 'Deleted' = 1; 'Disabled' = 2; 'Renamed' = 3; 'OtherDomain' = 4; 'ADError' = 5 }
$report = $result |
    Where-Object Status -ne 'Active' |
    Sort-Object @{Expression = { $statusOrder[$_.Status] }}, FolderLastWrite

$report | Export-Csv -Path $reportCsv -NoTypeInformation -Encoding UTF8

# 5) Interaktiver HTML-Report (alle Profile inkl. Active, mit Live-Filter und Summen).
function ConvertTo-HtmlSafe {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
}

$columns = 'Status','CanBeDeleted','FolderName','SamFromFolder','CurrentSamInAD',
           'ADEnabled','LastLogonDate','FolderLastWrite','SizeGB'

# Domain-SID-Inventar (Diagnose).
$domainBuckets = $inventory.Sid | ForEach-Object {
        if ($_ -match '^(?<d>S-1-5-21-\d+-\d+-\d+)-\d+$') { $Matches.d }
    } | Group-Object | Sort-Object Count -Descending

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('<!DOCTYPE html>')
[void]$sb.AppendLine('<html lang="de"><head><meta charset="utf-8">')
[void]$sb.AppendLine('<title>FSLogix-Report</title>')
[void]$sb.AppendLine(@'
<style>
  :root { --del:#c0392b; --del-bg:#ffe1e1; --ok:#27ae60; --warn:#e67e22; --muted:#777; }
  * { box-sizing: border-box; }
  body { font-family: "Segoe UI", Arial, sans-serif; font-size: 13px; color: #222; margin: 16px 24px; background:#fafafa; }
  h1 { font-size: 22px; margin: 0 0 4px 0; }
  h2 { font-size: 15px; margin: 24px 0 8px 0; }
  .meta { color: #555; margin-bottom: 14px; font-size: 12px; }
  .meta span { display:inline-block; margin-right:18px; }
  .tiles { display:flex; gap:10px; flex-wrap:wrap; margin: 14px 0 18px; }
  .tile { background:#fff; border:1px solid #ddd; border-radius:6px; padding:10px 14px; min-width:150px; }
  .tile .lbl { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.4px; }
  .tile .val { font-size:18px; font-weight:600; margin-top:2px; }
  .tile.del .val { color:var(--del); }
  .tile.ok  .val { color:var(--ok); }
  .controls { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin: 8px 0 12px; }
  .controls input[type="search"] { padding:6px 10px; border:1px solid #ccc; border-radius:4px; min-width:240px; font-size:13px; }
  .btn { padding:5px 11px; border:1px solid #ccc; background:#fff; border-radius:4px; cursor:pointer; font-size:12px; }
  .btn:hover { background:#f0f0f0; }
  .btn.active { background:#2c3e50; color:#fff; border-color:#2c3e50; }
  .btn.del { border-color:var(--del); color:var(--del); }
  .btn.del.active { background:var(--del); color:#fff; }
  .btn.ok { border-color:var(--ok); color:var(--ok); }
  .btn.ok.active { background:var(--ok); color:#fff; }
  table { border-collapse: collapse; width: 100%; background:#fff; }
  th, td { padding: 6px 10px; border: 1px solid #e1e1e1; text-align: left; vertical-align: top; font-size:12.5px; }
  th { background: #f0f0f0; position: sticky; top: 0; cursor:pointer; user-select:none; }
  th:hover { background:#e6e6e6; }
  th .arrow { color:#999; font-size:10px; margin-left:4px; }
  tr.cb-yes td { background: var(--del-bg); }
  tr.cb-yes td:first-child { border-left: 4px solid var(--del); }
  tr:hover td { background: #eef6ff; }
  tr.cb-yes:hover td { background: #ffd1d1; }
  td.num { text-align:right; font-variant-numeric: tabular-nums; }
  .footer { margin-top:24px; color:var(--muted); font-size:11px; }
  .pill { display:inline-block; padding:1px 7px; border-radius:10px; font-size:11px; }
  .pill.del { background:var(--del); color:#fff; }
  .pill.ok  { background:var(--ok); color:#fff; }
  .pill.warn{ background:var(--warn); color:#fff; }
  .pill.muted { background:#bbb; color:#fff; }
</style>
'@)
[void]$sb.AppendLine('</head><body>')
[void]$sb.AppendLine('<h1>FSLogix Profile Report</h1>')
[void]$sb.AppendLine('<div class="meta">')
[void]$sb.AppendLine("  <span><b>Created:</b> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span>")
[void]$sb.AppendLine("  <span><b>ProfileRoot:</b> $(ConvertTo-HtmlSafe $ProfileRoot)</span>")
[void]$sb.AppendLine("  <span><b>Search domain:</b> $(ConvertTo-HtmlSafe $defaultNc)</span>")
[void]$sb.AppendLine("  <span><b>Domain SID:</b> $(ConvertTo-HtmlSafe $domainSid)</span>")
[void]$sb.AppendLine('</div>')

# Tiles fuer Summen (Werte werden via JS aus den Tabellenzeilen berechnet).
[void]$sb.AppendLine('<div class="tiles">')
[void]$sb.AppendLine('  <div class="tile"><div class="lbl">Profiles (filtered)</div><div class="val" id="t-count">-</div></div>')
[void]$sb.AppendLine('  <div class="tile"><div class="lbl">Size (filtered)</div><div class="val" id="t-size">-</div></div>')
[void]$sb.AppendLine('  <div class="tile del"><div class="lbl">Deletable</div><div class="val" id="t-del">-</div></div>')
[void]$sb.AppendLine('  <div class="tile del"><div class="lbl">Deletable size</div><div class="val" id="t-del-size">-</div></div>')
[void]$sb.AppendLine('  <div class="tile ok"><div class="lbl">Active</div><div class="val" id="t-act">-</div></div>')
[void]$sb.AppendLine('  <div class="tile ok"><div class="lbl">Active size</div><div class="val" id="t-act-size">-</div></div>')
[void]$sb.AppendLine('</div>')

# Filter-Buttons + Suche.
[void]$sb.AppendLine('<div class="controls">')
[void]$sb.AppendLine('  <button class="btn active" data-filter="all">All FSLogix-Folders</button>')
[void]$sb.AppendLine('  <button class="btn del" data-filter="del">Deletable FSLogix-Folders</button>')
[void]$sb.AppendLine('  <button class="btn ok"  data-filter="active">Active Accounts</button>')
[void]$sb.AppendLine('  <button class="btn" data-filter="status:Deleted">Deleted AD-Accounts</button>')
[void]$sb.AppendLine('  <button class="btn" data-filter="status:Disabled">Disabled AD-Accounts</button>')
[void]$sb.AppendLine('  <button class="btn" data-filter="status:Renamed">Renamed AD-Accounts</button>')
[void]$sb.AppendLine('  <button class="btn" data-filter="status:ADError">ADError</button>')
[void]$sb.AppendLine('  <input type="search" id="q" placeholder="Search (folder / sAMAccountName)..." />')
[void]$sb.AppendLine('</div>')

# Tabelle (ALLE Zeilen, Filter macht JS).
[void]$sb.AppendLine('<table id="tbl">')
[void]$sb.Append('<thead><tr>')
foreach ($c in $columns) {
    [void]$sb.Append("<th data-col='$c'>$c<span class='arrow'>&#8597;</span></th>")
}
[void]$sb.AppendLine('</tr></thead><tbody>')

# Sortierung der HTML-Tabelle: erst loeschbare oben, dann nach Status, dann nach Datum.
$htmlOrder = @{ 'Deleted'=1; 'Disabled'=2; 'OtherDomain'=3; 'Renamed'=4; 'ADError'=5; 'Active'=6 }
$htmlRows = $result | Sort-Object `
    @{Expression = { $htmlOrder[$_.Status] }}, `
    FolderLastWrite

foreach ($row in $htmlRows) {
    $cbBool = if ($row.CanBeDeleted -like 'Yes*') { 'Yes' } else { 'No' }
    $cls    = if ($cbBool -eq 'Yes') { 'cb-yes' } else { 'cb-no' }
    $bytesAttr = if ($null -ne $row.SizeBytes) { $row.SizeBytes } else { '' }
    [void]$sb.Append("<tr class='$cls' data-status='$(ConvertTo-HtmlSafe $row.Status)' data-cb='$cbBool' data-bytes='$bytesAttr'>")

    # Status mit Pill-Style
    $pillClass = switch ($row.Status) {
        'Active'      { 'ok' }
        'Deleted'     { 'del' }
        'Disabled'    { 'del' }
        'Renamed'     { 'warn' }
        'OtherDomain' { 'warn' }
        'ADError'     { 'muted' }
        default       { 'muted' }
    }
    [void]$sb.Append("<td><span class='pill $pillClass'>$(ConvertTo-HtmlSafe $row.Status)</span></td>")
    [void]$sb.Append("<td>$(ConvertTo-HtmlSafe $row.CanBeDeleted)</td>")
    [void]$sb.Append("<td>$(ConvertTo-HtmlSafe $row.FolderName)</td>")
    [void]$sb.Append("<td>$(ConvertTo-HtmlSafe $row.SamFromFolder)</td>")
    [void]$sb.Append("<td>$(ConvertTo-HtmlSafe $row.CurrentSamInAD)</td>")
    [void]$sb.Append("<td>$(ConvertTo-HtmlSafe $row.ADEnabled)</td>")
    [void]$sb.Append("<td>$(ConvertTo-HtmlSafe $row.LastLogonDate)</td>")
    [void]$sb.Append("<td>$(ConvertTo-HtmlSafe $row.FolderLastWrite)</td>")
    $sizeDisp = if ($null -ne $row.SizeGB) { ('{0:N2}' -f $row.SizeGB) } else { '' }
    [void]$sb.Append("<td class='num'>$sizeDisp</td>")
    [void]$sb.AppendLine('</tr>')
}
[void]$sb.AppendLine('</tbody></table>')

# Diagnose-Bloecke.
[void]$sb.AppendLine('<h2>Status summary</h2>')
[void]$sb.AppendLine('<table style="width:auto"><thead><tr><th>Status</th><th>Count</th></tr></thead><tbody>')
foreach ($g in ($result | Group-Object Status | Sort-Object Name)) {
    [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlSafe $g.Name)</td><td class='num'>$($g.Count)</td></tr>")
}
[void]$sb.AppendLine('</tbody></table>')

[void]$sb.AppendLine('<h2>Domain SID inventory (all profiles)</h2>')
[void]$sb.AppendLine('<table style="width:auto"><thead><tr><th>Domain SID</th><th>Profiles</th><th>Match search domain?</th></tr></thead><tbody>')
foreach ($b in $domainBuckets) {
    $match = if ($b.Name -eq $domainSid) { 'YES' } else { 'NO' }
    [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlSafe $b.Name)</td><td class='num'>$($b.Count)</td><td>$match</td></tr>")
}
[void]$sb.AppendLine('</tbody></table>')

[void]$sb.AppendLine('<div class="footer">Tip: click a column header to sort. Filters and search combine.</div>')

# JavaScript: Filter, Suche, Sortierung, Live-Summen.
[void]$sb.AppendLine(@'
<script>
(function () {
  const tbody = document.querySelector('#tbl tbody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  const tiles = {
    count: document.getElementById('t-count'),
    size:  document.getElementById('t-size'),
    del:   document.getElementById('t-del'),
    delS:  document.getElementById('t-del-size'),
    act:   document.getElementById('t-act'),
    actS:  document.getElementById('t-act-size'),
  };
  const buttons = document.querySelectorAll('.btn[data-filter]');
  const search  = document.getElementById('q');
  let activeFilter = 'all';

  function fmtSize(bytes) {
    if (!bytes) return '0 GB';
    const gb = bytes / (1024**3);
    if (gb >= 1) return gb.toFixed(2) + ' GB';
    const mb = bytes / (1024**2);
    return mb.toFixed(0) + ' MB';
  }

  function matchFilter(tr) {
    if (activeFilter === 'all') return true;
    if (activeFilter === 'del') return tr.dataset.cb === 'Yes';
    if (activeFilter === 'active') return tr.dataset.status === 'Active';
    if (activeFilter.startsWith('status:')) {
      return tr.dataset.status === activeFilter.slice(7);
    }
    return true;
  }
  function matchSearch(tr) {
    const q = (search.value || '').trim().toLowerCase();
    if (!q) return true;
    return tr.textContent.toLowerCase().includes(q);
  }

  function recompute() {
    let count = 0, size = 0, delC = 0, delS = 0, actC = 0, actS = 0;
    for (const tr of rows) {
      const visible = matchFilter(tr) && matchSearch(tr);
      tr.style.display = visible ? '' : 'none';
      if (!visible) continue;
      const b = parseFloat(tr.dataset.bytes) || 0;
      count++; size += b;
      if (tr.dataset.cb === 'Yes') { delC++; delS += b; }
      if (tr.dataset.status === 'Active') { actC++; actS += b; }
    }
    tiles.count.textContent = count.toLocaleString('de-DE');
    tiles.size.textContent  = fmtSize(size);
    tiles.del.textContent   = delC.toLocaleString('de-DE');
    tiles.delS.textContent  = fmtSize(delS);
    tiles.act.textContent   = actC.toLocaleString('de-DE');
    tiles.actS.textContent  = fmtSize(actS);
  }

  buttons.forEach(b => b.addEventListener('click', () => {
    buttons.forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    activeFilter = b.dataset.filter;
    recompute();
  }));
  search.addEventListener('input', recompute);

  // Sortierung per Spaltenkopf
  const ths = document.querySelectorAll('#tbl thead th');
  ths.forEach((th, i) => th.addEventListener('click', () => {
    const dir = th.dataset.dir === 'asc' ? 'desc' : 'asc';
    ths.forEach(x => x.dataset.dir = '');
    th.dataset.dir = dir;
    const isNum = th.dataset.col === 'SizeGB';
    const isDate = th.dataset.col === 'LastLogonDate' || th.dataset.col === 'FolderLastWrite';
    const sorted = rows.slice().sort((a, b) => {
      let av = a.children[i].textContent.trim();
      let bv = b.children[i].textContent.trim();
      if (isNum)  { av = parseFloat(av.replace(',', '.')) || 0; bv = parseFloat(bv.replace(',', '.')) || 0; }
      if (isDate) { av = Date.parse(av.split('.').reverse().join('-')) || 0; bv = Date.parse(bv.split('.').reverse().join('-')) || 0; }
      if (av < bv) return dir === 'asc' ? -1 : 1;
      if (av > bv) return dir === 'asc' ?  1 : -1;
      return 0;
    });
    sorted.forEach(r => tbody.appendChild(r));
  }));

  recompute();
})();
</script>
'@)
[void]$sb.AppendLine('</body></html>')

Set-Content -Path $reportHtml -Value $sb.ToString() -Encoding UTF8

# Konsolen-Zusammenfassung
$summary = $result | Group-Object Status | Sort-Object Name |
    Select-Object @{N='Status';E={$_.Name}}, Count

Write-Host ""
Write-Host "Zusammenfassung:"
$summary | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "Domain-SID-Inventar:"
$domainBuckets |
    Select-Object @{N='Domain-SID';E={$_.Name}},
                  @{N='Profile';E={$_.Count}},
                  @{N='Match';E={ if ($_.Name -eq $domainSid) { 'JA' } else { 'NEIN' } }} |
    Format-Table -AutoSize | Out-String | Write-Host

Write-Host "Report CSV  (fuer Move-Skript)  -> $reportCsv"
Write-Host "Report HTML (zur Sichtpruefung) -> $reportHtml"
Write-Host ""
Write-Host "Hinweis:"
Write-Host "  CanBeDeleted = Yes -> Zeile rot markiert, vom Move-Skript verschiebbar"
Write-Host "  Deleted     = AD-Konto existiert nicht mehr      -> Yes"
Write-Host "  Disabled    = Konto deaktiviert                  -> Yes (separat pruefen)"
Write-Host "  Renamed     = Konto existiert, sAMAccountName geaendert -> No (NICHT loeschen)"
Write-Host "  OtherDomain = SID gehoert zu fremder Domain      -> No (Yes mit -AssumeOtherDomainDeleted)"
Write-Host "  ADError     = Lookup-Fehler                      -> No (manuell pruefen)"
