# Disassemble a .lib/.obj and report ARM64 functions whose first call is
# `bl __chkstk` made before the link register has been saved.
param(
  [Parameter(Mandatory)] [string]$Dumpbin,
  [Parameter(Mandatory)] [string]$Path,
  [string[]]$Show = @()
)
$dis = [IO.Path]::GetTempFileName()
& $Dumpbin /nologo /disasm:nobytes $Path > $dis
$bad = New-Object System.Collections.Generic.List[string]
$good = 0
$func = $null; $sawLr = $false; $done = $true
$showLeft = 0
switch -Regex -File $dis {
  '^([A-Za-z_?@][^\s:]*):\s*$' {
    $func = $Matches[1]; $sawLr = $false; $done = $false
    if ($Show -contains $func) { $showLeft = 14; Write-Output "--- $func ($Path)" }
    continue
  }
  '^\s+[0-9A-Fa-f]+:\s+(\S+)\s*(.*)$' {
    $mn = $Matches[1]; $ops = $Matches[2]
    if ($showLeft -gt 0) { Write-Output "    $mn $ops"; $showLeft-- }
    if ($done) { continue }
    if ($ops -match '\blr\b|\bx30\b') { $sawLr = $true }
    if ($mn -eq 'bl' -or $mn -eq 'blr') {
      if ($ops -match '__chkstk') {
        if ($sawLr) { $good++ } else { $bad.Add($func) }
      }
      $done = $true
    } elseif ($mn -eq 'ret' -or $mn -eq 'b' -or $mn -eq 'br') {
      $done = $true
    }
  }
}
Remove-Item $dis
Write-Output ("{0}: __chkstk after lr saved: {1}; __chkstk BEFORE lr saved: {2}" -f $Path, $good, $bad.Count)
$bad | Select-Object -First 40 | ForEach-Object { Write-Output "  BAD $_" }
