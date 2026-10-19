param([string]$Path)
$b = [System.IO.File]::ReadAllBytes($Path)
function U16($o){ [BitConverter]::ToUInt16($b,$o) }
function U32($o){ [BitConverter]::ToUInt32($b,$o) }
$pe = U32 0x3C
$nsec = U16 ($pe+6)
$optSize = U16 ($pe+20)
$opt = $pe+24
$magic = U16 $opt
$is64 = ($magic -eq 0x20b)
$ep = U32 ($opt+16)
$imgBase = if($is64){ [BitConverter]::ToUInt64($b,$opt+24) } else { [BitConverter]::ToUInt32($b,$opt+28) }
$dirOff = if($is64){$opt+112}else{$opt+96}
Write-Output ("magic=0x{0:X} nsec={1} EP=0x{2:X} ImageBase=0x{3:X} is64={4}" -f $magic,$nsec,$ep,$imgBase,$is64)
$names = @('EXPORT','IMPORT','RESOURCE','EXCEPTION','SECURITY','BASERELOC','DEBUG','ARCH','GLOBALPTR','TLS','LOADCFG','BOUNDIMP','IAT','DELAYIMP','CLR','RESV')
for($i=0;$i -lt 16;$i++){
  $rva = U32 ($dirOff+$i*8); $sz = U32 ($dirOff+$i*8+4)
  Write-Output ("  [{0,2}] {1,-9} rva=0x{2:X8} size=0x{3:X}" -f $i,$names[$i],$rva,$sz)
}
$secOff = $opt + $optSize
for($i=0;$i -lt $nsec;$i++){
  $s=$secOff+$i*40
  $name = ([System.Text.Encoding]::ASCII.GetString($b,$s,8)).Trim([char]0)
  $vs = U32 ($s+8); $va = U32 ($s+12); $rs = U32 ($s+16); $pr = U32 ($s+20); $ch = U32 ($s+36)
  # count nonzero bytes in raw
  $nz=0; $end=[Math]::Min($pr+$rs,$b.Length)
  for($k=$pr;$k -lt $end;$k++){ if($b[$k] -ne 0){$nz++} }
  Write-Output ("  sec {0,-10} va=0x{1:X8} vs=0x{2:X} raw=0x{3:X} roff=0x{4:X} ch=0x{5:X8} nonzero={6}" -f $name,$va,$vs,$rs,$pr,$ch,$nz)
}