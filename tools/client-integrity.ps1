[CmdletBinding()]
param(
  [ValidateSet('Prepare','Sign')][string]$Action='Prepare',
  [string]$Directory
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$version=(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
$private=Join-Path $root 'artifacts\private-signing\client-integrity.key.xml'
$utf8=[Text.UTF8Encoding]::new($false)
$rsa=New-Object Security.Cryptography.RSACryptoServiceProvider 3072
$rsa.PersistKeyInCsp=$false
try {
  if(Test-Path -LiteralPath $private){$rsa.FromXmlString([IO.File]::ReadAllText($private))}
  elseif($Action -eq 'Prepare'){
    $dir=Split-Path -Parent $private
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    [IO.File]::WriteAllText($private,$rsa.ToXmlString($true),$utf8)
    # Keep the release signing key local. Only the public key is compiled/shipped.
    $acl=Get-Acl -LiteralPath $dir
    $acl.SetAccessRuleProtection($true,$false)
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $dir -AclObject $acl
  }else{throw 'Signing key is missing; run Prepare and rebuild first'}
  $p=$rsa.ExportParameters($false)
  if($Action -eq 'Prepare'){
    $header=[IO.MemoryStream]::new()
    $writer=[IO.BinaryWriter]::new($header)
    foreach($value in @([uint32]0x31415352,[uint32]($p.Modulus.Length*8),[uint32]$p.Exponent.Length,[uint32]$p.Modulus.Length,[uint32]0,[uint32]0)){$writer.Write([uint32]$value)}
    $writer.Write([byte[]]$p.Exponent);$writer.Write([byte[]]$p.Modulus);$writer.Flush()
    $blob=$header.ToArray();$writer.Dispose();$header.Dispose()
    $bytes=($blob|ForEach-Object {'0x{0:x2}' -f $_}) -join ','
    [IO.File]::WriteAllText((Join-Path $root 'src\client_trust_key.h'),"#pragma once`n// Generated public release verification key, not a secret.`ninline constexpr unsigned char kClientTrustKey[] = {$bytes};`n",$utf8)
    $mod=[Convert]::ToBase64String($p.Modulus);$exp=[Convert]::ToBase64String($p.Exponent)
    [IO.File]::WriteAllText((Join-Path $root 'ui\Services\ClientTrustKey.g.cs'),"namespace NovaProtect.UI.Services;`ninternal static class ClientTrustKey { internal const string Modulus = `"$mod`"; internal const string Exponent = `"$exp`"; }`n",$utf8)
    Write-Host 'CLIENT-TRUST-PREPARED (public verification key only; private key never shipped)'
  }else{
    if(-not $Directory){throw 'Sign requires -Directory'}
    $Directory=(Resolve-Path -LiteralPath $Directory).Path.TrimEnd('\')
    foreach($file in @('NovaProtect.exe','NovaProtect.dll','NovaProtect.Engine.exe','NovaProtect.ManagedHost.exe')){
      if(-not(Test-Path -LiteralPath (Join-Path $Directory $file) -PathType Leaf)){throw "Missing required component: $file"}
    }
    $rows=@('NOVAPROTECT-CLIENT-1',$version)
    foreach($f in (Get-ChildItem -LiteralPath $Directory -Recurse -File|Sort-Object FullName)){
      $rel=$f.FullName.Substring($Directory.Length).TrimStart('\').Replace('\','/')
      if($rel.StartsWith('NovaProtect.exe.WebView2/',[StringComparison]::OrdinalIgnoreCase)){continue}
      if($f.Extension -in @('.pdb','.map','.vmp') -or $f.Name -like '*.vmprotect.log' -or $f.Name -in @('client-integrity.manifest','client-integrity.sig')){continue}
      $rows+=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$rel
    }
    $data=$utf8.GetBytes(($rows -join "`n")+"`n")
    $signature=$rsa.SignData($data,[Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'))
    [IO.File]::WriteAllBytes((Join-Path $Directory 'client-integrity.manifest'),$data)
    [IO.File]::WriteAllBytes((Join-Path $Directory 'client-integrity.sig'),$signature)
    Write-Host "CLIENT-INTEGRITY-SIGNED ($($rows.Count-2) files; RSA-3072/SHA-256; $version)"
  }
}finally{$rsa.Dispose()}
