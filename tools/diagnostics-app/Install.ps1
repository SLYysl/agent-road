param([ValidateSet('Install','Uninstall')][string]$Action='Install')
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$root=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'AgentRoadDiagnosticsPreview'
$exe=Join-Path $root 'AgentRoadDiagnostics.exe'
$receipt=Join-Path $root 'installed.json'
try {
    if($Action -eq 'Install'){
        if(Test-Path -LiteralPath $root){throw 'INSTALL_TARGET_EXISTS'}
        $source=Join-Path $PSScriptRoot 'AgentRoadDiagnostics.exe'
        $manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'package-manifest.json') -Raw|ConvertFrom-Json
        if($manifest.schemaVersion -ne 1 -or $manifest.product -cne 'AgentRoadDiagnosticsPreview' -or $manifest.sha256 -cnotmatch '^[A-F0-9]{64}$'){throw 'PACKAGE_INVALID'}
        $item=Get-Item -LiteralPath $source
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'PACKAGE_INVALID'}
        if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -cne $manifest.sha256){throw 'PACKAGE_HASH_MISMATCH'}
        New-Item -ItemType Directory -Path $root|Out-Null
        Copy-Item -LiteralPath $source -Destination $exe
        if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $manifest.sha256){throw 'INSTALLED_HASH_MISMATCH'}
        @{schemaVersion=1;product='AgentRoadDiagnosticsPreview';sha256=$manifest.sha256}|ConvertTo-Json|Set-Content -LiteralPath $receipt -Encoding UTF8
        @{state='INSTALLED_DIAGNOSTICS_ONLY';path=$exe;remoteAccessInstalled=$false}|ConvertTo-Json -Compress
    } else {
        $item=Get-Item -LiteralPath $root
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'UNINSTALL_TARGET_INVALID'}
        $names=@(Get-ChildItem -LiteralPath $root -Force|Select-Object -ExpandProperty Name)
        if($names.Count -ne 2 -or $names -cnotcontains 'AgentRoadDiagnostics.exe' -or $names -cnotcontains 'installed.json'){throw 'UNINSTALL_CONTENT_CHANGED'}
        foreach($p in @($exe,$receipt)){if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'UNINSTALL_TARGET_INVALID'}}
        $record=Get-Content -LiteralPath $receipt -Raw|ConvertFrom-Json
        if($record.schemaVersion -ne 1 -or $record.product -cne 'AgentRoadDiagnosticsPreview' -or (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $record.sha256){throw 'UNINSTALL_CONTENT_CHANGED'}
        Remove-Item -LiteralPath $exe
        Remove-Item -LiteralPath $receipt
        [IO.Directory]::Delete($root)
        @{state='UNINSTALLED_DIAGNOSTICS_ONLY'}|ConvertTo-Json -Compress
    }
} catch {
    $known=@('INSTALL_TARGET_EXISTS','PACKAGE_INVALID','PACKAGE_HASH_MISMATCH','INSTALLED_HASH_MISMATCH','UNINSTALL_TARGET_INVALID','UNINSTALL_CONTENT_CHANGED')
    $code=if($_.Exception.Message -cin $known){$_.Exception.Message}else{'INSTALLER_OPERATION_FAILED_INSPECT_BEFORE_RETRY'}
    @{state='STOPPED';code=$code}|ConvertTo-Json -Compress
    exit 2
}
