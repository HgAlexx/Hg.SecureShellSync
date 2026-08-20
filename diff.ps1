<#
.SYNOPSIS
	Reports the differences between the resolved NuGet dependencies and the plugin's lib folder.

.DESCRIPTION
	Builds Hg.SecureShellSync.DependencyUpdater in Release, which makes NuGet resolve the full
	transitive closure, then compares that output against Hg.SecureShellSync\lib.
	Nothing is written to disk. Run update.ps1 to apply the changes.
#>

$ErrorActionPreference = 'Stop'

$root    = $PSScriptRoot
$project = Join-Path $root 'Hg.SecureShellSync.DependencyUpdater\Hg.SecureShellSync.DependencyUpdater.csproj'
$exe     = Join-Path $root 'Hg.SecureShellSync.DependencyUpdater\bin\Release\net48\Hg.SecureShellSync.DependencyUpdater.exe'

dotnet build $project -c Release -v minimal --nologo
if ($LASTEXITCODE -ne 0) {
	throw "Build failed with exit code $LASTEXITCODE."
}

& $exe
exit $LASTEXITCODE
