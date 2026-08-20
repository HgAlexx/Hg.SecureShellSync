<#
.SYNOPSIS
	Updates the plugin's lib folder with the resolved NuGet dependencies.

.DESCRIPTION
	Builds Hg.SecureShellSync.DependencyUpdater in Release, which makes NuGet resolve the full
	transitive closure, then copies every new or changed assembly into Hg.SecureShellSync\lib.

	Afterwards, replace the Reference items in Hg.SecureShellSync.csproj with the block printed
	at the end of the output, then rebuild the solution and test the plugin in KeePass.
#>

$ErrorActionPreference = 'Stop'

$root    = $PSScriptRoot
$project = Join-Path $root 'Hg.SecureShellSync.DependencyUpdater\Hg.SecureShellSync.DependencyUpdater.csproj'
$exe     = Join-Path $root 'Hg.SecureShellSync.DependencyUpdater\bin\Release\net48\Hg.SecureShellSync.DependencyUpdater.exe'

dotnet build $project -c Release -v minimal --nologo
if ($LASTEXITCODE -ne 0) {
	throw "Build failed with exit code $LASTEXITCODE."
}

& $exe --update
exit $LASTEXITCODE
