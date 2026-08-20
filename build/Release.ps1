<#
.SYNOPSIS
	Prepares a release: syncs version.txt with AssemblyInfo.cs and tags the repository.

.DESCRIPTION
	AssemblyInfo.cs is the single source of truth for the plugin version, because it is the
	only file read by both MSBuild and the KeePass PLGX compiler (which ignores MSBuild
	props/targets entirely).

	This script:
	  1. Reads AssemblyVersion from Hg.SecureShellSync\Properties\AssemblyInfo.cs.
	  2. Rewrites version.txt (UTF-8 without BOM) in the KeePass version information format.
	  3. Optionally creates the git tag v<Major>.<Minor> and pushes it.

	Nothing is written, committed, tagged or pushed unless -Apply is specified.
	The tag is only pushed when -Push is also specified.

.EXAMPLE
	.\build\Release.ps1
	Dry run: shows the version, the resulting version.txt and the tag that would be created.

.EXAMPLE
	.\build\Release.ps1 -Apply
	Updates version.txt and creates the local tag, without pushing.

.EXAMPLE
	.\build\Release.ps1 -Apply -Push
	Updates version.txt, creates the local tag and pushes it to origin.
#>
[CmdletBinding()]
param(
	# Perform the changes. Without this switch the script only reports what it would do.
	[switch] $Apply,

	# Push the created tag to the remote. Requires -Apply.
	[switch] $Push,

	# Name of the git remote to push the tag to.
	[string] $Remote = 'origin',

	# Skip the clean working tree check (not recommended).
	[switch] $AllowDirty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$assemblyInfoPath = Join-Path $repoRoot 'Hg.SecureShellSync\Properties\AssemblyInfo.cs'
$versionFilePath = Join-Path $repoRoot 'version.txt'
$pluginTitle = 'Hg.SecureShellSync'
$separator = ':'

function Write-Step([string] $message) {
	Write-Host $message -ForegroundColor Cyan
}

if (-not (Test-Path -LiteralPath $assemblyInfoPath)) {
	throw "AssemblyInfo.cs not found at '$assemblyInfoPath'."
}

# --- Read the version -------------------------------------------------------

$assemblyInfo = Get-Content -LiteralPath $assemblyInfoPath -Raw
$versionMatch = [regex]::Match($assemblyInfo, '(?m)^\s*\[assembly:\s*AssemblyVersion\("(?<version>[0-9]+(\.[0-9]+){1,3})"\)\]')
if (-not $versionMatch.Success) {
	throw "Could not find an AssemblyVersion attribute in '$assemblyInfoPath'."
}

$version = [version] $versionMatch.Groups['version'].Value

$fileVersionMatch = [regex]::Match($assemblyInfo, '(?m)^\s*\[assembly:\s*AssemblyFileVersion\("(?<version>[0-9]+(\.[0-9]+){1,3})"\)\]')
if ($fileVersionMatch.Success) {
	$fileVersion = [version] $fileVersionMatch.Groups['version'].Value
	if ($fileVersion -ne $version) {
		throw "AssemblyVersion ($version) and AssemblyFileVersion ($fileVersion) do not match. Align them before releasing."
	}
}
else {
	Write-Warning 'No AssemblyFileVersion attribute found; KeePass matches plugins on the file version.'
}

# The release tag and the version information file both use Major.Minor, which is what
# UpdateUrl builds from Version.ToString(2).
$shortVersion = $version.ToString(2)
$tag = "v$shortVersion"

Write-Step "Version : $version"
Write-Step "Tag     : $tag"

# --- Compute version.txt ----------------------------------------------------

$newLine = "`n"
$versionFileContent = "$separator$newLine$pluginTitle$separator$shortVersion$newLine$separator$newLine"

Write-Step 'version.txt:'
Write-Host $versionFileContent

# --- Git safety checks ------------------------------------------------------

$gitAvailable = $null -ne (Get-Command git -ErrorAction SilentlyContinue)
if (-not $gitAvailable) {
	throw 'git was not found in PATH.'
}

Push-Location $repoRoot
try {
	$existingTag = (& git tag --list $tag) | Where-Object { $_ }
	if ($existingTag) {
		throw "Tag '$tag' already exists locally. Bump the version in AssemblyInfo.cs before releasing."
	}

	$remoteTag = (& git ls-remote --tags $Remote "refs/tags/$tag") | Where-Object { $_ }
	if ($LASTEXITCODE -ne 0) {
		Write-Warning "Could not query remote '$Remote' for existing tags; continuing."
	}
	elseif ($remoteTag) {
		throw "Tag '$tag' already exists on remote '$Remote'. Bump the version in AssemblyInfo.cs before releasing."
	}

	if (-not $Apply) {
		Write-Host ''
		Write-Host 'Dry run: nothing was written, tagged or pushed. Re-run with -Apply (and -Push) to release.' -ForegroundColor Yellow
		return
	}

	# --- Write version.txt --------------------------------------------------

	Write-Step "Writing '$versionFilePath'..."
	# KeePass recommends UTF-8 without a byte order mark.
	$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
	[System.IO.File]::WriteAllText($versionFilePath, $versionFileContent, $utf8NoBom)

	# --- Working tree check -------------------------------------------------

	$status = (& git status --porcelain) | Where-Object { $_ }
	if ($status -and -not $AllowDirty) {
		Write-Host ''
		Write-Host 'The working tree has uncommitted changes (including the version.txt update above):' -ForegroundColor Yellow
		$status | ForEach-Object { Write-Host "  $_" }
		throw "Commit the changes, then re-run the script to create the tag (or use -AllowDirty to skip this check)."
	}

	# --- Tag ----------------------------------------------------------------

	Write-Step "Creating tag '$tag'..."
	& git tag -a $tag -m "$pluginTitle $shortVersion"
	if ($LASTEXITCODE -ne 0) {
		throw "Failed to create tag '$tag'."
	}

	if ($Push) {
		Write-Step "Pushing tag '$tag' to '$Remote'..."
		& git push $Remote "refs/tags/$tag"
		if ($LASTEXITCODE -ne 0) {
			throw "Failed to push tag '$tag' to '$Remote'."
		}
	}
	else {
		Write-Host "Tag created locally. Push it with: git push $Remote refs/tags/$tag" -ForegroundColor Yellow
	}

	Write-Host "Done." -ForegroundColor Green
}
finally {
	Pop-Location
}
