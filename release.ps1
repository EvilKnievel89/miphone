<#
.SYNOPSIS
    Bumps the version, builds a release and tags it.

.DESCRIPTION
    Asks for the new version (Enter accepts the current version + 0.0.1), writes it
    to all crates, runs "cargo build --release", commits the version bump and
    creates the tag v<version>. With -Push (or --push) the commit and the tag are
    pushed to origin; GitHub then builds the tag and publishes it as a release.

    With -Pre (or --pre) the version gets the suffix -pre.<n>, e.g. 1.2.4-pre.1, and
    GitHub publishes it as a pre-release. The next release without -Pre is 1.2.4.

.EXAMPLE
    .\release.ps1                  # ask for the version
    .\release.ps1 --push           # ask, then push commit and tag
    .\release.ps1 0.2.0 --push     # no question
    .\release.ps1 -Auto --push     # no question, current version + 0.0.1
    .\release.ps1 -Pre --push      # ask, release as pre-release
    .\release.ps1 0.2.0 -Pre       # 0.2.0-pre.1
#>
param(
    [string]$Version,
    [switch]$Push,
    [switch]$Auto,
    [switch]$Pre,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = 'Stop'

# PowerShell does not bind "--push" to a switch, so accept that spelling by hand.
$words = @(@($Version) + @($Rest) | Where-Object { $_ })
$Version = $null
foreach ($word in $words) {
    switch -Regex ($word) {
        '^--push$' { $Push = $true; break }
        '^--auto$' { $Auto = $true; break }
        '^--pre$' { $Pre = $true; break }
        '^-' { throw "Unknown option: $word" }
        default {
            if ($Version) { throw "Unexpected argument: $word" }
            $Version = $word
        }
    }
}

function Invoke-Checked {
    # Runs a program and stops the script if it fails.
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

$manifests = @(
    'crates/misip/Cargo.toml',
    'crates/miphone/Cargo.toml',
    'crates/miphone-gui/Cargo.toml'
)
$packageVersion = [regex]'(?m)^version = "([^"]+)"'
$internalDependency = [regex]'(?m)^(misip|miphone|miphone-gui) = \{ version = "[^"]+"'

Push-Location $PSScriptRoot
try {
    if (git status --porcelain) {
        throw 'The working tree has uncommitted changes. Commit or stash them first.'
    }

    $text = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'crates/miphone-gui/Cargo.toml'))
    $match = $packageVersion.Match($text)
    if (-not $match.Success) { throw 'No version found in crates/miphone-gui/Cargo.toml' }
    $current = $match.Groups[1].Value
    if ($current -notmatch '^(\d+)\.(\d+)\.(\d+)(?:-pre\.(\d+))?$') {
        throw "The current version '$current' is not of the form 1.2.3 or 1.2.3-pre.1"
    }
    $major, $minor, $patch = $Matches[1], $Matches[2], [int]$Matches[3]
    $currentPre = if ($Matches[4]) { [int]$Matches[4] } else { 0 }
    # A pre-release already carries the number of the release it leads to.
    $next = if ($currentPre -and $Pre) {
        "$major.$minor.$patch-pre.$($currentPre + 1)"
    } elseif ($currentPre) {
        "$major.$minor.$patch"
    } elseif ($Pre) {
        "$major.$minor.$($patch + 1)-pre.1"
    } else {
        "$major.$minor.$($patch + 1)"
    }

    if (-not $Version) {
        if ($Auto) {
            $Version = $next
        } else {
            $Version = Read-Host "Current version is $current. New version [$next]"
            if (-not $Version) { $Version = $next }
        }
    }
    $Version = $Version.Trim() -replace '^v', ''
    if ($Version -notmatch '^\d+\.\d+\.\d+(-pre\.\d+)?$') {
        throw "'$Version' is not a version of the form 1.2.3 or 1.2.3-pre.1"
    }
    if ($Pre -and $Version -notmatch '-pre\.') {
        # The first pre-release of that version, or the one after those already tagged.
        $number = 1
        while (git tag --list "v$Version-pre.$number") { $number++ }
        $Version = "$Version-pre.$number"
    } elseif (-not $Pre -and $Version -match '-pre\.') {
        throw "'$Version' is a pre-release; say so with -Pre."
    }
    if ($Version -eq $current) { throw "Version $Version is already the current version." }

    $tag = "v$Version"
    if (git tag --list $tag) { throw "Tag $tag already exists." }

    Write-Host "Releasing $current -> $Version$(if ($Pre) { ' (pre-release)' })" -ForegroundColor Cyan

    try {
        foreach ($manifest in $manifests) {
            $path = Join-Path $PSScriptRoot $manifest
            $text = [IO.File]::ReadAllText($path)
            $text = $packageVersion.Replace($text, "version = `"$Version`"", 1)
            $text = $internalDependency.Replace($text, "`${1} = { version = `"$Version`"")
            # WriteAllText keeps the LF line endings and writes no BOM.
            [IO.File]::WriteAllText($path, $text)
        }

        # The build also writes the new version to Cargo.lock.
        Invoke-Checked cargo @('build', '--release', '--workspace')
    } catch {
        Write-Host 'Build failed, restoring the old version.' -ForegroundColor Yellow
        git checkout -- $manifests Cargo.lock
        throw
    }

    Invoke-Checked git (@('add', '--') + $manifests + 'Cargo.lock')
    Invoke-Checked git @('commit', '-m', "Release $tag")
    Invoke-Checked git @('tag', '-a', $tag, '-m', "Release $tag")

    if ($Push) {
        $branch = git rev-parse --abbrev-ref HEAD
        Invoke-Checked git @('push', '--atomic', 'origin', $branch, $tag)
        Write-Host "Released and pushed $tag." -ForegroundColor Green
    } else {
        Write-Host "Released $tag. Push it with: git push --atomic origin HEAD $tag" -ForegroundColor Green
    }
    Write-Host "Programs are in $(Join-Path $PSScriptRoot 'target\release')."
} finally {
    Pop-Location
}
