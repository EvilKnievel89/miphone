<#
.SYNOPSIS
    Bumps the version, builds a release and tags it.

.DESCRIPTION
    Asks for the new version (Enter accepts the current version + 0.0.1), writes it
    to all crates, runs "cargo build --release", commits the version bump and
    creates the tag v<version>. With -Push (or --push) the commit and the tag are
    pushed to origin.

.EXAMPLE
    .\release.ps1                  # ask for the version
    .\release.ps1 --push           # ask, then push commit and tag
    .\release.ps1 0.2.0 --push     # no question
    .\release.ps1 -Auto --push     # no question, current version + 0.0.1
#>
param(
    [string]$Version,
    [switch]$Push,
    [switch]$Auto,
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
    $parts = $current.Split('.')
    $next = '{0}.{1}.{2}' -f $parts[0], $parts[1], ([int]$parts[2] + 1)

    if (-not $Version) {
        if ($Auto) {
            $Version = $next
        } else {
            $Version = Read-Host "Current version is $current. New version [$next]"
            if (-not $Version) { $Version = $next }
        }
    }
    $Version = $Version.Trim() -replace '^v', ''
    if ($Version -notmatch '^\d+\.\d+\.\d+$') {
        throw "'$Version' is not a version of the form 1.2.3"
    }
    if ($Version -eq $current) { throw "Version $Version is already the current version." }

    $tag = "v$Version"
    if (git tag --list $tag) { throw "Tag $tag already exists." }

    Write-Host "Releasing $current -> $Version" -ForegroundColor Cyan

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
