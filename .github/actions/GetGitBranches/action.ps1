param (
    [Parameter(Mandatory = $false, HelpMessage="JSON-formatted array of branch names to include")]
    [string] $include = '[]'
)

$includeBranches = ConvertFrom-Json $include

git fetch
$allBranches = @(git for-each-ref --format="%(refname:short)" | % { $_ -replace 'origin/', '' })

if ($includeBranches) {
    Write-Host "Filtering branches by: $($includeBranches -join ', ')"
    $branches = @()
    foreach ($branchFilter in $includeBranches) {
        $branches += $allBranches | Where-Object { $_ -like $branchFilter }
    }
}
else {
    $branches = $allBranches
}

Write-Host "Git branches: $($branches -join ', ')"

$branchesJson = ConvertTo-Json $branches -Compress
Add-Content -Path $env:GITHUB_OUTPUT -Value "branchesJson=$branchesJson"