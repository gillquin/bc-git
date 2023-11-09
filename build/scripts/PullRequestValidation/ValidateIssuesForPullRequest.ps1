using module ..\GitHub\GitHubPullRequest.class.psm1
using module ..\GitHub\GitHubIssue.class.psm1

param(
    [Parameter(Mandatory = $true)]
    [string] $PullRequestNumber,
    [Parameter(Mandatory = $true)]
    [string] $Repository
    )

# Set error action
$ErrorActionPreference = "Stop"

Write-Host "Validating PR $PullRequestNumber"

$pullRequest = [GitHubPullRequest]::Get($PullRequestNumber, $Repository)

if (-not $pullRequest) {
    throw "Could not get PR $PullRequestNumber from repository $Repository"
}

$issueSection = "Fixes #"
$issueIds = $pullRequest.GetLinkedIssueIDs($issueSection)

$Comment = "Could not find linked issues in the pull request description. Please make sure the pull request description contains a line that contains '$issueSection' followed by the issue number being fixed. Use that pattern for every issue you want to link."
if(-not $issueIds) {
    $pullRequest.AddComment($Comment)
    throw $Comment
}

$pullRequest.RemoveComment($Comment)

$invalidIssues = @()

foreach ($issueId in $issueIds) {
    Write-Host "Validating issue $issueId"
    $issue = [GitHubIssue]::Get($issueId, $Repository)

    # If the issue is not approved, add a comment to the pull request and throw an error
    $isValid = $issue -and $issue.IsApproved() -and $issue.IsOpen() -and (-not $issue.IsPullRequest())
    $Comment = "Issue #$($issueId) is not valid. Please make sure you link an **issue** that exists, is **open** and is **approved**."
    if (-not $isValid) {
        $pullRequest.AddComment($Comment)
        $invalidIssues += $issueId
    }
    else {
        $pullRequest.RemoveComment($Comment)
    }
}

if($invalidIssues) {
    throw "The following issues are not valid: $($invalidIssues -join ', '). Issues linked in a PR need to exist, be open and approved."
}

Write-Host "PR $PullRequestNumber validated successfully" -ForegroundColor Green