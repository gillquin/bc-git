using module .\GitHubAPI.class.psm1


<#
    Class that represents a GitHub issue.
#>
class GitHubIssue {
    $IssueId
    $Repository
    $Issue

    hidden GitHubIssue([int] $IssueId, [string] $Repository) {
        $this.IssueId = $IssueId
        $this.Repository = $Repository

        $gitHubIssue = gh api "/repos/$Repository/issues/$IssueId" -H ([GitHubAPI]::AcceptJsonHeader) -H ([GitHubAPI]::GitHubAPIHeader) | ConvertFrom-Json
        if ($gitHubIssue.message) {
            # message property is populated when the issue is not found
            throw "::Error:: Could not get issue $IssueId from repository $Repository. Error: $($gitHubIssue.message)"
        }
        $this.Issue = $gitHubIssue
    }

    <#
        Gets the issue from GitHub.
    #>
    static [GitHubIssue] Get([int] $IssueId, [string] $Repository) {
        $gitHubIssue = [GitHubIssue]::new($IssueId, $Repository)

        return $gitHubIssue
    }

    <#
        Returns true if the issue is approved, otherwise returns false.
        Issue is considered approved if it has a label named "approved".
    #>
    [bool] IsApproved() {
        if(-not $this.Issue.labels) {
            return $false
        }

        return $this.Issue.labels.name -contains "approved"
    }
}
