permit(
    principal in Role::"administer-platform-branches",
    action in Action::"pharmacy-branch-management",
    resource in Resource::"pharmacy-branch"
) when {
    principal.account == 345
};