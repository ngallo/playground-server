@id("branch-administration")
permit(
  principal == Permguard::Identity::Attribute::"role/platform-admin",
  action in [ PharmaGovFlow::Platform::Action::"view", PharmaGovFlow::Platform::Action::"create",
    PharmaGovFlow::Platform::Action::"update", PharmaGovFlow::Platform::Action::"delete"],
  resource is PharmaGovFlow::Platform::Branch
);

@id("branch-team-management")
permit(
  principal == Permguard::Identity::Attribute::"role/branch-owner",
  action == PharmaGovFlow::Platform::Action::"assign-role",
  resource is PharmaGovFlow::Platform::Branch
);
