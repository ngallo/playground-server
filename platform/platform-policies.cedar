@id("platform-administrator")
permit(
  principal in Permguard::IAM::Actor::"platform-admin",
  action in [MagicFarmacia::Platform::Action::"view", MagicFarmacia::Platform::Action::"create", MagicFarmacia::Platform::Action::"update", MagicFarmacia::Platform::Action::"delete"],
  resource == MagicFarmacia::Platform::BranchInfo::"subscription"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-manager")
permit(
  principal in Permguard::IAM::Actor::"platform-admin",
  action in [MagicFarmacia::Platform::Action::"view", MagicFarmacia::Platform::Action::"update"],
  resource == MagicFarmacia::Platform::BranchInfo::"subscription"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-auditor")
permit(
  principal in Permguard::IAM::Actor::"platform-auditor",
  action == MagicFarmacia::Platform::Action::"view",
  resource == MagicFarmacia::Platform::BranchInfo::"subscription"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("amy.smith")
permit(
  principal in Permguard::IAM::User::"amy.smith@acmecorp.com",
  action == MagicFarmacia::Platform::Action::"create",
  resource == MagicFarmacia::Platform::BranchInfo::"subscription"
)
when {
  context.demoRequest == true
}
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-superuser")
permit(
  principal,
  action == MagicFarmacia::Platform::Action::"view",
  resource == MagicFarmacia::Platform::BranchInfo::"subscription"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};