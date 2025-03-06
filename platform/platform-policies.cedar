@id("platform-administrator")
permit(
  principal in Permguard::IAM::RoleActor::"platform-admin",
  action in [MagicFarmacia::Platform::Action::"view", MagicFarmacia::Platform::Action::"create", MagicFarmacia::Platform::Action::"update", MagicFarmacia::Platform::Action::"delete"],
  resource == MagicFarmacia::Platform::Subscription::"e3a786fd07e24bfa95ba4341d3695ae8"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-manager")
permit(
  principal in Permguard::IAM::RoleActor::"platform-manager",
  action in [MagicFarmacia::Platform::Action::"view", MagicFarmacia::Platform::Action::"update"],
  resource == MagicFarmacia::Platform::Subscription::"e3a786fd07e24bfa95ba4341d3695ae8"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-auditor")
permit(
  principal in Permguard::IAM::RoleActor::"platform-auditor",
  action == MagicFarmacia::Platform::Action::"view",
  resource == MagicFarmacia::Platform::Subscription::"e3a786fd07e24bfa95ba4341d3695ae8"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-viewer")
permit(
  principal in Permguard::IAM::RoleActor::"platform-viewer",
  action == MagicFarmacia::Platform::Action::"view",
  resource == MagicFarmacia::Platform::Subscription::"e3a786fd07e24bfa95ba4341d3695ae8"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-creator")
permit(
  principal,
  action == MagicFarmacia::Platform::Action::"create",
  resource
)
when { 
  context.isSubscriptionActive == true && action.isEnabled == true && resource.isEnabled == true
}
unless {
  principal.isSuperUser == false
};

