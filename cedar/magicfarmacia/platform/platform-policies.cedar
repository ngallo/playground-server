@id("platform-administrator")
permit(
  principal == Permguard::IAM::User::"platform-admin",
  action in [ MagicFarmacia::Platform::Action::"view", MagicFarmacia::Platform::Action::"create", 
    MagicFarmacia::Platform::Action::"update", MagicFarmacia::Platform::Action::"delete"],
  resource is MagicFarmacia::Platform::Subscription
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-manager")
permit(
  principal == Permguard::IAM::User::"platform-manager",
  action in [MagicFarmacia::Platform::Action::"view", MagicFarmacia::Platform::Action::"update"],
  resource is MagicFarmacia::Platform::Subscription
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-auditor")
permit(
  principal == Permguard::IAM::User::"platform-auditor",
  action == MagicFarmacia::Platform::Action::"view",
  resource is MagicFarmacia::Platform::Subscription
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-viewer")
permit(
  principal == Permguard::IAM::User::"platform-viewer",
  action == MagicFarmacia::Platform::Action::"view",
  resource is MagicFarmacia::Platform::Subscription
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-executor")
permit(
  principal == Permguard::IAM::User::"platform-executor",
  action == MagicFarmacia::Platform::Action::"create",
  resource is MagicFarmacia::Platform::Subscription
)
when { 
  context.isSubscriptionActive == true && action.isEnabled == true && resource.isEnabled == true
}
unless {
  principal.isSuperUser == false
};

