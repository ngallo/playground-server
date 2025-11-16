@id("platform-administrator")
permit(
  principal == Permguard::Identity::Attribute::"role/platform-admin",
  action in [ PharmaAuthZFlow::Platform::Action::"view", PharmaAuthZFlow::Platform::Action::"create", 
    PharmaAuthZFlow::Platform::Action::"update", PharmaAuthZFlow::Platform::Action::"delete"],
  resource is PharmaAuthZFlow::Platform::Subscription
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-manager")
permit(
  principal == Permguard::Identity::Attribute::"role/platform-manager",
  action in [PharmaAuthZFlow::Platform::Action::"view", PharmaAuthZFlow::Platform::Action::"update"],
  resource is PharmaAuthZFlow::Platform::Subscription
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-auditor")
permit(
  principal == Permguard::Identity::Attribute::"role/platform-auditor",
  action == PharmaAuthZFlow::Platform::Action::"view",
  resource is PharmaAuthZFlow::Platform::Subscription
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-viewer")
permit(
  principal == Permguard::Identity::Attribute::"role/platform-viewer",
  action == PharmaAuthZFlow::Platform::Action::"view",
  resource is PharmaAuthZFlow::Platform::Subscription
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-executor")
permit(
  principal == Permguard::Identity::Attribute::"role/platform-executor",
  action == PharmaAuthZFlow::Platform::Action::"create",
  resource is PharmaAuthZFlow::Platform::Subscription
)
when { 
  context.isSubscriptionActive == true && action.isEnabled == true && resource.isEnabled == true
}
unless {
  principal.isSuperUser == false
};

