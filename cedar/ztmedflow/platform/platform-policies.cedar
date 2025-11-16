@id("platform-administrator")
permit(
  principal == Permguard::Identity::Attribute::"role/platform-admin",
  action in [ ZTMedFlow::Platform::Action::"view", ZTMedFlow::Platform::Action::"create", 
    ZTMedFlow::Platform::Action::"update", ZTMedFlow::Platform::Action::"delete"],
  resource is ZTMedFlow::Platform::Subscription
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-manager")
permit(
  principal == Permguard::Identity::Attribute::"role/platform-manager",
  action in [ZTMedFlow::Platform::Action::"view", ZTMedFlow::Platform::Action::"update"],
  resource is ZTMedFlow::Platform::Subscription
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-auditor")
permit(
  principal == Permguard::Identity::Attribute::"role/platform-auditor",
  action == ZTMedFlow::Platform::Action::"view",
  resource is ZTMedFlow::Platform::Subscription
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-viewer")
permit(
  principal == Permguard::Identity::Attribute::"role/platform-viewer",
  action == ZTMedFlow::Platform::Action::"view",
  resource is ZTMedFlow::Platform::Subscription
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-executor")
permit(
  principal == Permguard::Identity::Attribute::"role/platform-executor",
  action == ZTMedFlow::Platform::Action::"create",
  resource is ZTMedFlow::Platform::Subscription
)
when { 
  context.isSubscriptionActive == true && action.isEnabled == true && resource.isEnabled == true
}
unless {
  principal.isSuperUser == false
};

