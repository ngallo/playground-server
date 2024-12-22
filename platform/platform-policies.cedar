permit(
	principal in Permguard::Actor::"inventory-auditor",
	action in Action::"view",
	resource in MagicFarmacia::Branch::Inventory::"*"
);

// Here the best part;
@id("assign-role-branch")
permit(
	principal in Permguard::Actor::"administer-branches-staff",
	action in Action::"assignRole",
	resource in MagicFarmacia::Branch::Staff::"*"
)
when {
	principal.active == true &&
	context.id > 0
}
unless {
	principal has isTerminated && principal.isTerminated
};
