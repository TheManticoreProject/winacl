package windows

const (
	ACE_FLAG_OBJECT_INHERIT       = 0x01 // Noncontainer child objects inherit the ACE as an effective ACE.
	ACE_FLAG_CONTAINER_INHERIT    = 0x02 // Child objects that are containers, such as directories, inherit the ACE as an effective ACE. The inherited ACE is inheritable unless the NO_PROPAGATE_INHERIT_ACE bit flag is also set.
	ACE_FLAG_NO_PROPAGATE_INHERIT = 0x04 // If the ACE is inherited by a child object, the system clears the OBJECT_INHERIT_ACE and CONTAINER_INHERIT_ACE flags in the inherited ACE. This prevents the ACE from being inherited by subsequent generations of objects.
	ACE_FLAG_INHERIT_ONLY         = 0x08 // Indicates an inherit-only ACE, which does not control access to the object to which it is attached. If this flag is not set, the ACE is an effective ACE that controls access to the object to which it is attached.
	ACE_FLAG_INHERITED            = 0x10 // Used to indicate that the ACE was inherited. See section 2.5.3.5 for processing rules for setting this flag.
	ACE_FLAG_SUCCESSFUL_ACCESS    = 0x40 // Used with system-audit ACEs in a system access control list (SACL) to generate audit messages for successful access attempts.
	ACE_FLAG_FAILED_ACCESS        = 0x80 // Used with system-audit ACEs in a system access control list (SACL) to generate audit messages for failed access attempts.
)
