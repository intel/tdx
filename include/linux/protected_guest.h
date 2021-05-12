#ifndef _LINUX_PROTECTED_GUEST_H
#define _LINUX_PROTECTED_GUEST_H 1

#define PROTECTED_GUEST_BITMAP_LEN	128

/* Protected Guest vendor types */
#define GUEST_TYPE_TDX			(1)
#define GUEST_TYPE_SEV			(2)

/* Protected Guest features */
#define MEMORY_ENCRYPTION		(20)

#ifdef CONFIG_ARCH_HAS_PROTECTED_GUEST
extern DECLARE_BITMAP(protected_guest_flags, PROTECTED_GUEST_BITMAP_LEN);

static bool protected_guest_has(unsigned long flag)
{
	return test_bit(flag, protected_guest_flags);
}

static inline void set_protected_guest_flag(unsigned long flag)
{
	__set_bit(flag, protected_guest_flags);
}

static inline bool is_protected_guest(void)
{
	return ( protected_guest_has(GUEST_TYPE_TDX) |
		 protected_guest_has(GUEST_TYPE_SEV) );
}
#else
static inline bool protected_guest_has(unsigned long flag) { return false; }
static inline void set_protected_guest_flag(unsigned long flag) { }
static inline bool is_protected_guest(void) { return false; }
#endif

#endif
