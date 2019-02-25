#pragma once

#include "type.h"
#include "ps4.h"

#define	KERN_XFAST_SYSCALL 0x1C0      //5.05
#define KERN_PROCESS_ASLR 0x194875
#define KERN_PRISON_0 0x10986A0
#define KERN_ROOTVNODE 0x22C1A70
#define KERN_PTRACE_CHECK 0x30D9AA
#define KERN_COPY_IN 0x1EA710
#define KERN_COPY_OUT 0x1EA630
#define KERN_COPY_IN_PATCH 0x1EA767
#define KERN_COPY_OUT_PATCH 0x1EA682
#define KERN_GET_SEALED_KEY_KEY_AND_SECRET 0x61F800

#define X86_CR0_WP (1 << 16)

struct auditinfo_addr {
	/*
	4    ai_auid;
	8    ai_mask;
	24    ai_termid;
	4    ai_asid;
	8    ai_flags;r
	*/
	char useless[184];
};

struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;     // effective user id
	uint32_t cr_ruid;    // real user id
	uint32_t useless2;
	uint32_t useless3;
	uint32_t cr_rgid;    // real group id
	uint32_t useless4;
	void *useless5;
	void *useless6;
	void *cr_prison;     // jail(2)
	void *useless7;
	uint32_t useless8;
	void *useless9[2];
	void *useless10;
	struct auditinfo_addr useless11;
	uint32_t *cr_groups; // groups
	uint32_t useless12;
};

struct filedesc {
	void *useless1[3];
	void *fd_rdir;
	void *fd_jdir;
};

struct proc {
	char useless[64];
	struct ucred *p_ucred;
	struct filedesc *p_fd;
};

struct thread {
	void *useless;
	struct proc *td_proc;
};

struct payload_info
{
  uint8_t* bufSealedKey;
  uint8_t* bufSealedSecret;
  size_t size;
};

struct get_sealed_key_payload_args
{
  void* syscall_handler;
  struct payload_info* payload_info;
};

int kernelPayload(struct thread *td, void* uap);

int getSealedKeyAndSecretPayload(void* td, struct get_sealed_key_payload_args* args);

typedef int (*copyin_ptr)(const void *uaddr, void *kaddr, size_t len);
typedef int (*copyout_ptr)(const void	*kaddr,	void *uaddr, size_t len);
typedef int (*GetSealedKeyKeyAndSecret_ptr)(void *p1, void *p2);
