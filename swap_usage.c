
/* swap-usage.c - Check actual swap consumption for each process
 *
 * Aaron Tomlin <atomlin@redhat.com>
 *
 * Copyright (C) 2013 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "defs.h"

#define DISPLAY_KB      (0x2)
#define DISPLAY_TG      (0x4)

#ifdef	ARM
#define _PAGE_FILE	(1 << 2)
#endif	/* ARM */

#ifdef	X86
#define _PAGE_FILE	(1 << 6) /* _PAGE_BIT_DIRTY */
#endif	/* X86 */

#ifdef	X86_64
/* set in defs.h already */
#define _PAGE_FILE	0x040
#endif /* X86_64 */

#ifdef	ALPHA
#define	_PAGE_FILE	0x80000 /* set:pagecache, unset:swap */
#endif	/* ALPHA */

#ifdef	IA64
#define	_PAGE_FILE	(1 << 1) /* see swap & file pte remarks below */
#endif	/* IA64 */

#ifdef	S390
#define	_PAGE_FILE	0x601
#endif	/* S390 */

#define pte_file_present(pte) (pte & _PAGE_FILE)

#define MEMBER_FOUND 1
#define MEMBER_NOT_FOUND 0
#define PRINT_HEADER() \
		fprintf(fp, \
	"PID     SWAP     COMM\n");

int _init(void);
int _fini(void);

void cmd_pswap(void);
char *help_pswap[];

static unsigned int swap_usage_offset;

static struct command_table_entry command_table[] = {
	{ "pswap", cmd_pswap, help_pswap, 0 },
	{ NULL }
};

int 
_init(void)
{ 
        register_extension(command_table);
	return 1;
}
 
int 
_fini(void) 
{ 
	return 1;
}

void
show_swap_usage(struct task_context *tc, ulong exists, ulong flag) 
{
	struct task_mem_usage task_mem_usage, *tm;
	tm = &task_mem_usage;
	get_task_mem_usage(tc->task, tm);
	physaddr_t paddr;
	ulong mm;
	ulong vma;
	ulong vm_start;
	ulong vm_end;
	ulong vm_next;
	ulong swap_usage = 0;

	readmem(tc->task + OFFSET(task_struct_mm), KVADDR, &mm,
		sizeof(void *), "mm_struct mm", FAULT_ON_ERROR);

	if (!mm)
		return;

	switch (exists) {
	case MEMBER_FOUND:

		readmem((mm + swap_usage_offset), KVADDR, &swap_usage,
			sizeof(void *), "mm_counter_t", FAULT_ON_ERROR);

		break;

	case MEMBER_NOT_FOUND:
	default:

		readmem(mm + OFFSET(mm_struct_mmap), KVADDR, &vma,
			sizeof(void *), "mm_struct mmap", FAULT_ON_ERROR);

		for (; vma; vma = vm_next) {

			readmem(vma + OFFSET(vm_area_struct_vm_start), KVADDR, &vm_start,
				sizeof(void *), "vm_area_struct vm_start", FAULT_ON_ERROR);

			readmem(vma + OFFSET(vm_area_struct_vm_end), KVADDR, &vm_end,
				sizeof(void *), "vm_area_struct vm_end", FAULT_ON_ERROR);

			readmem(vma + OFFSET(vm_area_struct_vm_next), KVADDR, &vm_next,
				sizeof(void *), "vm_area_struct vm_next", FAULT_ON_ERROR);

			while (vm_start < vm_end) {
				if (!uvtop(tc, vm_start, &paddr, 0)) {

					if (paddr && !(pte_file_present(paddr))) {
						swap_usage++;
					}
				}
				vm_start += PAGESIZE();
			}
		}
	}
	if (flag & DISPLAY_KB)
		swap_usage  <<= (PAGESHIFT()-10);

	fprintf(fp, "%3ld  %6ld%s%5s\n", tc->pid, swap_usage,
		(flag & DISPLAY_KB) ? "k\t" : "\t", tc->comm);
}


void
cmd_pswap(void)
{
	struct task_context *tc;
	int i;
	int c;
	ulong value;
	ulong flag = 0;
	ulong tgid;
	int subsequent = 0;
	ulong exists = MEMBER_NOT_FOUND;

	if (MEMBER_EXISTS("mm_struct", "_swap_usage")) {
		swap_usage_offset = MEMBER_OFFSET("mm_struct", "_swap_usage");
		exists = MEMBER_FOUND;
	}

	while ((c = getopt(argcnt, args, "kG")) != EOF) {
		switch (c) {
                case 'k':
                        flag |= DISPLAY_KB;
                        break;
		case 'G':
                        flag |= DISPLAY_TG;
                        break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

        if (!args[optind]) {
                PRINT_HEADER();
                tc = FIRST_CONTEXT();
                for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
                        if (!is_kernel_thread(tc->task)) {
				if (flag & DISPLAY_TG) {
					tgid = task_tgid(tc->task);
					if (tc->pid != tgid)
						continue;
					tc = tgid_to_context(tgid);
				}
				show_swap_usage(tc, exists, flag);
			}
                }
		return;
        }

	PRINT_HEADER();
	while (args[optind]) {
		switch (str_to_context(args[optind], &value, &tc)) {
		case STR_PID:
			for (tc = pid_to_context(value); tc; tc = tc->tc_next) {
				if (!is_kernel_thread(tc->task)) {
					if (flag & DISPLAY_TG) {
						tgid = task_tgid(tc->task);
						if (tc->pid != tgid)
							continue;
						tc = tgid_to_context(tgid);
					}
					show_swap_usage(tc, exists, flag);
				} else {
					error(INFO, "only specify a user task or pid: %s\n",
						args[optind]);
				}
			}
			break;

		case STR_TASK:
			for (; tc; tc = tc->tc_next) {
				if (!is_kernel_thread(tc->task)) {
					if (flag & DISPLAY_TG) {
						tgid = task_tgid(tc->task);
						if (tc->pid != tgid)
							continue;
						tc = tgid_to_context(tgid);
					}
					show_swap_usage(tc, exists, flag);
				} else {
					error(INFO, "only specify a user task or pid: %s\n",
						args[optind]);
				}
			}
			break;

		case STR_INVALID:
			error(INFO, "invalid task or pid value: %s\n",
				args[optind]);
			break;
		}

		subsequent++;
		optind++;
	}
}

char *help_pswap[] = {
	"pswap",
	"Returns the actual swap consumption of a user process",
	"[-k -G] [pid | taskp]",

	"  This command obtains the swap consumption (in pages) of a user process.",
	"  The process list may be restricted with the following options:\n",
        "  	-k print in kilobytes.\n"
        "  	-G show only the thread group leader in a thread group.\n"
	" ",
	"  If no arguments are specified, every user process will be checked.",
	"  Supported on ARM, X86, X86_64, ALPHA, IA64 and S390 only.",
	"\nEXAMPLE",
	"  Show the swap consumption for pid 1232, 1353 and 2275:\n",
	"    crash> pswap 1232 1353 2275",
	"     PID     SWAP    COMM",
	"     1232     34    auditd",
	"     1353    526       vi",
	"     2275  30237    gnome-shell",
	"    crash>",
	" ",
	" Show the swap consumption for thread group leaders only:\n",
	"    crash> pswap -G",
	"     PID     SWAP    COMM",
	"     469      71      zsh",
	"     599      37    systemd-journal",
	"     608     298    lvmetad",
	"     637     428    systemd-udevd",
	"     822      77    auditd",
	"     836      26    audispd",
	"     838      39    sedispatch",
	"     842      23    alsactl",
	"     844      44    bluetoothd",
	"     851      46    rtkit-daemon",
	"     852      59    accounts-daemon",
	"     855      23    avahi-daemon",
	"     857      96    rsyslogd",
	"     858     179    restorecond",
	"     859     144    smartd",
	"     862      33    irqbalance",
	"     867      41    systemd-logind",
	"     868      37    dbus-daemon",
	"    crash>",
	NULL
};
