/*
 * Copyright (C) 2013-2014 FUJITSU LIMITED
 * Author: Zhang Yanfei <zhangyanfei@cn.fujitsu.com>
 * Signed-off-by: Qiao Nuohan <qiaonuohan@cn.fujitsu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "defs.h"

void ksm_init(void);
void ksm_fini(void);

void cmd_ksm(void);
char *help_ksm[];

static struct command_table_entry command_table[] = {
        { "ksm", cmd_ksm, help_ksm, 0},
        { NULL },
};

struct ksm_offset_table {
	long stable_node_node;
	long stable_node_hlist;
	long stable_node_kpfn;
	long rmap_item_mm;
	long rmap_item_address;
	long rmap_item_hlist;
} ksm_offset_table;

#define KSM_ASSIGN_OFFSET(X) (ksm_offset_table.X)
#define KSM_INVALID_MEMBER(X) (ksm_offset_table.X == INVALID_OFFSET)
#define KSM_MEMBER_OFFSET_INIT(X, Y, Z) (KSM_ASSIGN_OFFSET(X) = MEMBER_OFFSET(Y, Z))
#define KSM_ANON_MEMBER_OFFSET_INIT(X, Y, Z) (KSM_ASSIGN_OFFSET(X) = ANON_MEMBER_OFFSET(Y, Z))
#define KSM_OFFSET(X)  (OFFSET_verify(ksm_offset_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))

struct meminfo {
	int memtype;
	ulong flags;
	ulonglong spec_addr;
};

struct page_ref {
        ulong mm;
        ulong pid;
        int ref;
	struct page_ref *next;
};

static void dump_ksm(struct meminfo *);

void __attribute__((constructor))
ksm_init(void) /* Register the command set. */
{
	if (STRUCT_EXISTS("stable_node")) {
		KSM_MEMBER_OFFSET_INIT(stable_node_node, "stable_node", "node");
		if (KSM_INVALID_MEMBER(stable_node_node))
			KSM_ANON_MEMBER_OFFSET_INIT(stable_node_node, "stable_node", "node");

		KSM_MEMBER_OFFSET_INIT(stable_node_hlist, "stable_node", "hlist");
		KSM_MEMBER_OFFSET_INIT(stable_node_kpfn, "stable_node", "kpfn");
		KSM_MEMBER_OFFSET_INIT(rmap_item_mm, "rmap_item", "mm");
		KSM_MEMBER_OFFSET_INIT(rmap_item_address, "rmap_item", "address");
		KSM_ANON_MEMBER_OFFSET_INIT(rmap_item_hlist, "rmap_item", "hlist");
	} else
		error(FATAL, "ksm_init: stable_node does not exist\n");

       	register_extension(command_table);
}

void __attribute__((destructor))
ksm_fini(void) { }

void
cmd_ksm(void)
{
        int i, c, vflag, pflag;
	ulong ksm_pages_shared;
        ulonglong value[MAXARGS];
	int spec_addr;
	struct meminfo meminfo;

	vflag = pflag = spec_addr = 0;
	BZERO(&meminfo, sizeof (struct meminfo));

        while ((c = getopt(argcnt, args, "vp")) != EOF) {
                switch(c)
                {
		case 'v':
			vflag++;
			break;
		case 'p':
			pflag++;
			break;
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	get_symbol_data("ksm_pages_shared", sizeof(ulong), &ksm_pages_shared);
	if (!ksm_pages_shared)
		error(FATAL, "no ksm pages in the system\n");

        while (args[optind]) {
		if (hexadecimal(args[optind], 0))
                        value[spec_addr++] =
                                htoll(args[optind], FAULT_ON_ERROR, NULL);
		optind++;
	}

	for (i = 0; i < spec_addr; i++) {
		meminfo.spec_addr = value[i];
		meminfo.flags = ADDRESS_SPECIFIED;
		if (pflag)
                	meminfo.memtype = PHYSADDR;
		else
                	meminfo.memtype = IS_KVADDR(value[i]) ? KVADDR : PHYSADDR;
		if (meminfo.memtype == PHYSADDR)
			meminfo.spec_addr = (ulonglong)PHYSPAGEBASE(meminfo.spec_addr);
		if (vflag)
			meminfo.flags |= VERBOSE;
		dump_ksm(&meminfo);
	}

	if (!spec_addr) {
		if (vflag) {
			meminfo.flags |= VERBOSE;
			dump_ksm(&meminfo);
		} else
			dump_ksm(NULL);
        }
}

char *help_ksm[] = {
        "ksm",
        "kernel samepage merging (KSM) information",
        "[-v] [[-p] address ...]",

        "  This command displays information about all KSM pages currently",
        "  in use.  For each KSM page, the display includes its stable_node",
        "  address, its page struct address, its physical address, the TGID/PID",
        "  for each task that is using the page, the number of mappings in the",
        "  task's address space for the page, and the mm_struct address of the",
        "  task. If pid is '-', the task has exited and the ksm page has not",
        "  been removed.",
        " ",
        "       -v  also dump each virtual address in a PID's virtual address",
        "           space that maps the KSM page.",
        "  address  restricts the output to the KSM data associated with a",
        "           stable_node address, a page's physical address, or a page",
        "           pointer.",
        "       -p  specifies that the address argument is a physical address,",
        "           for architectures that require it.",
        "\nEXAMPLE",
        "  Display information about all KSM pages:\n",
        "    %s> ksm",
        "                PAGE: ffffea000451f180",
        "         STABLE_NODE: ffff88004866b6c0",
        "    PHYSICAL ADDRESS: 1147c6000",
        "                 PID: 1318  MAPPINGS: 7707  MM: ffff88007f8abe80",
        "                 PID: 1297  MAPPINGS: 4965  MM: ffff88007f8aa580",
        "",
        "                PAGE: ffffea0003413c40",
        "         STABLE_NODE: ffff880117bfbfc0",
        "    PHYSICAL ADDRESS: d04f1000",
        "                 PID: 1297  MAPPINGS: 1  MM: ffff88007f8aa580",
        "                 PID: 1318  MAPPINGS: 1  MM: ffff88007f8abe80",
        "",
        "                PAGE: ffffea00021e9880",
        "         STABLE_NODE: ffff880054ee1f30",
        "    PHYSICAL ADDRESS: 87a62000",
        "                 PID: 1297  MAPPINGS: 2  MM: ffff88007f8aa580",
        "    ...",
        "",
        "  Display all information about the KSM page whose physical",
        "  address is 0xffffea000168cd00:\n",
        "    %s> ksm -v ffffea000168cd00",
        "                PAGE: ffffea000168cd00",
        "         STABLE_NODE: ffff88007153ce10",
        "    PHYSICAL ADDRESS: 5a334000",
        "                 PID: 1297  MAPPINGS: 4  MM: ffff88007f8aa580",
        "                 VIRTUAL:",
        "                 7f8cb91f9000",
        "                 7f8cb8f28000",
        "                 7f8cb7abf000",
        "                 7f8cb79c7000",
        "",
        "                 PID: 1318  MAPPINGS: 4  MM: ffff88007f8abe80",
        "                 VIRTUAL:",
        "                 7f7ca0703000",
        "                 7f7c9f15e000",
        "                 7f7c9ef8f000",
        "                 7f7c9e96b000",
        NULL
};

/*
 * find the page_ref whose mm is same as mm
 */
static struct page_ref *
find_match_ref(struct page_ref *ref_list, ulong mm)
{
	struct page_ref *next_ref = ref_list;

	while (next_ref) {
		if (next_ref->mm == mm) {
			break;
		} else {
			next_ref = next_ref->next;
		}
	}

	return next_ref;
}

/*
 * get the pid of the task that mm_struct belongs to, if not find,
 * return (ulong)-1
 */
static ulong
find_pid(ulong mm)
{
	struct task_context *tc;
	int i;
	ulong pid = -1;

	tc = FIRST_CONTEXT();
	for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (tc->mm_struct == mm) {
			pid = tc->pid;
			break;
		}
	}

	return pid;
}

static void
add_to_ref_list(struct page_ref **ref_list_ptr, struct page_ref *ref)
{
	ref->next = *ref_list_ptr;
	*ref_list_ptr = ref;
}

static void
clean_ref_list(struct page_ref *ref_list)
{
	struct page_ref *tmp_ref, *next_ref;

	tmp_ref = ref_list;

	while (tmp_ref) {
		next_ref = tmp_ref->next;
		FREEBUF(tmp_ref);
		tmp_ref = next_ref;
	}
}

/*
 * dump the ksm pages from the stable tree
 */
static void
dump_stable_tree(struct meminfo *mi, struct rb_root *root)
{
	ulong stable_node, kpfn;
	ulong rmap_item, mm, paddr;
	struct rb_node *node;
	ulong first, next;
	int found;
	struct page_ref *ref_list;
	ulong page, address;

	found = (mi && mi->flags & ADDRESS_SPECIFIED) ? 0 : -1;

	for (node = rb_first(root); node; node = rb_next(node)) {
		stable_node = (ulong) node - KSM_OFFSET(stable_node_node);
		if (CRASHDEBUG(1))
			fprintf(fp, "  stable_node = %lx\n", stable_node);

		readmem(stable_node + KSM_OFFSET(stable_node_kpfn),
			KVADDR, &kpfn, sizeof(ulong),
			"stable_node kpfn", FAULT_ON_ERROR);
		paddr = kpfn << PAGE_SHIFT;
		phys_to_page(paddr, &page);

		if (found == 0) {
			if ((mi->memtype == KVADDR) &&
			    (((mi->spec_addr & ~0x3) == stable_node) ||
			     (mi->spec_addr == page)))
				found = 1;
			if ((mi->memtype == PHYSADDR) &&
			    (mi->spec_addr == paddr))
				found = 1;
		}
		if (found == 0)
			continue;

		fprintf(fp, "            PAGE: %lx\n", page);
		fprintf(fp, "     STABLE_NODE: %lx\n", stable_node);
		fprintf(fp, "PHYSICAL ADDRESS: %lx\n", paddr);

		readmem(stable_node + KSM_OFFSET(stable_node_hlist),
			KVADDR, &first, sizeof(ulong),
			"stable_node hlist", FAULT_ON_ERROR);

		next = first;
		ref_list = NULL;
		struct page_ref *tmp_ref = NULL;

		while (next) {
			rmap_item = next - KSM_OFFSET(rmap_item_hlist);
			readmem(rmap_item + KSM_OFFSET(rmap_item_mm),
				KVADDR, &mm, sizeof(ulong),
				"rmap_item mm", FAULT_ON_ERROR);

			//get the page_ref whose mm is equal to rmap_item's mm
			tmp_ref = find_match_ref(ref_list, mm);
			if (tmp_ref) {
				tmp_ref->ref += 1;
			} else {
				//create a new page_ref
				tmp_ref = (struct page_ref *)GETBUF(
						sizeof(struct page_ref));
				tmp_ref->mm = mm;
				tmp_ref->pid = find_pid(mm);
				tmp_ref->ref = 1;

				add_to_ref_list(&ref_list, tmp_ref);
			}

			readmem(next + OFFSET(hlist_node_next),
				KVADDR, &next, sizeof(ulong),
				"hlist_node next", FAULT_ON_ERROR);
		};

		tmp_ref = ref_list;
		while (tmp_ref) {
			if (tmp_ref->pid == (ulong)-1) {
				/*
				 * the task has exited, but the ksm pages has
				 * not been cleared yet.
				 */
				fprintf(fp, "             PID: - ");
			} else {
				fprintf(fp, "             PID: %ld ", tmp_ref->pid);
			}
			fprintf(fp, " MAPPINGS: %d ", tmp_ref->ref);
			fprintf(fp, " MM: %lx\n", tmp_ref->mm);

			if (!(mi && mi->flags & VERBOSE))
				goto next_ref;

			fprintf(fp, "             VIRTUAL:\n");
			next = first;
			while (next) {
				rmap_item = next - KSM_OFFSET(rmap_item_hlist);
				readmem(rmap_item + KSM_OFFSET(rmap_item_mm),
					KVADDR, &mm, sizeof(ulong),
					"rmap_item mm", FAULT_ON_ERROR);
				if (tmp_ref->mm == mm) {
					readmem(rmap_item + KSM_OFFSET(rmap_item_address),
						KVADDR, &address, sizeof(ulong),
						"rmap_item address", FAULT_ON_ERROR);
					fprintf(fp, "             %lx\n",
						PAGEBASE(address));
				}
				readmem(next + OFFSET(hlist_node_next),
					KVADDR, &next, sizeof(ulong),
					"hlist_node next", FAULT_ON_ERROR);
			}
			fprintf(fp, "\n");

next_ref:
			tmp_ref = tmp_ref->next;
		}

		//clear all page_ref
		clean_ref_list(ref_list);

		if (!(mi && mi->flags & VERBOSE))
			fprintf(fp, "\n");

		if (found == 1)
			break;
	}

	if (found == 0)
		fprintf(fp, "address 0x%llx cannot specify a ksm stable tree node\n",
			mi->spec_addr);
}

/*
 * dump_ksm() displays information of ksm pages.
 */
static void
dump_ksm(struct meminfo *mi)
{
	ulong root_stable_tree_ptr;
	ulong ksm_nr_node_ids_ptr;
	int ksm_nr_node_ids;
	struct rb_root *root;
	int i;

	if (!symbol_exists("root_stable_tree")) {
		error(INFO, "cannot determine ksm stable tree address from root_stable_tree\n");
		return;
	}
	root_stable_tree_ptr = symbol_value("root_stable_tree");

	if (symbol_exists("ksm_nr_node_ids")) {
		//root_stable_tree_ptr is an array of stable tree root
		ksm_nr_node_ids_ptr = symbol_value("ksm_nr_node_ids");
		readmem(ksm_nr_node_ids_ptr, KVADDR, &ksm_nr_node_ids,
			sizeof(ksm_nr_node_ids), "ksm_nr_node_ids",
			FAULT_ON_ERROR);

		readmem(root_stable_tree_ptr, KVADDR, &root, sizeof(ulong),
			"first stable tree root", FAULT_ON_ERROR);
		
		for (i = 0; i < ksm_nr_node_ids; i++) {
			dump_stable_tree(mi, root + i);
		}
	} else {
		root = (struct rb_root *)root_stable_tree_ptr;
		dump_stable_tree(mi, root);
	}
}
