/* memutils.c - Provides memory related information
 * other than those provided by kmem command.
 * Currently the following are supported.
 *
 * 1) The page count per migrate type for all orders,
 *    for all nodes.
 *
 * Copyright (C) 2013, Vinayak Menon <vinayakm.list@gmail.com>
 * Author: Vinayak Menon <vinayakm.list@gmail.com>
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

void memutils_init(void);
void memutils_fini(void);

void cmd_memutils(void);
char *help_memutils[];

static struct command_table_entry command_table[] = {
	{ "memutils", cmd_memutils, help_memutils, 0},
	{ NULL },
};

static void dump_pgtype_info(void);

void __attribute__((constructor))
memutils_init(void)
{
	register_extension(command_table);
}

void __attribute__((destructor))
memutils_fini(void) { }


void
cmd_memutils(void)
{
	int c;
	int pflag = 0;

	while ((c = getopt(argcnt, args, "p")) != EOF) {
		switch (c) {

		case 'p':
			pflag = 1;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (pflag == 1)
		dump_pgtype_info();
}

static void dump_pgtype_info(void)
{
	int n, m, z, o;
	int list_count = 0;
	ulong free_cnt = 0;
	int mtype_sym = 0;
	int mtype_len = 0;
	ulong *mtypes;
	ulong node_zones;
	ulong temp;
	ulong freelist;
	ulong *free_ptr;
	char *free_list_buf;
	char name_buf[BUFSIZE];
	char buf[BUFSIZE];
	struct node_table *nt;
	struct list_data list_data;

	if (!(vt->flags & (NODES|ZONES)))
		error(FATAL,
			"dump_pgtype_info called without (NODES|ZONES)\n");

	if (!VALID_STRUCT(zone))
		error(FATAL,
			"zone struct not available in this kernel\n");

	if (VALID_STRUCT(free_area)) {
		if (SIZE(free_area) == (3 * sizeof(ulong)))
			error(FATAL,
				"free_area type not supported by command\n");
		else
			list_count = MEMBER_SIZE("free_area",
					"free_list")/SIZE(list_head);
	} else
		error(FATAL,
			"free_area structure not found in this kernel\n");

	free_list_buf = GETBUF(SIZE(list_head));

	do {
		if (symbol_exists("migratetype_names") &&
			(get_symbol_type("migratetype_names",
					 NULL, NULL) == TYPE_CODE_ARRAY)) {

			open_tmpfile();
			sprintf(buf, "whatis migratetype_names");
			if (!gdb_pass_through(buf, fp, GNU_RETURN_ON_ERROR)) {
				close_tmpfile();
				break;
			}

			rewind(pc->tmpfile);
			while (fgets(buf, BUFSIZE, pc->tmpfile)) {
				if (STRNEQ(buf, "type = "))
					break;
			}
			close_tmpfile();

			if (!strstr(buf, "char *") ||
				(count_chars(buf, '[') != 1) ||
				(count_chars(buf, ']') != 1))
				break;

			mtype_len = get_array_length("migratetype_names",
					NULL, 0);

			mtypes = (ulong *)GETBUF(mtype_len * sizeof(ulong));

			readmem(symbol_value("migratetype_names"),
					KVADDR, mtypes,
					(mtype_len * sizeof(ulong)),
					NULL, FAULT_ON_ERROR);

			mtype_sym = 1;
		}
	} while (0);

	fprintf(fp, "%-43s [%d-%d]:",
			"Free pages count per migrate type at order",
			0, vt->nr_free_areas - 1);

	fprintf(fp, "\n");

	for (n = 0; n < vt->numnodes; n++) {
		nt = &vt->node_table[n];
		node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);

		for (m = 0; m < list_count; m++) {

			for (z = 0; z < vt->nr_zones; z++) {
				readmem((node_zones + (z * SIZE(zone)))
					+ OFFSET(zone_name), KVADDR, &temp,
					sizeof(void *), "node_zones name",
					FAULT_ON_ERROR);
				read_string(temp, name_buf, BUFSIZE-1);

				fprintf(fp, "Node %4d, ", nt->node_id);
				fprintf(fp, "zone %8s, ", name_buf);

				if (mtype_sym) {
					read_string(mtypes[m],
						name_buf, BUFSIZE-1);
					fprintf(fp, "type %12s ", name_buf);
				} else
					fprintf(fp, "type %12d ", m);

				for (o = 0; o < vt->nr_free_areas; o++) {
					freelist =
					(node_zones + (z * SIZE(zone)))
					+ (OFFSET(zone_free_area) +
					(o * SIZE(free_area))) +
					(m * SIZE(list_head));

					readmem(freelist, KVADDR, free_list_buf,
						SIZE(list_head),
						"free_area free_list",
						FAULT_ON_ERROR);

					free_ptr = (ulong *)free_list_buf;

					if (!(*free_ptr) ||
						(*free_ptr == freelist)) {
						fprintf(fp, "%6lu ", (ulong)0);
						continue;
					}

					BZERO(&list_data,
						sizeof(struct list_data));
					list_data.flags = RETURN_ON_DUPLICATE;
					list_data.start = *free_ptr;
					list_data.end = freelist;
					list_data.list_head_offset =
						OFFSET(page_lru) +
						OFFSET(list_head_next);

					free_cnt = do_list(&list_data);
					if (free_cnt < 0) {
						error(pc->curcmd_flags &
						IGNORE_ERRORS ? INFO : FATAL,
						"corrupted free list\n");
						free_cnt = 0;
					}

					fprintf(fp, "%6lu ", free_cnt);
				}
				fprintf(fp, "\n");
			}
		}
	}

	FREEBUF(free_list_buf);

	if (mtype_sym)
		FREEBUF(mtypes);
}

char *help_memutils[] = {
	"memutils",
	"memory information",
	"[-p]",

	"The command displays memory information",
	"        -p  displays the number of pages per migrate type for all orders, for all",
	"            nodes.",
	"\nEXAMPLES",
	"\n  Display pages per migrate type for all orders, for all nodes:\n",
	"    %s> memutils -p",
	"    Free pages count per migrate type at order [0-10]:",
	"    Node    0, zone   Normal, type    Unmovable    155    172     92     39     20      8     10     15      7      3      1",
	"    Node    0, zone  HighMem, type    Unmovable      1      2      0      0      0      0      0      0      0      0      0",
	"    Node    0, zone  Movable, type    Unmovable      0      0      0      0      0      0      0      0      0      0      0",
	"    Node    0, zone   Normal, type  Reclaimable      9      3      0      0      1      1      0      0      0      0      0",
	"    Node    0, zone  HighMem, type  Reclaimable      0      0      0      0      0      0      0      0      0      0      0",
	"    Node    0, zone  Movable, type  Reclaimable      0      0      0      0      0      0      0      0      0      0      0",
	"    Node    0, zone   Normal, type      Movable      7     68     35    253    137     38     16      4      0      0     66",
	"    Node    0, zone  HighMem, type      Movable      0      1      0      0      0      0      0      0      0      0      0",
	"    Node    0, zone  Movable, type      Movable      0      0      0      0      0      0      0      0      0      0      0",
	"    Node    0, zone   Normal, type      Reserve      0      0      0      0      0      0      0      0      0      0      1",
	"    Node    0, zone  HighMem, type      Reserve     11      7      5      1      0      0      0      0      0      0      0",
	"    Node    0, zone  Movable, type      Reserve      0      0      0      0      0      0      0      0      0      0      0",
	"    Node    0, zone   Normal, type      Isolate      0      0      0      0      0      0      0      0      0      0      0",
	"    Node    0, zone  HighMem, type      Isolate      0      0      0      0      0      0      0      0      0      0      0",
	"    Node    0, zone  Movable, type      Isolate      0      0      0      0      0      0      0      0      0      0      0",
	NULL
};

