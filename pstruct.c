/* pstruct.c - print structure's member
 *
 * Copyright (C) 2012 FUJITSU LIMITED
 * Author: Qiao Nuohan <qiaonuohan@cn.fujitsu.com>
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

#include "defs.h"    /* From the crash source top-level directory */

#define STRUCTURE_CACHE_MAX_SIZE    10

struct struct_cache {
	char name[100];
	char member[100];
	long type;
	long unsigned_type;
	long length;
	long offset;
	long bitpos;
	long bitsize;
};

int struct_cache_size = -1;
struct struct_cache struct_cache[STRUCTURE_CACHE_MAX_SIZE];

void pstruct_init(void);
void pstruct_fini(void);

void cmd_pstruct(void);     /* Declare the commands and their help data. */
char *help_pstruct[];

static struct struct_cache *get_struct_cache(char *, char *);
static void get_bitfield_data(ulong *, int, int);

static struct command_table_entry command_table[] = {
	{ "pstruct", cmd_pstruct, help_pstruct, 0 },  /* One or more commands, */
	{ NULL }                                      /* terminated by NULL, */
};

void __attribute__((constructor))
pstruct_init(void) /* Register the command set. */
{ 
        register_extension(command_table);
}
 
/* 
 *  The pstruct_fini() function is called if the shared object is unloaded. 
 *  If desired, perform any cleanups here. 
 */
void __attribute__((destructor))
pstruct_fini(void) { }


char *help_pstruct[] = {
        "pstruct",                                     /* command name */
        "print structure member's data in one line",   /* short description */
        "struct_name.member[.member...,member...] [-d|-x] [-l offset]\n"
	"    [address|symbol]",              /* argument synopsis, or " " if none */
 
        "  This command displays the contents of a structure's members in one",
	"  line.\n",
	"  The arguments are as follows:\n",
	"  struct_name  name of a C-code structure used by the kernel.",
	"   .member...  name of a structure member; to display multiple members",
	"               of a structure, use a comma-separated list of members.",
	"    -l offset  if the address argument is a pointer to a structure",
	"               member that is contained by the target data structure,",
	"               typically a pointer to an embedded list_head, the offset",
	"               to the embedded member may be entered in either of the",
	"               following manners:",
	"                   1. in \"structure.member\" format.",
	"                   2. a number of bytes. ",
	"           -x  override default output format with hexadecimal format.",
	"           -d  override default output format with decimal format.",
	"  ",
        "\nEXAMPLE",
        "  Display the page's member private, _count.counter, inuse at address ",
	"  0xffffea00000308f0:\n",
        "    %s> pstruct page.private,_count.counter,inuse 0xffffea00000308f0",
        "    0       198896  59904",
	" ",
	"  Display the page's member mapping, index at address 0xffffea00000308f0",
	"  in hexadecimal format:\n",
        "    %s> pstruct page.mapping,index ffffea000004c778 -x",
        "    0xffff88004b6412b8      0x100167",
        NULL
};

/* 
 *  Arguments are passed to the command functions in the global args[argcnt]
 *  array.  See getopt(3) for info on dash arguments.  Check out defs.h and
 *  other crash commands for usage of the myriad of utility routines available
 *  to accomplish what your task.
 */
void
cmd_pstruct(void)
{
        int c, i;
	ulong addr;
	struct syment *sp;
	ulong list_head_offset;
	int argc_members;
	unsigned int radix;
	struct datatype_member datatype_member, *dm;
	char *structname, *members;
	char *separator;
	char *memberlist[MAXARGS];
	char outputbuf[BUFSIZE];
	long outputindex;
	ulong tmpvalue;
	struct struct_cache *struct_cache;

	argc_members = 0;
	dm = &datatype_member;
	list_head_offset = 0;
	structname = separator = members = NULL;
	outputindex = 0;

        while ((c = getopt(argcnt, args, "dxl:")) != EOF) {
                switch(c)
                {
		case 'd':
			if (radix == 16)
				error(FATAL, 
				    "-d and -x are mutually exclusive\n");
			radix = 10;
			break;

		case 'x':
			if (radix == 10)
				error(FATAL, 
				    "-d and -x are mutually exclusive\n");
			radix = 16;
			break;

		case 'l':
                        if (IS_A_NUMBER(optarg))
                                list_head_offset = stol(optarg,
                                        FAULT_ON_ERROR, NULL);
                        else if (arg_to_datatype(optarg,
                                dm, RETURN_ON_ERROR) > 1)
                                list_head_offset = dm->member_offset;
			else
				error(FATAL, "invalid -l option: %s\n", 
					optarg);
			break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs || !args[optind] || !args[optind+1] || args[optind+2])
                cmd_usage(pc->curcmd, SYNOPSIS);

	if ((count_chars(args[optind], ',')+1) > MAXARGS)
		error(FATAL, "too many members in comma-separated list!\n");

	if ((LASTCHAR(args[optind]) == ',') || (LASTCHAR(args[optind]) == '.'))
		error(FATAL, "invalid format: %s\n", args[optind]);

	if (count_chars(args[optind], '.') < 1)
		error(FATAL, "no member format is invalid: %s\n", args[optind]);

	/*
	 * Handle struct.member[,member] argument format.
	 */
	structname = GETBUF(strlen(args[optind])+1);
	strcpy(structname, args[optind]);
	separator = strstr(structname, ".");

	members = GETBUF(strlen(args[optind])+1);
	strcpy(members, separator+1);
	replace_string(members, ",", ' ');
	argc_members = parse_line(members, memberlist);

	*separator = NULLCHAR;

	/*
 	 *  Handle address
 	 */
	if (clean_arg() && IS_A_NUMBER(args[optind+1]))
		addr = htol(args[optind+1], FAULT_ON_ERROR, NULL);
	else if ((sp = symbol_search(args[optind+1])))
		addr = sp->value;
	else {
		fprintf(fp, "symbol not found: %s\n", args[optind+1]);
		fprintf(fp, "possible alternatives:\n");
		if (!symbol_query(args[optind], "  ", NULL))
			fprintf(fp, "  (none found)\n");
		goto freebuf;
	}

	if (list_head_offset)
		addr -= list_head_offset;

	i = 0;
	outputindex = 0;
	
	do {
		tmpvalue = 0;
		struct_cache = get_struct_cache(structname, memberlist[i]);

		switch (struct_cache->type)
		{
		case TYPE_CODE_PTR:
			readmem(addr+struct_cache->offset, KVADDR, &tmpvalue,
				struct_cache->length, "tmpvalue", FAULT_ON_ERROR);
			outputindex += sprintf(outputbuf + outputindex, "0x%lx\t",
				tmpvalue);
			break;

		case TYPE_CODE_INT:
			readmem(addr+struct_cache->offset, KVADDR, &tmpvalue, 
				struct_cache->length, "tmpvalue", FAULT_ON_ERROR);
			get_bitfield_data(&tmpvalue, struct_cache->bitpos,
				struct_cache->bitsize);
		
			if (radix == 16 || (radix == 0 && *gdb_output_radix == 16))
				outputindex += sprintf(outputbuf + outputindex,
					"0x%lx\t", tmpvalue);
			else if (struct_cache->unsigned_type ||
				struct_cache->length ==	sizeof(ulonglong))
				outputindex += sprintf(outputbuf + outputindex,
					"%lu\t", tmpvalue);
			else
				outputindex += sprintf(outputbuf + outputindex,
					"%d\t",	(int)tmpvalue);
			break;

		default:
			error(FATAL, "invalid data structure reference %s.%s\n",
				struct_cache->name, struct_cache->member);
			break;
		}
		
	} while (++i < argc_members);

	fprintf(fp, "%s\n", outputbuf);

freebuf:
	if (structname)
		FREEBUF(structname);
	if (members)
                FREEBUF(members);
}

static struct struct_cache *
get_struct_cache(char *structname, char *member)
{
	int index = 0;
	char buf[BUFSIZE];
	char *printmlist[MAXARGS];

	while (index <= struct_cache_size && index <= STRUCTURE_CACHE_MAX_SIZE) {
		if (!strcmp(struct_cache[index].name, structname) &&
			!strcmp(struct_cache[index].member, member))
			return &struct_cache[index];

		index++;
	}

	struct_cache_size++;
	index = struct_cache_size % STRUCTURE_CACHE_MAX_SIZE;

	open_tmpfile();

	sprintf(buf, "printm ((struct %s *)0x0).%s", structname, member);

	if (!gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
		rewind(fp);
		sprintf(buf, "printm ((union %s *)0x0).%s", structname, member);
		if (!gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR))
			error(FATAL, "invalid data structure reference %s.%s\n",
				structname, member);
	}

	rewind(fp);
	if (fgets(buf, BUFSIZE, fp))
	{
		parse_line(buf, printmlist);
	}

	sprintf(struct_cache[index].name, "%s", structname);
	sprintf(struct_cache[index].member, "%s", member);
	struct_cache[index].type = dtol(printmlist[0], RETURN_ON_ERROR, NULL);
	struct_cache[index].unsigned_type = dtol(printmlist[1],
					RETURN_ON_ERROR, NULL);
	struct_cache[index].length = dtol(printmlist[2], RETURN_ON_ERROR, NULL);
	struct_cache[index].offset = dtol(printmlist[3], RETURN_ON_ERROR, NULL);
	struct_cache[index].bitpos = dtol(printmlist[4], RETURN_ON_ERROR, NULL);
	struct_cache[index].bitsize = dtol(printmlist[5], RETURN_ON_ERROR, NULL);

	close_tmpfile();

	return &struct_cache[index];
}

static void
get_bitfield_data(ulong *value, int pos, int size)
{
	if (pos == 0 && size == 0)
		return;

	ulong tmpvalue = *value;
	ulong mask;
	
	tmpvalue = tmpvalue >> pos;
	mask = (1UL << size) - 1;
	tmpvalue &= mask;

	*value = tmpvalue;
}
