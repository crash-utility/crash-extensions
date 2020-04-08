/* spu.c - commands for viewing Cell/B.E. SPUs data
 *
 * (C) Copyright 2007 IBM Corp.
 *
 * Author: Lucio Correia <luciojhc@br.ibm.com>
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

#define NR_SPUS			 (16)	/* Enough for current hardware */
#define MAX_PRIO		(140)
#define MAX_PROPERTY_NAME	 (64)
#define STR_SPU_INVALID		(0x0)
#define STR_SPU_ID		(0x1)
#define STR_SPU_PID		(0x2)
#define STR_SPU_CTX_ADDR	(0x8)

#define SPUCTX_CMD_NAME "spuctx"
#define SPUS_CMD_NAME "spus"
#define SPURQ_CMD_NAME "spurq"

struct cbe_size_table;
struct cbe_offset_table;
void init_cbe_size_table(void);
void init_cbe_offset_table(void);
ulong get_spu_addr(ulong spu_info);

void cmd_spus(void);
void cmd_spurq(void);
void cmd_spuctx(void);
char *help_spus[];
char *help_spurq[];
void show_spu_state(ulong spu);
void dump_spu_runq(ulong k_prio_array);
char *help_spuctx[];
void show_ctx_info(ulong ctx_addr);
void print_ctx_info(char *ctx_data, char *spu_data, int info);
void show_ctx_info_all(void);


static struct command_table_entry command_table[] = {
	SPUCTX_CMD_NAME, cmd_spuctx, help_spuctx, 0,
	SPUS_CMD_NAME, cmd_spus, help_spus, 0,
	SPURQ_CMD_NAME, cmd_spurq, help_spurq, 0,
	NULL
};

struct cbe_size_table {
	long crash_spu_info;
	long spu;
	long spu_context;
	long spu_prio_array;
	long list_head;
} cbe_size_table;

struct cbe_offset_table {
	long crash_spu_info_spu;
	long crash_spu_info_saved_mfc_sr1_RW;
	long crash_spu_info_saved_mfc_dar;
	long crash_spu_info_saved_mfc_dsisr;
	long crash_spu_info_saved_spu_runcntl_RW;
	long crash_spu_info_saved_spu_status_R;
	long crash_spu_info_saved_spu_npc_RW;

	long spu_node;
	long spu_number;
	long spu_ctx;
	long spu_pid;
	long spu_name;
	long spu_slb_replace;
	long spu_mm;
	long spu_timestamp;
	long spu_class_0_pending;
	long spu_problem;
	long spu_priv2;
	long spu_flags;

	long spu_context_spu;
	long spu_context_state;
	long spu_context_prio;
	long spu_context_local_store;
	long spu_context_rq;

	long spu_prio_array_runq;
} cbe_offset_table;

#define CBE_SIZE(X)			(cbe_size_table.X)
#define CBE_OFFSET(X, Y)		(cbe_offset_table.X##_##Y)

#define CBE_SIZE_INIT(X, Y) 						\
do {									\
	cbe_size_table.X = STRUCT_SIZE(Y);				\
	if (cbe_size_table.X == -1)					\
		error(FATAL, "Couldn't get %s size.\n", Y);		\
} while(0)

#define CBE_OFFSET_INIT(X, Y, Z)					\
do {									\
	cbe_offset_table.X = MEMBER_OFFSET(Y, Z);			\
	if (cbe_offset_table.X == -1)					\
		error(FATAL, "Couldn't get %s.%s offset.\n", Y, Z);	\
} while(0)

ulong spu[NR_SPUS];

/*****************************************************************************
 * INIT FUNCTIONS
 */

/*
 * Read kernel virtual addresses of crash_spu_info data stored by kdump
 */

void init_cbe_size_table(void)
{
	CBE_SIZE_INIT(crash_spu_info, "crash_spu_info");
	CBE_SIZE_INIT(spu, "spu");
	CBE_SIZE_INIT(spu_context, "spu_context");
	CBE_SIZE_INIT(spu_prio_array, "spu_prio_array");
	CBE_SIZE_INIT(list_head, "list_head");
}

void init_cbe_offset_table(void)
{
	CBE_OFFSET_INIT(crash_spu_info_spu, "crash_spu_info", "spu");
	CBE_OFFSET_INIT(crash_spu_info_saved_mfc_sr1_RW, "crash_spu_info",
							"saved_mfc_sr1_RW");
	CBE_OFFSET_INIT(crash_spu_info_saved_mfc_dar, "crash_spu_info",
							"saved_mfc_dar");
	CBE_OFFSET_INIT(crash_spu_info_saved_mfc_dsisr, "crash_spu_info",
							"saved_mfc_dsisr");
	CBE_OFFSET_INIT(crash_spu_info_saved_spu_runcntl_RW, "crash_spu_info",
							"saved_spu_runcntl_RW");
	CBE_OFFSET_INIT(crash_spu_info_saved_spu_status_R, "crash_spu_info",
							"saved_spu_status_R");
	CBE_OFFSET_INIT(crash_spu_info_saved_spu_npc_RW, "crash_spu_info",
							"saved_spu_npc_RW");

	CBE_OFFSET_INIT(spu_node, "spu", "node");
	CBE_OFFSET_INIT(spu_number, "spu", "number");
	CBE_OFFSET_INIT(spu_ctx, "spu", "ctx");
	CBE_OFFSET_INIT(spu_pid, "spu", "pid");
	CBE_OFFSET_INIT(spu_name, "spu", "name");
	CBE_OFFSET_INIT(spu_slb_replace, "spu", "slb_replace");
	CBE_OFFSET_INIT(spu_mm, "spu", "mm");
	CBE_OFFSET_INIT(spu_timestamp, "spu", "timestamp");
	CBE_OFFSET_INIT(spu_class_0_pending, "spu", "class_0_pending");
	CBE_OFFSET_INIT(spu_problem, "spu", "problem");
	CBE_OFFSET_INIT(spu_priv2, "spu", "priv2");
	CBE_OFFSET_INIT(spu_flags, "spu", "flags");

	CBE_OFFSET_INIT(spu_context_spu, "spu_context", "spu");
	CBE_OFFSET_INIT(spu_context_state, "spu_context", "state");
	CBE_OFFSET_INIT(spu_context_prio, "spu_context", "prio");
	CBE_OFFSET_INIT(spu_context_local_store, "spu_context", "local_store");
	CBE_OFFSET_INIT(spu_context_rq, "spu_context", "rq");

	CBE_OFFSET_INIT(spu_prio_array_runq, "spu_prio_array", "runq");
}

void get_crash_spu_info(void)
{
	int i;
	ulong addr;
	long struct_size;

	addr = symbol_value("crash_spu_info");
	struct_size = CBE_SIZE(crash_spu_info);

	for (i = 0; i < NR_SPUS; i++)
		spu[i] = addr + (i * struct_size);
}

_init()
{
	int i, n_registered;
	struct command_table_entry *cte;

	init_cbe_size_table();
	init_cbe_offset_table();

	for (i = 0; i < NR_SPUS; i++)
		spu[i] = 0;

	register_extension(command_table);

	get_crash_spu_info();
}


_fini() { }



/*****************************************************************************
 * BASIC FUNCTIONS
 */


/*
 * Returns a pointer to the requested SPU field
 */
ulong get_spu_addr(ulong spu_info)
{
	ulong spu_addr;

	readmem(spu_info + CBE_OFFSET(crash_spu_info, spu), KVADDR, &spu_addr,
			sizeof(spu_addr), "get_spu_addr", FAULT_ON_ERROR);

	return spu_addr;
}


/*****************************************************************************
 * SPUCTX COMMAND
 */

#define DUMP_WIDTH	23
#define DUMP_SPU_NAME							\
do {									\
	fprintf(fp, "  %-*s = %s\n", DUMP_WIDTH, "name", name_str);	\
} while(0)

#define DUMP_SPU_FIELD(format, field, cast)				\
do {									\
	offset = CBE_OFFSET(spu, field);				\
	fprintf(fp, "  %-*s = "format"\n", DUMP_WIDTH, #field,		\
					cast(spu_data + offset));	\
} while(0)

#define DUMP_CTX_FIELD(format, field, cast)				\
do {									\
	offset = CBE_OFFSET(spu_context, field);			\
	fprintf(fp, "  %-*s = "format"\n", DUMP_WIDTH, #field,		\
					cast(ctx_data + offset));	\
} while(0)

#define DUMP_DBG_FIELD(format, field, cast)				\
do {									\
	offset = CBE_OFFSET(crash_spu_info, field);			\
	fprintf(fp, "  %-*s = "format"\n", DUMP_WIDTH, #field,		\
					cast(debug_data + offset));	\
} while(0)

/*
 * Print the spu and spu_context structs fields. Some SPU memory-mapped IO
 * registers are taken directly from crash_spu_info.
 */
void print_ctx_info(char *ctx_data, char *spu_data, int info)
{
	long offset, size;
	char *name_str, *debug_data;

	DUMP_CTX_FIELD("%d", state, *(int *));
	DUMP_CTX_FIELD("%d", prio, *(int *));
	DUMP_CTX_FIELD("%p", local_store, *(ulong *));
	DUMP_CTX_FIELD("%p", rq, *(ulong *));

	if (spu_data) {
		offset = CBE_OFFSET(spu, name);
		size = MAX_PROPERTY_NAME * sizeof(char);
		name_str = (char *)GETBUF(size);
		readmem(*(ulong *)(spu_data + offset), KVADDR, name_str, size,
						"name_str", FAULT_ON_ERROR);
		DUMP_SPU_NAME;
		FREEBUF(name_str);

		DUMP_SPU_FIELD("%d", node, *(int *));
		DUMP_SPU_FIELD("%d", number, *(int *));
		DUMP_SPU_FIELD("%d", pid, *(int *));
		DUMP_SPU_FIELD("0x%x", slb_replace, *(unsigned int *));
		DUMP_SPU_FIELD("%p", mm, *(ulong *));
		DUMP_SPU_FIELD("%p", timestamp, *(long long *));
		DUMP_SPU_FIELD("%d", class_0_pending, *(int *));
		DUMP_SPU_FIELD("%p", problem, *(ulong *));
		DUMP_SPU_FIELD("%p", priv2, *(ulong *));
		DUMP_SPU_FIELD("0x%lx", flags, *(ulong *));

		size = CBE_SIZE(crash_spu_info);
		debug_data = (char *)GETBUF(size);
		readmem(spu[info], KVADDR, debug_data, size, "debug_data",
								FAULT_ON_ERROR);

		DUMP_DBG_FIELD("0x%lx", saved_mfc_sr1_RW, *(ulong *));
		DUMP_DBG_FIELD("0x%lx", saved_mfc_dar, *(ulong *));
		DUMP_DBG_FIELD("0x%lx", saved_mfc_dsisr, *(ulong *));
		DUMP_DBG_FIELD("0x%x", saved_spu_runcntl_RW, *(uint *));
		DUMP_DBG_FIELD("0x%x", saved_spu_status_R, *(uint *));
		DUMP_DBG_FIELD("0x%x", saved_spu_npc_RW, *(uint *));

		FREEBUF(debug_data);
	}
}


/*
 * Pass ctx and respective spu data to print_ctx_info for the contexts in
 * ctx_addr list (chosen contexts).
 */
void show_ctx_info(ulong ctx_addr)
{
	int number, info, i;
	char *ctx_data, *spu_data;
	long size, offset;
	ulong spu_addr, addr;

	if (!ctx_addr)
		return;

	spu_data = NULL;
	info = 0;

	size = CBE_SIZE(spu_context);
	ctx_data = GETBUF(size);
	if (!ctx_data)
		error(FATAL, "Couldn't allocate memory for ctx.\n");
	readmem(ctx_addr, KVADDR, ctx_data, size, "show_ctx_info ctx",
								FAULT_ON_ERROR);

	spu_addr = *(ulong *)(ctx_data + CBE_OFFSET(spu_context, spu));

	if (spu_addr) {
		size = CBE_SIZE(spu);
		spu_data = GETBUF(size);
		if (!spu_data)
			error(FATAL, "Couldn't allocate memory for spu.\n");
		readmem(spu_addr, KVADDR, spu_data, size, "show_ctx_info spu",
								FAULT_ON_ERROR);

		for (i = 0; i < NR_SPUS; i++) {
			readmem(spu[i], KVADDR, &addr, sizeof(addr), "spu addr",
								FAULT_ON_ERROR);
			if (addr == spu_addr)
				info = i;
		}
	}

	fprintf(fp,"\nDumping context fields for spu_context %lx:\n", ctx_addr);
	print_ctx_info(ctx_data, spu_data, info);

	FREEBUF(ctx_data);
	if (spu_addr)
		FREEBUF(spu_data);
}

/*
 * Pass ctx and respective spu data to show_ctx_info for all the contexts
 * running and on the runqueue.
 */
void show_ctx_info_all(void)
{
	int i, j, cnt;
	long prio_size, prio_runq_off, ctx_rq_off, jump, offset, ctxs_size;
	char *u_spu_prio;
	ulong spu_prio_addr, k_spu_prio, kvaddr, uvaddr, spu_addr, ctx_addr;
	ulong *ctxs;
	ulong list_head[2];
	struct list_data list_data, *ld;

	/* Walking SPUs */
	for (i = 0; i < NR_SPUS; i++) {
		spu_addr = get_spu_addr(spu[i]) + CBE_OFFSET(spu, ctx);
		readmem(spu_addr, KVADDR, &ctx_addr, sizeof(ctx_addr),
				"show_ctx_info_all", FAULT_ON_ERROR);
		if (ctx_addr)
			show_ctx_info(ctx_addr);
	}

	/* Walking SPU runqueue */
	if (symbol_exists("spu_prio")) {
		spu_prio_addr = symbol_value("spu_prio");
		readmem(spu_prio_addr, KVADDR, &k_spu_prio, sizeof(k_spu_prio),
						"runq_array", FAULT_ON_ERROR);
	}
	else
		error(FATAL, "Could not get SPU run queue data.\n");

	jump = CBE_SIZE(list_head);
	prio_runq_off =  CBE_OFFSET(spu_prio_array, runq);
	ctx_rq_off =  CBE_OFFSET(spu_context, rq);
	prio_size = CBE_SIZE(spu_prio_array);

	u_spu_prio = (char *)GETBUF(prio_size);
	readmem(k_spu_prio, KVADDR, u_spu_prio, prio_size, "get_runq_ctxs",
								FAULT_ON_ERROR);

	for (i = 0; i < MAX_PRIO; i++) {
		offset = prio_runq_off + i * jump;
		kvaddr = k_spu_prio + offset;
		uvaddr = (ulong)u_spu_prio + offset;

		BCOPY((char *)uvaddr, (char *)&list_head[0], sizeof(ulong)*2);

		if ((list_head[0] == kvaddr) && (list_head[1] == kvaddr))
			continue;

		ld = &list_data;

		BZERO(ld, sizeof(struct list_data));
		ld->start = list_head[0];
		ld->list_head_offset = ctx_rq_off;
		ld->flags |= RETURN_ON_LIST_ERROR;
		ld->end = kvaddr;

		hq_open();
		cnt = do_list(ld);
		if (cnt == -1) {
			hq_close();
			FREEBUF(u_spu_prio);
			error(FATAL, "Couldn't walk the list.\n");
		}

		ctxs_size = cnt * sizeof(ulong);
		ctxs = (ulong *)GETBUF(ctxs_size);

		BZERO(ctxs, ctxs_size);
		cnt = retrieve_list(ctxs, cnt);
		hq_close();

		for (j = 0; j < cnt; j++)
			show_ctx_info(ctxs[j]);

		FREEBUF(ctxs);
	}

	FREEBUF(u_spu_prio);
}

/*
 * Tries to discover the meaning of string and to find the referred context
 */
int str_to_spuctx(char *string, ulong *value, ulong *spu_ctx)
{
	char *s, *u_spu_prio;
	ulong dvalue, hvalue, addr, ctx;
	ulong k_spu_prio, spu_prio_addr, kvaddr, uvaddr;
	int type, pid, i, j, cnt;
	long prio_size, prio_runq_off, ctx_rq_off, jump, offset, ctxs_size;
	ulong *ctxs;
	ulong list_head[2];
	struct list_data list_data, *ld;

	if (string == NULL) {
		error(INFO, "%s: received NULL string.\n", __FUNCTION__);
		return STR_SPU_INVALID;
	}

	s = string;
	dvalue = hvalue = BADADDR;

	if (decimal(s, 0))
		dvalue = dtol(s, RETURN_ON_ERROR, NULL);

	if (hexadecimal(s, 0)) {
		if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
			s += 2;
		if (strlen(s) <= MAX_HEXADDR_STRLEN)
			hvalue = htol(s, RETURN_ON_ERROR, NULL);
	}

	type = STR_SPU_INVALID;

	if (dvalue != BADADDR) {
		/* Testing for SPU ID */
		if ((dvalue >= 0) && (dvalue < NR_SPUS)) {
			addr = get_spu_addr(spu[dvalue]) + CBE_OFFSET(spu, ctx);
			readmem(addr, KVADDR, &ctx, sizeof(ctx),
					"str_to_spuctx ID", FAULT_ON_ERROR);

			type = STR_SPU_ID;
			*value = dvalue;
			*spu_ctx = ctx;
			return type;
		}
		else {
			/* Testing for PID */
			for (i = 0; i < NR_SPUS; i++) {
				addr = get_spu_addr(spu[i]) +
							CBE_OFFSET(spu, pid);
				readmem(addr, KVADDR, &pid, sizeof(pid),
					"str_to_spuctx PID", FAULT_ON_ERROR);

				if (dvalue == pid) {
					addr = get_spu_addr(spu[i]) +
							CBE_OFFSET(spu, ctx);
					readmem(addr, KVADDR, &ctx, sizeof(ctx),
						"str_to_spuctx PID ctx",
						FAULT_ON_ERROR);

					type = STR_SPU_PID;
					*value = dvalue;
					*spu_ctx = ctx;
					return type;
				}
			}
		}
	}

	if (hvalue != BADADDR) {
		/* Testing for spuctx address on SPUs */
		for (i = 0; i < NR_SPUS; i++) {
			addr = get_spu_addr(spu[i]) + CBE_OFFSET(spu, ctx);
			readmem(addr, KVADDR, &ctx, sizeof(ctx),
					"str_to_spuctx CTX", FAULT_ON_ERROR);

			if (hvalue == ctx) {
				type = STR_SPU_CTX_ADDR;
				*value = hvalue;
				*spu_ctx = ctx;
				return type;
			}
		}

		/* Testing for spuctx address on SPU runqueue */
		if (symbol_exists("spu_prio")) {
			spu_prio_addr = symbol_value("spu_prio");
			readmem(spu_prio_addr, KVADDR, &k_spu_prio,
			      sizeof(k_spu_prio), "runq_array", FAULT_ON_ERROR);
		}
		else
			error(FATAL, "Could not get SPU run queue data.\n");

		jump = CBE_SIZE(list_head);
		prio_runq_off = CBE_OFFSET(spu_prio_array, runq);
		ctx_rq_off = CBE_OFFSET(spu_context, rq);
		prio_size = CBE_SIZE(spu_prio_array);

		u_spu_prio = (char *)GETBUF(prio_size);
		readmem(k_spu_prio, KVADDR, u_spu_prio, prio_size,
					"get_runq_ctxs", FAULT_ON_ERROR);

		for (i = 0; i < MAX_PRIO; i++) {
			offset = prio_runq_off + i * jump;
			kvaddr = k_spu_prio + offset;
			uvaddr = (ulong)u_spu_prio + offset;

			BCOPY((char *)uvaddr, (char *)&list_head[0], sizeof(ulong)*2);

			if ((list_head[0] == kvaddr) && (list_head[1] == kvaddr))
				continue;

			ld = &list_data;

			BZERO(ld, sizeof(struct list_data));
			ld->start = list_head[0];
			ld->list_head_offset = ctx_rq_off;
			ld->flags |= RETURN_ON_LIST_ERROR;
			ld->end = kvaddr;

			hq_open();
			cnt = do_list(ld);
			if (cnt == -1) {
				hq_close();
				FREEBUF(u_spu_prio);
				error(FATAL, "Couldn't walk the list.\n");
			}

			ctxs_size = cnt * sizeof(ulong);
			ctxs = (ulong *)GETBUF(ctxs_size);

			BZERO(ctxs, ctxs_size);
			cnt = retrieve_list(ctxs, cnt);
			hq_close();

			for (j = 0; j < cnt; j++)
				if (hvalue == ctxs[j]) {
					type = STR_SPU_CTX_ADDR;
					*value = hvalue;
					*spu_ctx = ctxs[j];
					FREEBUF(u_spu_prio);
					FREEBUF(ctxs);
					return type;
				}

			FREEBUF(ctxs);
		}

		FREEBUF(u_spu_prio);
	}

	return type;
}

/*
 * spuctx command stands for "spu context" and shows the context fields
 * for the spu or respective struct address passed as an argument
 */
void cmd_spuctx()
{
	int i, c, cnt;
	ulong value, ctx;
	ulong *ctxlist;

	while ((c = getopt(argcnt, args, "")) != EOF) {
		switch(c)
		{
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!args[optind]) {
		show_ctx_info_all();
		return;
	}

	cnt = 0;
	ctxlist = (ulong *)GETBUF((MAXARGS+NR_CPUS)*sizeof(ctx));

	while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
			switch (str_to_spuctx(args[optind], &value, &ctx))
			{
			case STR_SPU_ID:
			case STR_SPU_PID:
			case STR_SPU_CTX_ADDR:
				ctxlist[cnt++] = ctx;
				break;

			case STR_SPU_INVALID:
				error(INFO, "Invalid SPU reference: %s\n",
								args[optind]);
				break;
			}
		}
		else
			error(INFO, "Invalid SPU reference: %s\n",
								args[optind]);
		optind++;
	}

	if (cnt == 0)
		error(INFO, "No valid ID, PID or context address.\n");
	else
		for (i = 0; i < cnt; i++)
			show_ctx_info(ctxlist[i]);

	FREEBUF(ctxlist);
}


/*****************************************************************************
 * SPUS COMMAND
 */

void print_spu_header(ulong spu_info)
{
	int id, pid, size, state;
	uint status;
	ulong ctx_addr, spu_addr;
	char *spu_data;
	const char *state_str;

	if (spu_info) {
		readmem(spu_info + CBE_OFFSET(crash_spu_info,
			saved_spu_status_R), KVADDR, &status, sizeof(status),
			"print_spu_header: get status", FAULT_ON_ERROR);

		size = CBE_SIZE(spu);
		spu_data = GETBUF(size);
		spu_addr = get_spu_addr(spu_info);
		readmem(spu_addr, KVADDR, spu_data, size, "SPU struct",
								FAULT_ON_ERROR);

		id = *(int *)(spu_data + CBE_OFFSET(spu, number));
		pid = *(int *)(spu_data + CBE_OFFSET(spu, pid));
		ctx_addr = *(ulong *)(spu_data + CBE_OFFSET(spu, ctx));

		if (ctx_addr) {
			readmem(ctx_addr + CBE_OFFSET(spu_context, state),
				KVADDR, &state, sizeof(state),
				"print_spu_header get ctxstate", FAULT_ON_ERROR);

			switch (state) {
				case 0: /* SPU_STATE_RUNNABLE */
					state_str = "RUNNABLE";
					break;

				case 1: /* SPU_STATE_SAVED */
					state_str = " SAVED  ";
					break;

				default:
					state_str = "UNKNOWN ";
			}
		}
		else {
			state_str = "   -    ";
		}

		fprintf(fp, "%2d   %16lx   %s   %16lx   %s   %5d\n", id,
		    spu_addr,
		    status % 2 ? "RUNNING" : (ctx_addr ? "STOPPED" : "  IDLE "),
		    ctx_addr, state_str, pid);

		FREEBUF(spu_data);
	}
}

void print_node_header(int node)
{
	fprintf(fp, "\n");
	fprintf(fp, "NODE %i:\n", node);
	fprintf(fp, "ID        SPUADDR      SPUSTATUS       CTXADDR       \
CTXSTATE    PID \n");
}

void show_spus()
{
	int i, j, nr_cpus, show_header, node;
	ulong spu_addr, addr;
	long offset;

	nr_cpus = kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS : NR_CPUS;

	for (i = 0; i < nr_cpus; i++) {
		show_header = TRUE;

		for (j = 0; j < NR_SPUS; j++) {
			addr = spu[j] + CBE_OFFSET(crash_spu_info, spu);
			readmem(addr, KVADDR, &spu_addr, sizeof(spu_addr),
					"show_spus spu_addr", FAULT_ON_ERROR);

			offset = CBE_OFFSET(spu, node);
			if (offset == -1)
				error(FATAL, "Couldn't get spu.node offset.\n");

			spu_addr += offset;
			readmem(spu_addr, KVADDR, &node, sizeof(node),
					"show_spus node", FAULT_ON_ERROR);

			if (node == i) {
				if (show_header) {
					print_node_header(node);
					show_header = FALSE;
				}

				print_spu_header(spu[j]);
			}
		}
	}
}

/*
 * spus stands for "spu state" and shows what contexts are running in what
 * SPU.
 */
void cmd_spus()
{
	int c;

	while ((c = getopt(argcnt, args, "")) != EOF) {
		switch(c)
		{
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);
	else
		show_spus();
}


/*****************************************************************************
 * SPURQ COMMAND
 */

/*
 * Prints the addresses of SPU contexts on the SPU runqueue.
 */
void dump_spu_runq(ulong k_spu_prio)
{
	int i, cnt;
	long prio_size, prio_runq_off, ctx_rq_off, jump, offset;
	char *u_spu_prio;
	ulong kvaddr, uvaddr;
	ulong list_head[2];
	struct list_data list_data, *ld;

	prio_runq_off = CBE_OFFSET(spu_prio_array, runq);
	jump = CBE_SIZE(list_head);
	ctx_rq_off = CBE_OFFSET(spu_context, rq);
	prio_size = CBE_SIZE(spu_prio_array);

	u_spu_prio = (char *)GETBUF(prio_size);
	readmem(k_spu_prio, KVADDR, u_spu_prio, prio_size, "get_runq_ctxs",
								FAULT_ON_ERROR);

	for (i = 0; i < MAX_PRIO; i++) {
		offset = prio_runq_off + (i * jump);
		kvaddr = k_spu_prio + offset;
		uvaddr = (ulong)u_spu_prio + offset;

		BCOPY((char *)uvaddr, (char *)&list_head[0], sizeof(ulong)*2);

		if ((list_head[0] == kvaddr) && (list_head[1] == kvaddr))
			continue;

		fprintf(fp, "PRIO[%i]:\n", i);

		ld = &list_data;

		BZERO(ld, sizeof(struct list_data));
		ld->start = list_head[0];
		ld->list_head_offset = ctx_rq_off;
		ld->flags |= VERBOSE;
		ld->end = kvaddr;

		hq_open();
		cnt = do_list(ld);
		hq_close();

		if (cnt == -1) {
			FREEBUF(u_spu_prio);
			error(FATAL, "Couldn't walk runqueue[%i].\n", i);
		}
	}

	FREEBUF(u_spu_prio);
}

/*
 * spurq stands for "spu run queue" and shows info about the contexts
 * that are on the SPU run queue
 */
void cmd_spurq()
{
	int c;
	ulong spu_prio_addr, spu_prio;
	long size;

	while ((c = getopt(argcnt, args, "")) != EOF) {
		switch(c)
		{
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);
	else {
		if (symbol_exists("spu_prio")) {
			spu_prio_addr = symbol_value("spu_prio");
			readmem(spu_prio_addr, KVADDR, &spu_prio,
				sizeof(spu_prio), "runq_array", FAULT_ON_ERROR);
			dump_spu_runq(spu_prio);
		} else
			error(FATAL, "Could not get SPU run queue data.\n");
	}
}

/**********************************************************************************
 * HELP TEXTS
 */

char *help_spuctx[] = {
	SPUCTX_CMD_NAME,
	"shows complete info about a SPU context",
	"[ID | PID | CTXADDR] ...",

	"  This command shows the fields of spu and spu_context structs for a ",
	"SPU context, including debug info specially saved by kdump after a ",
	"crash.",
	"  By default, it shows info about all the contexts created by the ",
	"system, including ones in the runqueue. To specify the contexts of ",
	"interest, the PID of the controller task, ID of the SPU which the ",
	"context is bound to or the address of spu_context struct can be used ",
	"as parameters.",
	"\nEXAMPLES",
	"\n  Show info about contexts bound to SPUs 0 and 7, and the one ",
	"controlled by thread whose PID is 1524:",
	"\n    crash> spuctx 0 7 1524",
	"\n    Dumping context fields for spu_context c00000003dcbdd80:",
	"      state                   = 0",
	"      prio                    = 120",
	"      local_store             = 0xc000000039055840",
	"      rq                      = 0xc00000003dcbe720",
	"      node                    = 0",
	"      number                  = 0",
	"      pid                     = 1524",
	"      name                    = spe",
	"      slb_replace             = 0",
	"      mm                      = 0xc0000000005dd700",
	"      timestamp               = 0x10000566f",
	"      class_0_pending         = 0",
	"      problem                 = 0xd000080080210000",
	"      priv2                   = 0xd000080080230000",
	"      flags                   = 0",
	"      saved_mfc_sr1_RW        = 59",
	"      saved_mfc_dar           = 14987979559889612800",
	"      saved_mfc_dsisr         = 0",
	"      saved_spu_runcntl_RW    = 1",
	"      saved_spu_status_R      = 1",
	"      saved_spu_npc_RW        = 0",
	"\n    Dumping context fields for spu_context c00000003dec4e80:",
	"      state                   = 0",
	"      prio                    = 120",
	"      local_store             = 0xc00000003b1cea40",
	"      rq                      = 0xc00000003dec5820",
	"      node                    = 0",
	"      number                  = 7",
	"      pid                     = 1538",
	"      name                    = spe",
	"      slb_replace             = 0",
	"      mm                      = 0xc0000000005d2b80",
	"      timestamp               = 0x10000566f",
	"      class_0_pending         = 0",
	"      problem                 = 0xd000080080600000",
	"      priv2                   = 0xd000080080620000",
	"      flags                   = 0",
	"      saved_mfc_sr1_RW        = 59",
	"      saved_mfc_dar           = 14987979559896297472",
	"      saved_mfc_dsisr         = 0",
	"      saved_spu_runcntl_RW    = 1",
	"      saved_spu_status_R      = 1",
	"      saved_spu_npc_RW        = 0",
	"\n    Dumping context fields for spu_context c00000003dcbdd80:",
	"      state                   = 0",
	"      prio                    = 120",
	"      local_store             = 0xc000000039055840",
	"      rq                      = 0xc00000003dcbe720",
	"      node                    = 0",
	"      number                  = 0",
	"      pid                     = 1524",
	"      name                    = spe",
	"      slb_replace             = 0",
	"      mm                      = 0xc0000000005dd700",
	"      timestamp               = 0x10000566f",
	"      class_0_pending         = 0",
	"      problem                 = 0xd000080080210000",
	"      priv2                   = 0xd000080080230000",
	"      flags                   = 0",
	"      saved_mfc_sr1_RW        = 59",
	"      saved_mfc_dar           = 14987979559889612800",
	"      saved_mfc_dsisr         = 0",
	"      saved_spu_runcntl_RW    = 1",
	"      saved_spu_status_R      = 1",
	"      saved_spu_npc_RW        = 0",

	"\n  Show info about the context whose struct spu_context address is ",
	"0xc00000003dcbed80:\n",
	"crash> spuctx 0x00000003dcbed80",
	"    ...",
	NULL
};


char *help_spus[] = {
	SPUS_CMD_NAME,
	"shows how contexts are scheduled in the SPUs",
	" ",
	"  This command shows how the contexts are scheduled in the SPUs of ",
	"each node. It provides info about the spu address, SPU status, the ",
	"spu_context address, context state and spu_context addresses and the ",
	"PID of controller thread for each SPU.",
	"\nEXAMPLE",
	"  Show SPU contexts:",
	"\n    crash> spus",
	"    NODE 0:",
	"    ID        SPUADDR      SPUSTATUS       CTXADDR       CTXSTATE    PID ",
	"     0   c000000001fac880   RUNNING   c00000003dcbdd80   RUNNABLE    1524",
	"     1   c000000001faca80   RUNNING   c00000003bf34e00   RUNNABLE    1528",
	"     2   c000000001facc80   RUNNING   c00000003bf30e00   RUNNABLE    1525",
	"     3   c000000001face80   RUNNING   c000000039421d00   RUNNABLE    1533",
	"     4   c00000003ee29080   RUNNING   c00000003dec3e80   RUNNABLE    1534",
	"     5   c00000003ee28e80   RUNNING   c00000003bf32e00   RUNNABLE    1526",
	"     6   c00000003ee28c80   STOPPED   c000000039e5e700    SAVED      1522",
	"     7   c00000003ee2e080   RUNNING   c00000003dec4e80   RUNNABLE    1538",
	"\n    NODE 1:",
	"    ID        SPUADDR      SPUSTATUS       CTXADDR       CTXSTATE    PID ",
	"     8   c00000003ee2de80   RUNNING   c00000003dcbed80   RUNNABLE    1529",
	"     9   c00000003ee2dc80   RUNNING   c00000003bf39e00   RUNNABLE    1535",
	"    10   c00000003ee2da80   RUNNING   c00000003bf3be00   RUNNABLE    1521",
	"    11   c000000001fad080   RUNNING   c000000039420d00   RUNNABLE    1532",
	"    12   c000000001fad280   RUNNING   c00000003bf3ee00   RUNNABLE    1536",
	"    13   c000000001fad480   RUNNING   c00000003dec2e80   RUNNABLE    1539",
	"    14   c000000001fad680   RUNNING   c00000003bf3ce00   RUNNABLE    1537",
	"    15   c000000001fad880   RUNNING   c00000003dec6e80   RUNNABLE    1540",
	NULL
};


char *help_spurq[] = {
	SPURQ_CMD_NAME,
	"shows contexts on the SPU runqueue",
	" ",
	"  This command shows info about all contexts waiting for execution ",
	"in the SPU runqueue. No parameter is needed.",
	"\nEXAMPLE",
	"  Show SPU runqueue:",
	"\n    crash> spurq",
	"    PRIO[120]:",
	"    c000000000fd7380",
	"    c00000003bf31e00",
	"    PRIO[125]:",
	"    c000000039422d00",
	"    c00000000181eb80",
	NULL
};

