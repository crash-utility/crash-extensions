/* vz.c - crash extension for OpenVZ containers
 *
 * Copyright (C) 2015 Vasily Averin
 * Copyright (C) 2015 Parallels IP Holdings GmbH.
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

#define VZ_MEMBER_OFFSET_INIT(X,Y,Z) (vz_offset_table.X=MEMBER_OFFSET(Y,Z))
#define VZ_OFFSET(X)	(OFFSET_verify(vz_offset_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
#define VZ_INVALID_MEMBER(X)  (vz_offset_table.X == INVALID_OFFSET)
#define VZ_VALID_MEMBER(X)    (vz_offset_table.X >= 0)
#define VZ_INIT 0x1

struct vz_offset_table {
	long task_veinfo;
	long veinfo_ve;
	long task_ve;
	long ve_velist;
	long ve_veid;
	long ve_nsproxy;
	long nsproxy_pidns;
	long pidns_init;
};

static struct vz_offset_table vz_offset_table = { 0 };
static int init_flags = 0;
static int id_size;

void vz_init(void);
void vz_fini(void);

static ulong
ve_to_task(ulong ve)
{
	ulong ns, pidns, task;

	readmem(ve + VZ_OFFSET(ve_nsproxy), KVADDR, &ns,
		sizeof(ulong), "ve_struct.ve_ns", FAULT_ON_ERROR);
	readmem(ns + VZ_OFFSET(nsproxy_pidns), KVADDR, &pidns,
		sizeof(ulong), "nsproxy.ve_pidns", FAULT_ON_ERROR);
	readmem(pidns + VZ_OFFSET(pidns_init), KVADDR, &task,
		sizeof(ulong), "pid_namespace.child_reaper", FAULT_ON_ERROR);

	return task;
}

#define VZLIST_HEADER \
"     CTID     VE_STRUCT            TASK          PID  COMM\n"

static void
show_container(ulong ve, ulong ctid, ulong flag)
{
	ulong task;
	struct task_context *tc;

	task = ve_to_task(ve);
	tc = task_to_context(task);

	if (!(flag & PS_NO_HEADER))
		fprintf(fp, VZLIST_HEADER);

	fprintf(fp, "%9ld  %16lx  %16lx  %6ld  %s\n",
		ctid, ve, tc->task, tc->pid, tc->comm);
	return;
}

static void
show_containers(ulong ctid)
{
	struct list_data list_data, *ld;
	ulong ve, id, flag = 0;
	int i, cnt;

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= LIST_ALLOCATE;

	ld->start = ld->end = symbol_value("ve_list_head");
	ld->list_head_offset = 0;

	cnt = do_list(ld);

	for (i = 1; i < cnt; i++) {
		id = 0;
		ve = ld->list_ptr[i] - VZ_OFFSET(ve_velist);
		readmem(ve + VZ_OFFSET(ve_veid), KVADDR, &id,
			id_size, "ve_struct.veid", FAULT_ON_ERROR);
		if ((ctid == -1) || ctid == id) {
			show_container(ve, id, flag);
			flag = PS_NO_HEADER;
		}
	}
	return;
}

void
cmd_vzlist(void)
{
	int c;
	ulong ctid = -1;

	while ((c = getopt(argcnt, args, "E:")) != EOF) {
		switch(c)
		{
		case 'E':
			ctid = stol(optarg, FAULT_ON_ERROR, NULL);
			break;
		default:
			argerrs++;
			break;
		}
	}
	if (argerrs) {
		cmd_usage(pc->curcmd, SYNOPSIS);
		return;
	}

	show_containers(ctid);
	return;
}

char *help_vzlist[] = {
"vzlist",
"shows list of runnig OpenVZ containers",
"[-E CTID]",
"If no argument is entered, command shows IDs of all running containers\n",
"  -E  Container ID",
"\nEXAMPLES",
"%s> vzlist",
"     CTID     VE_STRUCT            TASK          PID  COMM",
"      121  ffff8801491e7000  ffff8801493d0ff0   95990  init",
"      123  ffff880135a37000  ffff8803fb0a3470   95924  init",
"      321  ffff88045a778000  ffff880400616300   95923  init",
"      700  ffff88019ddae000  ffff88019ddd4fb0   95882  init",
"      503  ffff88045a84e800  ffff8803c3c782c0   95902  init",
"      122  ffff8804004ea000  ffff88045612afb0   95886  init",
"      600  ffff88016e467000  ffff880459d653f0   95885  init",
"        0  ffffffff81aaa220  ffff88045e530b30       1  init",
NULL
};

static ulong
task_to_ctid(ulong task)
{
	ulong veinfo, ve, ctid = 0;

	if (VZ_VALID_MEMBER(task_veinfo)) {
		veinfo = task + VZ_OFFSET(task_veinfo);
		readmem(veinfo + VZ_OFFSET(veinfo_ve), KVADDR, &ve,
			sizeof(ulong), "ve_task_info.exec_env", FAULT_ON_ERROR);
	} else if (VZ_VALID_MEMBER(task_ve)) {
		readmem(task + VZ_OFFSET(task_ve), KVADDR, &ve,
			sizeof(ulong), "task_struct.task_ve", FAULT_ON_ERROR);
	} else
		return 0;

	readmem(ve + VZ_OFFSET(ve_veid), KVADDR, &ctid,
		id_size, "ve_struct.veid", FAULT_ON_ERROR);

	return ctid;
}

static void
show_ctid(struct task_context *tc, ulong flag)
{
	ulong ctid;

	ctid = task_to_ctid(tc->task);
	if (!(flag & PS_NO_HEADER))
		fprintf(fp, "     CTID    PID         TASK        COMM\n");

	fprintf(fp, "%9ld  %6ld  %16lx  %s\n",
		ctid, tc->pid, tc->task, tc->comm);
	return;
}

void
cmd_ctid(void)
{
	ulong value, flag = 0;
	struct task_context *tc;
	int c;

	while ((c = getopt(argcnt, args, "")) != EOF) {
		switch(c)
		{
		default:
			cmd_usage(pc->curcmd, SYNOPSIS);
			return;
		}
	}

	if (!args[optind]) {
		tc = task_to_context(CURRENT_TASK());
		show_ctid(tc, flag);
	}
	while (args[optind]) {
		switch (str_to_context(args[optind], &value, &tc))
		{
		case STR_PID:
		case STR_TASK:
			break;
		case STR_INVALID:
			error(INFO, "invalid task or pid value: %s\n",
				   args[optind]);
		default:
			argerrs++;
			 break;
		}
		if (argerrs)
			break;
		show_ctid(tc, flag);
		flag = PS_NO_HEADER;
		optind++;
	}
	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	return;
}

char *help_ctid[] = {
"ctid",
"shows Container ID of given tasks",
"[task|pid]",
"     If no argument is entered, command shows CTID of current task",
"\nEXAMPLES",
"%s> ctid 99583",
"     CTID    PID         TASK        COMM",
"      121   99583  ffff880203e56f30  httpd",
NULL
};

static void
show_vzps(ulong ctid)
{
	struct task_context *tc;
	ulong flag;
	int i;

	tc = FIRST_CONTEXT();
	for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		ulong id = task_to_ctid(tc->task);
		if ((ctid == -1) || (ctid == id)) {
			show_ctid(tc, flag);
			flag = PS_NO_HEADER;
		}
	}
	return;
}

void
cmd_vzps(void)
{
	ulong ctid = -1;
	int c;

	while ((c = getopt(argcnt, args, "E:")) != EOF) {
		switch(c)
		{
		case 'E':
			ctid = stol(optarg, FAULT_ON_ERROR, NULL);
			break;
		default:
			argerrs++;
			break;
		}
	}
	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	show_vzps(ctid);
	return;
}

char *help_vzps[] = {
"vzps",
"shows list of tasks related to specified CTID",
" [ -E CTID]",
"     If no argument is entered, command shows CTID for all processes\n",
"\nEXAMPLES",
"%s> vzps -E 121",
"     CTID    PID         TASK        COMM",
"      121   95990  ffff8801493d0ff0  init",
"      121   95996  ffff8803c3e3b0f0  kthreadd/121",
"      121   95997  ffff8803cd3aacb0  khelper/121",
"      121   97267  ffff880405e4b2f0  udevd",
"      121   99341  ffff8803c3fd2440  syslogd",
"      121   99404  ffff880405e0c2c0  klogd",
"      121   99424  ffff8803fb0f68c0  sshd",
"      121   99445  ffff8801493d0500  xinetd",
"      121   99557  ffff8804599f9230  sendmail",
"      121   99568  ffff8804591b00c0  sendmail",
"      121   99583  ffff880203e56f30  httpd",
"      121   99594  ffff88016e4e01c0  crond",
"      121   99614  ffff8803fb26cf70  xfs",
"      121   99624  ffff88045a6ce2c0  saslauthd",
"      121   99625  ffff8801ce134ff0  saslauthd",
"      121  248691  ffff88040e2ee9c0  httpd",
NULL
};

static struct command_table_entry command_table[] = {
	{ "vzlist", cmd_vzlist, help_vzlist, 0},
	{ "ctid", cmd_ctid, help_ctid, 0},
	{ "vzps", cmd_vzps, help_vzps, 0},
	{ NULL },
};

void __attribute__((constructor))
vz_init(void)
{
	if (init_flags & VZ_INIT)
		return;

	if (!symbol_exists("ve_list_head")) {
		fprintf(fp, "vz commands only work on OpenVZ kernels\n");
		return;
	}
	init_flags |= VZ_INIT;

	BNEG(&vz_offset_table, sizeof(vz_offset_table));

	if (STRUCT_EXISTS("ve_task_info")) {
		/* RHEL6-based OpenVZ */
		VZ_MEMBER_OFFSET_INIT(task_veinfo,
					 "task_struct", "ve_task_info");
		VZ_MEMBER_OFFSET_INIT(veinfo_ve, "ve_task_info", "exec_env");
	} else {
		/* RHEL7-based OpenVZ */
		VZ_MEMBER_OFFSET_INIT(task_ve, "task_struct", "task_ve");
	}
	if (STRUCT_EXISTS("ve_struct")) {
		VZ_MEMBER_OFFSET_INIT(ve_velist, "ve_struct", "ve_list");
		VZ_MEMBER_OFFSET_INIT(ve_veid, "ve_struct", "veid");
		VZ_MEMBER_OFFSET_INIT(ve_nsproxy, "ve_struct", "ve_ns");
		id_size = MEMBER_SIZE("ve_struct", "veid");
	}
	if (STRUCT_EXISTS("nsproxy")) {
		VZ_MEMBER_OFFSET_INIT(nsproxy_pidns, "nsproxy", "pid_ns");
	}
	if (STRUCT_EXISTS("pid_namespace"))
		VZ_MEMBER_OFFSET_INIT(pidns_init,
					"pid_namespace", "child_reaper");

	register_extension(command_table);
}

void __attribute__((destructor))
vz_fini(void) { }
