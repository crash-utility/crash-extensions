/* lscgroup.c - list cgroups
 *
 * Copyright (C) 2012 FUJITSU LIMITED
 * Author: Yu Yongming <yuym.fnst@cn.fujitsu.com>
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

#define PATHNAME_MAX      200
#define ROOT_MAX          64
#define CG_CONTROLLER_MAX 20
#define CG_HIER_MAX       20
#define LIST_CER	  0x1
#define LIST_ADD	  0x2


#define CGROUP_MEMBER_OFFSET_INIT(X,Y,Z) (cgroup_offset_table.X=MEMBER_OFFSET(Y,Z))
#define CGROUP_OFFSET(X) (OFFSET_verify(cgroup_offset_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))

/*
 *struct declaration
 */
struct cgroup_offset_table {
	long cgroupfs_root_root_list;
	long cgroupfs_root_top_cgroup;
	long cgroupfs_root_subsys_list;
	long cgroupfs_root_actual_subsys_bits;
	long cgroupfs_root_name;
	long cgroup_sibling;
	long cgroup_children;
	long cgroup_dentry;
	long cgroup_subsys_name;
	long cgroup_subsys_sibling;
};

struct cgroup_group_spec {
	char path[PATHNAME_MAX];
	char *controllers[CG_CONTROLLER_MAX];
};

/*
 *function declaration
 */
int _init(void);
int _fini(void);

void cmd_lscgroup(void);
char *help_lscgroup[];

static void cgroup_init(void);
static void get_controller_name(ulong);
static void get_cgroup_name(ulong, char *);
static void parse_top_cgroup(ulong, char *);
static void print_all_cgroups(void);
static int in_cgroupfs_root(char *, struct cgroup_group_spec *);
static ulong locate_top_cgroup(struct cgroup_group_spec *);
static void parse_path(char *, char **);
static ulong locate_cgroup(ulong, ulong, char *);
static void standarlize_path(char *);
static void cgroup_elem(struct cgroup_group_spec *);
static void check_addr(ulong, ulong, char *, char *);
static ulong addr_to_cgroup(ulong, char *);
static void cgroup_addr(char *);
static void cgroup_list_cgroups(char **, struct cgroup_group_spec **, int);
static int parse_cgroup_spec(struct cgroup_group_spec **, char *);
static void free_cgroup_spec(char **, struct cgroup_group_spec **);

/*
 * global data
 */

static char controller_name[PATHNAME_MAX];
static int authen = FALSE;
char *spe;

static struct command_table_entry command_table[] = {
	{"lscgroup", cmd_lscgroup, help_lscgroup, 0},
	{NULL},
};

static struct cgroup_offset_table cgroup_offset_table = { 0 };

char *help_lscgroup[] = {
"lscgroup",
"list all cgroups",
"[[<controllers>:<path>] [...]] [[<address>][...]]",
"  The command list all present cgroups and their addresses, chosen cgroups",
"  and their addresses or cgroup according to input address. When no parameter",
"  is specified, the command list all cgroups which are present. When parameter",
"  controller/path is specified, the command list subcgroups of cgroup specified",
"  by parameter <controllers>:<path>, controllers in <controllers>:<path> can be",
"  a comma separated controller list. When the input is hexadecimal address, the",
"  command display the cgroup whose address equals to the specified parameter.",
"\nEXAMPLE",
"  display all cgroups:\n",
"    %s>lscgroup",
"         CGROUP       CONTROLLER:PATH",
"    ffff8801188f8030  blkio:/",
"    ffff8801188d3200  blkio:/libvirt",
"    ffff88011a724600  blkio:/libvirt/lxc",
"    ffff88011adac600  blkio:/libvirt/qemu",
"    ffff8801151f6030  net_cls:/",
"    ffff88011522a030  freezer:/",
"    ffff8801158f9200  freezer:/libvirt",
"    ffff88011a724800  freezer:/libvirt/lxc",
"    ffff88011adac800  freezer:/libvirt/qemu",
"    ffff880115264030  devices:/",
"    ffff880115846e00  devices:/libvirt",
"    ffff88011a724a00  devices:/libvirt/lxc",
"    ffff88011adaca00  devices:/libvirt/qemu",
"    ffff88011794c030  memory:/",
"    ffff88011738ca00  memory:/libvirt",
"    ffff88011a724c00  memory:/libvirt/lxc",
"    ffff88011adacc00  memory:/libvirt/qemu",
"    ffff880115b20030  cpuacct:/",
"    ffff8801191ed600  cpuacct:/libvirt",
"    ffff88011a08d200  cpuacct:/libvirt/lxc",
"    ffff8801188d3e00  cpuacct:/libvirt/qemu",
"    ffff88011923a030  cpu:/",
"    ffff880115846600  cpu:/libvirt",
"    ffff88011906e400  cpu:/libvirt/lxc",
"    ffff880117be6400  cpu:/libvirt/qemu",
"    ffff8801173f2030  cpuset:/",
"    ffff8801179e6200  cpuset:/libvirt",
"    ffff88011a08d000  cpuset:/libvirt/lxc",
"    ffff880119fe8000  cpuset:/libvirt/qemu",
"	",
"  display chosen cgroups:\n",
"    %s>lscgroup cpu:/libvirt  cpu:/",
"         CGROUP       CONTROLLER:PATH",
"    ffff880115846600  cpu:/libvirt",
"    ffff88011906e400  cpu:/libvirt/lxc",
"    ffff880117be6400  cpu:/libvirt/qemu",
"    ffff88011923a030  cpu:/",
"    ffff880115846600  cpu:/libvirt",
"    ffff88011906e400  cpu:/libvirt/lxc",
"    ffff880117be6400  cpu:/libvirt/qemu",
"       ",
"  display cgroup according to input address:\n",
"    %s>lscgroup ffff880119fe8000 ffff880115846600",
"         CGROUP       CONTROLLER:PATH",
"    ffff880119fe8000  cpuset:/libvirt/qemu",
"    ffff880115846600  cpu:/libvirt",
NULL
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

static void 
cgroup_init(void)
{
	CGROUP_MEMBER_OFFSET_INIT(cgroupfs_root_root_list, "cgroupfs_root",
		"root_list");
	CGROUP_MEMBER_OFFSET_INIT(cgroupfs_root_top_cgroup, "cgroupfs_root",
		"top_cgroup");
	CGROUP_MEMBER_OFFSET_INIT(cgroupfs_root_subsys_list, "cgroupfs_root",
		"subsys_list");
	CGROUP_MEMBER_OFFSET_INIT(cgroupfs_root_actual_subsys_bits,
		"cgroupfs_root", "actual_subsys_bits");
	CGROUP_MEMBER_OFFSET_INIT(cgroupfs_root_name, "cgroupfs_root",
		"name");
	CGROUP_MEMBER_OFFSET_INIT(cgroup_sibling, "cgroup", "sibling");
	CGROUP_MEMBER_OFFSET_INIT(cgroup_children, "cgroup", "children");
	CGROUP_MEMBER_OFFSET_INIT(cgroup_dentry, "cgroup", "dentry");
	CGROUP_MEMBER_OFFSET_INIT(cgroup_subsys_name, "cgroup_subsys", "name");
	CGROUP_MEMBER_OFFSET_INIT(cgroup_subsys_sibling, "cgroup_subsys", 
		"sibling");
}

static void 
get_controller_name(ulong cgroupfs_root)
{
	char name[PATHNAME_MAX];
	ulong subsys, next, subsys_list, name_buf, name_addr;
	int len;
	
	BZERO(name, PATHNAME_MAX);
	BZERO(controller_name, PATHNAME_MAX);

	readmem(cgroupfs_root + CGROUP_OFFSET(cgroupfs_root_actual_subsys_bits),
		KVADDR, &subsys, sizeof(ulong), "cgroupfs_root_actual_subsys",
		FAULT_ON_ERROR);
	if(subsys == 0) {
		readmem(cgroupfs_root + CGROUP_OFFSET(cgroupfs_root_name), 
			KVADDR, &name, ROOT_MAX, "cgroupfs_root_name",
			FAULT_ON_ERROR);
		strcat(controller_name, name);
		return ;
	}
	subsys_list = cgroupfs_root + CGROUP_OFFSET(cgroupfs_root_subsys_list);
	readmem(subsys_list, KVADDR, &next, sizeof(ulong),
		"cgroupfs_root_subsys_list", FAULT_ON_ERROR);
	
	do {
		name_buf = next - CGROUP_OFFSET(cgroup_subsys_sibling)
                	+ CGROUP_OFFSET(cgroup_subsys_name);
		readmem(name_buf, KVADDR, &name_addr, sizeof(ulong),
			"cgroup_subsys_name", FAULT_ON_ERROR);
                readmem(name_addr, KVADDR, name, sizeof(name), 
			"char* name", FAULT_ON_ERROR);
			
		strcat(controller_name, name);
		strcat(controller_name, ",");

		readmem(next, KVADDR, &next, sizeof(ulong),
                "list_head", FAULT_ON_ERROR);
	} while(next != subsys_list);
	
	len = strlen(controller_name);	
	controller_name[len-1] = '\0';
}

static void
get_cgroup_name(ulong cgroup, char *name)
{
	ulong dentry, name_addr;
	char *dentry_buf;
	int len;

	readmem(cgroup + CGROUP_OFFSET(cgroup_dentry), KVADDR,
		&dentry, sizeof(ulong), "cgroup dentry",
		FAULT_ON_ERROR);

	dentry_buf = GETBUF(SIZE(dentry));
	readmem(dentry, KVADDR, dentry_buf, SIZE(dentry),
		"dentry", FAULT_ON_ERROR);
	len = UINT(dentry_buf + OFFSET(dentry_d_name) + OFFSET(qstr_len));
	name_addr = ULONG(dentry_buf + OFFSET(dentry_d_name) + OFFSET(qstr_name));
	readmem(name_addr, KVADDR, name, len, "qstr name", FAULT_ON_ERROR);
	FREEBUF(dentry_buf);
}

static void 
parse_top_cgroup(ulong top_cgroup, char *path)
{
	int len;
	char tmp_buf[PATHNAME_MAX];
	ulong list_head[2], next, child;

	BZERO(tmp_buf, PATHNAME_MAX);
	get_cgroup_name(top_cgroup, tmp_buf);
	if (strlen(path) > 1) 
		strncat(path, "/", 1);
	strncat(path, tmp_buf, strlen(tmp_buf));

	fprintf(fp, "%lx  %s:%s\n", top_cgroup, controller_name, path);

	child = top_cgroup + CGROUP_OFFSET(cgroup_children);
	readmem(child, KVADDR, list_head, sizeof(ulong) * 2,
		"cgroup children", FAULT_ON_ERROR);

	if ((list_head[0] == child) && (list_head[1] == child))
		return;

	next = list_head[0];
	while (next != child) {
		top_cgroup = next - CGROUP_OFFSET(cgroup_sibling);
		readmem(top_cgroup + CGROUP_OFFSET(cgroup_sibling) +
			OFFSET(list_head_next), KVADDR, &next, sizeof(ulong),
			"cgroup siblings", FAULT_ON_ERROR);
		len = strlen(path);
		parse_top_cgroup(top_cgroup, path);
		path[len] = '\0';
	}
}

static void 
print_all_cgroups(void)
{
	struct syment *roots;
        ulong top_cgroup;
        ulong list_head[2], next, cgroupfs_root;;
        char path_name[PATHNAME_MAX];

        BZERO(path_name, PATHNAME_MAX);

        if (!(roots = symbol_search("roots")))
                error(FATAL, "roots symbol does not exist?\n");

        readmem(roots->value, KVADDR, list_head, sizeof(ulong) * 2,
                "list_head", FAULT_ON_ERROR);

        if ((list_head[0] == roots->value) && (list_head[1] == roots->value)) {
        	fprintf(fp, "no active cgroup hierarchy in the kernel.");
	        return;
	}

        next = list_head[0];
        while (next != roots->value) {
                cgroupfs_root = next - CGROUP_OFFSET(cgroupfs_root_root_list);
		get_controller_name(cgroupfs_root);

                top_cgroup = cgroupfs_root +
                        CGROUP_OFFSET(cgroupfs_root_top_cgroup);
                /* print infomation of cgroup and subcgroup */
                parse_top_cgroup(top_cgroup, path_name);
                readmem(next + OFFSET(list_head_next), KVADDR, &next,
                        sizeof(ulong), "list_head next", FAULT_ON_ERROR);
                BZERO(path_name, PATHNAME_MAX);
		BZERO(controller_name, PATHNAME_MAX);
        }
}

static int
in_cgroupfs_root(char *tmp_name, struct cgroup_group_spec *elem)
{
	char *name;
	int i = 0;
	name = strtok(tmp_name, ",");
	while(name != NULL) {	
		while(elem->controllers[i] != NULL && i < CG_CONTROLLER_MAX) {
			if(STREQ(name, elem->controllers[i]))
				return 1;
			i++;
		}
		name = strtok(NULL, ",");
		i = 0;
	}	
	
	return 0;
}

static ulong 
locate_top_cgroup(struct cgroup_group_spec *elem)
{
	struct syment *roots;
	ulong top_cgroup;
	ulong list_head[2], next, cgroupfs_root;
	char tmp_name[PATHNAME_MAX];

	if (!(roots = symbol_search("roots")))
		error(FATAL, "roots symbol does not exist?");

	readmem(roots->value, KVADDR, list_head, sizeof(ulong)*2,
		"list_head", FAULT_ON_ERROR);

	if ((list_head[0] == roots->value) && (list_head[1] == roots->value))
		return 0;
	
	next = list_head[0];
	while (next != roots->value) {
		/* begin from first root */
		cgroupfs_root = next - CGROUP_OFFSET(cgroupfs_root_root_list);
		get_controller_name(cgroupfs_root);
		strcpy(tmp_name, controller_name);

		if (in_cgroupfs_root(tmp_name, elem)) {
   			top_cgroup = cgroupfs_root +
   				CGROUP_OFFSET(cgroupfs_root_top_cgroup);
  			return top_cgroup;
		}
		readmem(next + OFFSET(list_head_next), KVADDR, &next,
   			sizeof(ulong), "list_head", FAULT_ON_ERROR);
		BZERO(controller_name, PATHNAME_MAX);
	}
	return 0;
}

/*
 * function parse_path and extracts the input path before the first '/' as
 * relatively path which will be used to compare with path name of cgroup.
 * In addition, it ignores the unnecessary '/' in the path
 */
static void 
parse_path(char *path, char **elem_path)
{ 
 	char *token;

	token = *elem_path;
	if (token[0] == '/') {
		*path++ = *token++;
	} else {
		while (*token) {
			if (*token == '/' && *(token + 1) == '/') {
				token++;
			} else if (*token == '/' && *(token + 1) != '/') {
				token++; 
				break;
			} else {
				*path++ = *token++;	
			}
		}	
	}
	*elem_path = token;
	*path = '\0';
}

static ulong 
locate_cgroup(ulong current, ulong prev_addr, char *elem_path)
{
        char tmp_buf[PATHNAME_MAX];
	char path[PATHNAME_MAX];
	char *tmp_path = elem_path;
	ulong child, sibling, child_offset, sibling_offset;

	if (*elem_path == '\0')
		return prev_addr;

        BZERO(tmp_buf, PATHNAME_MAX);
	get_cgroup_name(current, tmp_buf);

	parse_path(path, &elem_path);

	readmem(current + CGROUP_OFFSET(cgroup_children), KVADDR, &child,
                sizeof(ulong), "cgroup children", FAULT_ON_ERROR);
        readmem(current + CGROUP_OFFSET(cgroup_sibling), KVADDR, &sibling,
                sizeof(ulong), "cgroup sibling", FAULT_ON_ERROR);	

	child_offset = CGROUP_OFFSET(cgroup_children);
	sibling_offset = CGROUP_OFFSET(cgroup_sibling);
	/* parse the children if temp=path_name, do change elem_path */
	if (STREQ(tmp_buf, path)) {
		if ((child - child_offset != current))
			return locate_cgroup(child - sibling_offset,
					current, elem_path);
		else if (*elem_path == '\0')
			return current;
	} else { 
	/* parse the sibling if temp !=path_name, do not chage elem_path */
		if (((sibling - child_offset) != prev_addr) &&
		    ((sibling - sibling_offset) != current)) {
			elem_path = tmp_path;
			return locate_cgroup(sibling - sibling_offset,
					prev_addr, elem_path);
		}
	}
	return 0;
}

/*
 * make the input path begin with character '/' and end without character '/'
 * to cope with the situation that the input path may be like "/xxxxx",
 * "xxxxx", "xxxxx/", or "/xxxxx/"
 */
static void 
standarlize_path(char *path)
{
	int len;

	len = strlen(path) - 1;
	if (path[len] == '/')
		path[len] = '\0';

	if (path[0] != '/') {
		len = strlen(path);
		path[len + 1] = '\0';
		while (len) {
			path[len] = path[len - 1];
			len--;
		}
		path[0] = '/';
	}
}

static void 
mani_path(char *path)
{	
	int len;

	standarlize_path(path);
 	
	if (STREQ(path, "/")) {
		*path = '\0';
                return ;
	}
	len = strlen(path);
	while (path[len] != '/') {
		path[len] = '\0';
		len--;
	}
	path[len] = '\0';
	path[0] = '/';
}

static void 
cgroup_elem(struct cgroup_group_spec *list_elem)
{
	ulong top_cgroup;
	ulong cgroup;
	char path_name[PATHNAME_MAX];
	char buf1[BUFSIZE];

	top_cgroup = locate_top_cgroup(list_elem);
	if (top_cgroup == 0) {
		fprintf(fp, "%s  %s\n",
                mkstring(buf1, VADDR_PRLEN, CENTER, "no cgroup"), 
			spe);
		return ;
	}
        
	strcpy(path_name, list_elem->path);
	standarlize_path(path_name);
	cgroup = locate_cgroup(top_cgroup, top_cgroup, path_name);
	if (cgroup == 0) {
		fprintf(fp, "%s  %s\n",
                mkstring(buf1, VADDR_PRLEN, CENTER, "no cgroup"),
                        spe);
		return ;
	}
 
	mani_path(list_elem->path);
	parse_top_cgroup(cgroup, list_elem->path);
}

static void 
check_addr(ulong top_cgroup, ulong addr_num, char *path, char *full_path)
{
	int len;
        char tmp_buf[PATHNAME_MAX];
        ulong list_head[2], next, child;

        BZERO(tmp_buf, PATHNAME_MAX);
        get_cgroup_name(top_cgroup, tmp_buf);
        if (strlen(path) > 1)
                strncat(path, "/", 1);
        strncat(path, tmp_buf, strlen(tmp_buf));

	if (top_cgroup == addr_num) {
                strcpy(full_path, path);
		authen = TRUE;
                return ;
        }

        child = top_cgroup + CGROUP_OFFSET(cgroup_children);
        readmem(child, KVADDR, list_head, sizeof(ulong) * 2,
                "cgroup children", FAULT_ON_ERROR);

        next = list_head[0];
        while (next != child) {
                top_cgroup = next - CGROUP_OFFSET(cgroup_sibling);
                readmem(top_cgroup + CGROUP_OFFSET(cgroup_sibling) +
                        OFFSET(list_head_next), KVADDR, &next, sizeof(ulong),
                        "cgroup siblings", FAULT_ON_ERROR);
                len = strlen(path);
                check_addr(top_cgroup, addr_num, path, full_path);
                path[len] = '\0';
        }
}

static ulong 
addr_to_cgroup(ulong addr_num, char *path)
{
	struct syment *roots;
        ulong top_cgroup;
        ulong list_head[2], next, cgroupfs_root;
	char path_name[PATHNAME_MAX];

	BZERO(path_name, PATHNAME_MAX);
        if (!(roots = symbol_search("roots")))
                error(FATAL, "roots symbol does not exist?");

        readmem(roots->value, KVADDR, list_head, sizeof(ulong)*2,
                "list_head", FAULT_ON_ERROR);

        next = list_head[0];
        while (next != roots->value) {
                /* begin from first root */
                cgroupfs_root = next - CGROUP_OFFSET(cgroupfs_root_root_list);
                get_controller_name(cgroupfs_root);

                top_cgroup = cgroupfs_root +
                	CGROUP_OFFSET(cgroupfs_root_top_cgroup);
		check_addr(top_cgroup, addr_num, path_name, path);
		if (authen) {
			authen = FALSE;
			return TRUE;
		}	
                readmem(next + OFFSET(list_head_next), KVADDR, &next,
                        sizeof(ulong), "list_head", FAULT_ON_ERROR);
		BZERO(path_name, PATHNAME_MAX);
                BZERO(controller_name, PATHNAME_MAX);
        }
        return FALSE;	 	
}

static void 
cgroup_addr(char *addr)
{
	ulong addr_num;
	char path[PATHNAME_MAX];
	char buf1[BUFSIZE];

	BZERO(path, PATHNAME_MAX);
	addr_num = stol (addr, FAULT_ON_ERROR, NULL);

	if (!addr_to_cgroup(addr_num, path)) {
		fprintf(fp, "%s  can not find cgroup with address %s\n",
                mkstring(buf1, VADDR_PRLEN, CENTER, addr), addr);
		return ;	
	}
	fprintf(fp, "%lx  %s:%s\n", addr_num, controller_name, path);	
}

static void 
cgroup_list_cgroups(char **addr, struct cgroup_group_spec *cgroup_list[],
	int flags)
{
	int i,j;
	char buf1[BUFSIZE];

	i = j = 0;	
	cgroup_init();
	if(cgroup_offset_table.cgroupfs_root_root_list == -1) {
		fprintf(fp, "cgroup does not exist, check kernel version.");
		return ;
	}
	fprintf(fp, "%s  CONTROLLER:PATH\n",
                mkstring(buf1, VADDR_PRLEN, CENTER, "CGROUP"));
	if (flags == 0 ) {
		/* list all the cgroups */
		print_all_cgroups();
	} 
	if (flags & LIST_CER) {
		/* list the specified cgroups */
		while ((cgroup_list[i]->path != NULL)) {
			cgroup_elem(cgroup_list[i]);
			i++;
		}
	}
	if (flags & LIST_ADD) {
		/* list specified addr cgroups */
		while ((addr[j] != NULL)) {
			cgroup_addr(addr[j]);
			j++;
		}	
	}
}

static int 
parse_cgroup_spec(struct cgroup_group_spec **list, char *optarg)
{
	struct cgroup_group_spec *ptr;
	int i, j;
	char *controller, *path, *temp;

	ptr = *list;

	for (i = 0; i < CG_HIER_MAX; i++, ptr++) {
		if (!list[i])
			break;
	}

	if (i == CG_HIER_MAX) {
		fprintf(fp, "Max allowed hierarchies %d reached\n",
			CG_HIER_MAX);
		return -1;
	}

	controller = strtok(optarg, ":");
	if (!controller)
		return -1;

	path = strtok(NULL, ":");
	if (!path)
		return -1;

	list[i] = (struct cgroup_group_spec *)GETBUF(sizeof(**list));
	j = 0;
	do {
		if (j == 0)
			temp = strtok(controller, ",");
		else
			temp = strtok(NULL, ",");

		if (temp) {
			list[i]->controllers[j] = strdup(temp);
			if (!list[i]->controllers[j]) {
				FREEBUF(list[i]);
				fprintf(fp, "%s\n", strerror(errno));
				return -1;
			}
		}
		j++;
	} while (temp && (j < (CG_CONTROLLER_MAX - 1)));

	strncpy(list[i]->path, path, strlen(path));

	return 0;
}

static int 
parse_addr_spec(char **addr,char *optarg)
{
	int i;

	for(i = 0; i < CG_HIER_MAX; i++)
		if (!addr[i])
			break;
	if (i == CG_HIER_MAX) {
                fprintf(fp, "Max allowed hierarchies %d reached\n",
                        CG_HIER_MAX);
                return -1;
        }
	
	addr[i] = strdup(optarg);
	if (!addr[i]) {
		fprintf(fp, "%s\n",strerror(errno));
		return -1;
	}
	return 0;
}

static void 
free_cgroup_spec(char **addr, struct cgroup_group_spec **list)
{
	int i,j;

	for (i = 0; i < CG_HIER_MAX; i++) {
		if (list[i]) {
			for(j = 0; j< CG_CONTROLLER_MAX; j++)
				if (list[i]->controllers[j])
					free(list[i]->controllers[j]);
			FREEBUF(list[i]);
		}
		else {
			break;
		}	
	}
	for (i =0; i< CG_HIER_MAX; i++) {
		if (addr[i])
			free(addr[i]);
		else 
			break;
	}

}

void 
cmd_lscgroup(void)
{
	int c, ret, flags;
	char *addr[CG_HIER_MAX];
	struct cgroup_group_spec *cgroup_list[CG_HIER_MAX];

	ret = flags = 0;
	BZERO(cgroup_list, sizeof(cgroup_list));
	BZERO(addr, sizeof(addr));

	while ((c = getopt(argcnt, args, "")) != EOF) {
		switch(c) {
		default:
			cmd_usage(pc->curcmd, SYNOPSIS);
			return ;
		}
	}
	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);
	while (optind < argcnt) {
		spe = strdup(args[optind]);
		if (args[optind]) {
			if (hexadecimal(args[optind], 0)) {
				ret = parse_addr_spec(addr, args[optind]);
				if (ret) {
					fprintf(fp, "%s: cgroup controller "
						"and path parsing failed(%s)\n",
                                        	args[0], args[optind]);
					free_cgroup_spec(addr, cgroup_list);
					return ;
				}
			}
			else {
				ret = parse_cgroup_spec(cgroup_list,
					args[optind]);
				if (ret) {
					 fprintf(fp, "%s: cgroup controller "
                                                "and path parsing failed(%s)\n",
                                                args[0], args[optind]);
                                        free_cgroup_spec(addr, cgroup_list);
					return ;
				}

			}
		}
		optind++;
	}	
	
	if (addr[0] != NULL)
		flags |= LIST_ADD;

	if (cgroup_list[0] != NULL)
		flags |= LIST_CER;	

	cgroup_list_cgroups(addr, cgroup_list, flags);
	free_cgroup_spec(addr, cgroup_list);
}

