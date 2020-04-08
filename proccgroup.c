/*
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Nikolay Borisov <n.borisov.lkml@gmail.com>
 */

#include <stdbool.h>
#include "defs.h"

#define MAX_CGROUP_PATH 4096

static void showcgrp(void);
char *help_proc_cgroups[];

static bool have_ss_member;

static struct command_table_entry command_table[] = {
        { "showcg", showcgrp, help_proc_cgroups, 0},
        { NULL },
};


void __attribute__((constructor))
proccgroup_init(void)
{

    if (!MEMBER_EXISTS("task_struct", "cgroups") ||
        (!MEMBER_EXISTS("cgroup", "kn") && !MEMBER_EXISTS("cgroup", "name")))
    {
        error(FATAL, "Unrecognised or disabled cgroup support\n");
    }

    if (!MEMBER_EXISTS("cgroup_subsys_state", "ss")) {
        have_ss_member = false;
        error(WARNING, "pre-3.12 kernel detected, no support for getting subsys name\n");
    } else
        have_ss_member = true;

    register_extension(command_table);
}

void __attribute__((destructor))
proccgroup_finish(void) { }

/* Prepends contents of cgroup_name to buf, using start as a pointer
 * index into buf
 */
static void prepend_string(char *buf, char **start, char *cgroup_name) {

    int len = strlen(cgroup_name);
    *start -= len;

    if (*start < buf) {
        error(FATAL, "Cgroup too long to parse\n");
    }

    memcpy(*start, cgroup_name, len);

    if (--*start < buf) {
        error(FATAL, "Cgroup too long to parse\n");
    }

    **start = '/';
}

/* For post-3.15 kernels */
static void get_cgroup_name_kn(ulong cgroup, char *buf, int buflen)
{
    ulong kernfs_node;
    ulong cgroup_name_ptr;
    ulong kernfs_parent;
    bool slash_prepended = false;
    char cgroup_name[BUFSIZE];
    char *start = buf + buflen - 1;
    *start = '\0'; //null terminate the end

    /* Get cgroup->kn */
    readmem(cgroup + MEMBER_OFFSET("cgroup", "kn"), KVADDR, &kernfs_node, sizeof(void *),
            "cgroup->kn", FAULT_ON_ERROR);

    do {
        /* Get kn->name */
        readmem(kernfs_node + MEMBER_OFFSET("kernfs_node", "name"), KVADDR, &cgroup_name_ptr, sizeof(void *),
                "kernfs_node->name", FAULT_ON_ERROR);
        /* Get kn->parent */
        readmem(kernfs_node + MEMBER_OFFSET("kernfs_node", "parent"), KVADDR, &kernfs_parent, sizeof(void *),
                "kernfs_node->parent", FAULT_ON_ERROR);

        if (kernfs_parent != 0) {
            read_string(cgroup_name_ptr, cgroup_name, BUFSIZE-1);
            prepend_string(buf, &start, cgroup_name);
            slash_prepended = true;
        } else if (!slash_prepended) {
            if (--start < buf) {
                error(FATAL, "Cgroup too long to parse\n");
            }
            *start = '/';
        }

        kernfs_node = kernfs_parent;

    } while(kernfs_parent);

    memmove(buf, start, buf + buflen - start);
}

/* For pre-3.15 kernels */
static void get_cgroup_name_old(ulong cgroup, char *buf, size_t buflen)
{
    ulong cgroup_name_ptr;
    ulong cgroup_parent_ptr;
    char cgroup_name[BUFSIZE];
    char *start = buf + buflen - 1;
    *start = '\0'; //null terminate the end
    bool slash_prepended = false;

    do {
        /* Get cgroup->name */
        readmem(cgroup + MEMBER_OFFSET("cgroup", "name"), KVADDR, &cgroup_name_ptr, sizeof(void *),
                "cgroup->name", FAULT_ON_ERROR);
        /* Get cgroup->parent */
        readmem(cgroup + MEMBER_OFFSET("cgroup", "parent"), KVADDR, &cgroup_parent_ptr, sizeof(void *),
                "cgroup->parent", FAULT_ON_ERROR);

        read_string(cgroup_name_ptr + MEMBER_OFFSET("cgroup_name", "name"), cgroup_name, BUFSIZE-1);

        if (cgroup_parent_ptr) {
            prepend_string(buf, &start, cgroup_name);
            slash_prepended = true;
        } else if (!slash_prepended) {
            if (--start < buf)
                break;
            *start = '/';
        }

        cgroup = cgroup_parent_ptr;

    } while(cgroup_parent_ptr);

    memmove(buf, start, buf + buflen - start);
}

static void get_subsys_name(ulong subsys, char *buf, size_t buflen)
{
    ulong subsys_name_ptr;
    ulong cgroup_subsys_ptr;

    /* Get cgroup->kn */
    readmem(subsys + MEMBER_OFFSET("cgroup_subsys_state", "ss"), KVADDR, &cgroup_subsys_ptr, sizeof(void *),
            "cgroup_subsys_state->ss", FAULT_ON_ERROR);

    readmem(cgroup_subsys_ptr + MEMBER_OFFSET("cgroup_subsys", "name"), KVADDR, &subsys_name_ptr, sizeof(void *),
            "cgroup_subsys->name", FAULT_ON_ERROR);
    read_string(subsys_name_ptr, buf, buflen-1);
}

static void get_cgroup_name(ulong cgroup, ulong subsys)
{
    char *cgroup_path = GETBUF(MAX_CGROUP_PATH);
    char subsys_name[BUFSIZE];

    /* Handle the 2 cases of cgroup_name and the kernfs one */
    if (MEMBER_EXISTS("cgroup", "kn")) {
        get_cgroup_name_kn(cgroup, cgroup_path, MAX_CGROUP_PATH);
    } else if (MEMBER_EXISTS("cgroup", "name")) {
        get_cgroup_name_old(cgroup, cgroup_path, MAX_CGROUP_PATH);
    }

    /* pre-3.12 cgroup_subsys_state doesn't contain 'ss' member */
    if (have_ss_member) {
        get_subsys_name(subsys, subsys_name, BUFSIZE);
        fprintf(fp, "subsys: %-20s cgroup: %s\n", subsys_name, cgroup_path);
    } else {
        fprintf(fp, "cgroup: %s\n", cgroup_path);
    }


    FREEBUF(cgroup_path);
}


void show_proc_cgroups(ulong task_ctx) {
    int en_subsys_cnt;
    int i;
    ulong *cgroup_subsys_arr;
    ulong subsys_base_ptr;
	ulong cgroups_subsys_ptr = 0;


    /* Get address of task_struct->cgroups */
    readmem(task_ctx + MEMBER_OFFSET("task_struct", "cgroups"),
                            KVADDR, &cgroups_subsys_ptr, sizeof(void *),
                            "task_struct->cgroups", FAULT_ON_ERROR);

    subsys_base_ptr = cgroups_subsys_ptr + MEMBER_OFFSET("css_set", "subsys");
    en_subsys_cnt = MEMBER_SIZE("css_set", "subsys") / sizeof(void *);
    cgroup_subsys_arr = (ulong *)GETBUF(en_subsys_cnt * sizeof(ulong));

    /* Get the contents of the css_set->subsys array */
    readmem(subsys_base_ptr, KVADDR, cgroup_subsys_arr, sizeof(ulong) * en_subsys_cnt,
               "css_set->subsys", FAULT_ON_ERROR);

    for (i = 0; i < en_subsys_cnt; i++) {
        ulong cgroup;
		
		/* Generally the subsys_array is not NULL-terminated, however 
		 * a particular fedora kernel was NULL-terminated
		 */
		if (!cgroup_subsys_arr[i])
			continue;

        /* Get cgroup_subsys_state -> cgroup */
        readmem(cgroup_subsys_arr[i] + MEMBER_OFFSET("cgroup_subsys_state", "cgroup"),
                KVADDR, &cgroup, sizeof(void *), "cgroup_subsys_state->cgroup", FAULT_ON_ERROR);

        get_cgroup_name(cgroup, cgroup_subsys_arr[i]);
    }

    FREEBUF(cgroup_subsys_arr);
}


static void showcgrp(void) {
 
    ulong value;
    struct task_context *tc;
    ulong task_struct_ptr = 0;

    while (args[++optind]) {
        if (IS_A_NUMBER(args[optind])) {
                switch (str_to_context(args[optind], &value, &tc))
                {
                case STR_PID:
                    task_struct_ptr = tc->task;
                    ++optind;
                    break;

                case STR_TASK:
					task_struct_ptr = value;
                    ++optind;
                    break;

                case STR_INVALID:
                    error(FATAL, "invalid task or pid value: %s\n\n",
                            args[optind]);
                    break;
                }
        } else {
            if (argcnt > 1)
                error(FATAL, "invalid task or pid value: %s\n",args[optind]);
            else
                break;
        }
    }

    if (!task_struct_ptr) {
        task_struct_ptr = CURRENT_TASK();
    }

    show_proc_cgroups(task_struct_ptr);
}

char *help_proc_cgroups[] = {
        "showcg",
        "Show which cgroups is a process member of",
        " [task | pid]",

        " This command prints the cgroup for each subsys that a process is a member of",
        "\nExample",
        "  Show the cgroup for the currently active process:\n",
        "       crash> showcg",
        "       subsys: cpuset               cgroup: /user.slice/user-1000.slice/session-c1.scope",
        "       subsys: cpu                  cgroup: /user.slice/user-1000.slice/session-c1.scope",
        "       subsys: cpuacct              cgroup: /user.slice/user-1000.slice/session-c1.scope",
        "       subsys: blkio                cgroup: /user.slice/user-1000.slice/session-c1.scope",
        "       subsys: memory               cgroup: /user.slice/user-1000.slice/session-c1.scope",
        "       subsys: devices              cgroup: /user.slice/user-1000.slice/session-c1.scope",
        "       subsys: freezer              cgroup: /user.slice/user-1000.slice/session-c1.scope",
        "       subsys: net_cls              cgroup: /user.slice/user-1000.slice/session-c1.scope",
        "       subsys: perf_event           cgroup: /user.slice/user-1000.slice/session-c1.scope",
        "       subsys: net_prio             cgroup: /user.slice/user-1000.slice/session-c1.scope",
        "       subsys: hugetlb              cgroup: /user.slice/user-1000.slice/session-c1.scope",
        "\n  Alternatively you can pass either a pid or a task pointer to show the cgroup the",
        "  respective process is a member of e.g:\n",
        "       crash> showcg 1064\n   OR",
        "       crash> showcg ffff880405711b80",
        NULL
};


