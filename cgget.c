/*
 * cgget.c - Display the parameters of cgroup.
 *
 * Copyright (C) 2012 FUJITSU LIMITED
 * Author: Zhang Xiaohe <zhangxh@cn.fujitsu.com>
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
#include <getopt.h>

/* HZ is 1000 as default after kernel 2.6 */
#ifdef HZ
#undef HZ
#define HZ 1000
#endif
/* USER_HZ is 100 only on X86 platform */
#define USER_HZ 100
#define NSEC_PER_SEC 1000000000ULL
#define NSEC_PER_USEC 1000L

#define DEV_BLOCK 1
#define DEV_CHAR  2
#define DEV_ALL   4
#define MAJMINLEN 13
#define ACCLEN 4
#define ACC_MKNOD 1
#define ACC_READ  2
#define ACC_WRITE 4
#define ACC_MASK (ACC_MKNOD|ACC_READ|ACC_WRITE)

#define LRU_BASE 0
#define LRU_ACTIVE 1
#define LRU_FILE 2

#define CGROUP_HIER_MAX 100
#define CGROUP_STR_LEN 32
#define MODE_SEPARATE_PATH 0x01
#define MODE_COMBINE_PATH 0x02

#define CGGET_MEMBER_OFFSET_INIT(TABLE, MEMBER, STRUCT, X)		\
	TABLE.MEMBER = MEMBER_OFFSET(STRUCT, X)
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_LONG)

#define BLKIO_MERGE_POL(x, val)		(((x) << 16) | (val))
#define MINORBITS       20
#define MINORMASK       ((1U << MINORBITS) - 1)
#define MAJOR(dev)      ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)      ((unsigned int) ((dev) & MINORMASK))

#define CGROUP_SUBSYS_COUNT cgroup_subsys_num

#define CGROUP_NOT_SUPPORT 0
#define CGROUP_SUPPORTED   1

#define for_each_possible_cpu(cpu)				\
	for ((cpu) = -1; (cpu) = next_possible_cpu(cpu),	\
			 (cpu) < kt->cpus;)

struct cgroup_spec {
	char subsys_str[CGROUP_STR_LEN];
	char path[FILENAME_MAX];
};

struct cgroupfs_root_offset_table {
	long cgroupfs_root_top_cgroup;
	long cgroupfs_root_number_of_cgroups;
	long cgroupfs_root_root_list;
};

struct cgroup_offset_table {
	long cgroup_sibling;
	long cgroup_children;
	long cgroup_parent;
	long cgroup_dentry;
	long cgroup_subsys;
};

struct cpuset_offset_table {
	long cpuset_flags;
	long cpuset_cpus_allowed;
	long cpuset_mems_allowed;
	long cpuset_fmeter;
	long cpuset_shed_relax_domain_level;
};

struct tg_offset_table {
	long tg_shares;
	long tg_rt_bandwidth;
	long tg_cfs_bandwidth;
};

struct cpuacct_offset_table {
	long cpuacct_cpuusage;
	long cpuacct_cpustat;
};

struct hugetlb_offset_table {
	long hugetlb_hugepage;
};

struct memory_offset_table {
	long memory_res;
	long memory_memsw;
	long memory_kmem;
	long memory_tcp_mem;
	long memory_info;
	long memory_stat;
	long memory_oom_kill_disable;
	long memory_under_oom;
	long memory_mcai;
	long memory_swappiness;
	long memory_use_hierarchy;
	long counter_usage;
	long counter_max_usage;
	long counter_limit;
	long counter_soft_limit;
	long counter_failcnt;
	long perzone_count;
};

struct devices_offset_table {
	long devices_whitelist;
	long devices_behavior;
	long item_major;
	long item_minor;
	long item_type;
	long item_access;
	long item_list;
};

struct freezer_offset_table {
	long freezer_state;
};

struct cls_offset_table {
	long cls_classid;
};

struct blkio_offset_table {
	long blkio_blkg_list;
	long blkio_policy_list;
	long blkio_weight;
	long blkg_blkcg_node;
	long blkg_dev;
	long blkg_plid;
	long blkg_stats;
	long blkg_stats_cpu;
	long blkp_dev;
	long blkp_plid;
	long blkp_fileid;
	long blkp_weight;
	long blkg_pd;
	long cfq_group_stats;
	long cfqg_stats_service_bytes;
	long cfqg_stats_serviced;
	long cfqg_stats_time;
	long cfqg_stats_sectors;
	long cfqg_stats_service_time;
	long cfqg_stats_wait_time;
	long cfqg_stats_merged;
	long cfqg_stats_queued;
};

struct netprio_offset_table {
	long netprio_prioidx;
};

static struct cgroupfs_root_offset_table cgroupfs_root_offset_table = {0};
static struct cgroup_offset_table cgroup_offset_table = {0};
static struct cpuset_offset_table cpuset_offset_table = {0};
static struct tg_offset_table tg_offset_table = {0};
static struct cpuacct_offset_table cpuacct_offset_table = {0};
static struct hugetlb_offset_table hugetlb_offset_table = {0};
static struct memory_offset_table memory_offset_table = {0};
static struct devices_offset_table devices_offset_table = {0};
static struct freezer_offset_table freezer_offset_table = {0};
static struct cls_offset_table cls_offset_table = {0};
static struct blkio_offset_table blkio_offset_table = {0};
static struct netprio_offset_table netprio_offset_table = {0};

static const char *cpuset_params[] = {
	"cpu_exclusive",
	"mem_exclusive",
	"mem_hardwall",
	"memory_migrate",
	"sched_load_balance",
	"memory_spread_page",
	"memory_spread_slab",
	"memory_pressure_enabled",
	"memory_pressure",
	"sched_relax_domain_level",
	"mems",
	"cpus"
};

enum {
	CS_CPU_EXCLUSIVE,
	CS_MEM_EXCLUSIVE,
	CS_MEM_HARDWALL,
	CS_MEMORY_MIGRATE,
	CS_SCHED_LOAD_BALANCE,
	CS_SPREAD_PAGE,
	CS_SPREAD_SLAB,
	CS_MEM_PRESSURE_ENABLE,
	CS_MEM_PRESSURE,
	CS_SHED_RELAX_DOMAIN_LEVEL,
	CS_MEMS,
	CS_CPUS,
};

static const char *cpu_params[] = {
	"rt_period_us",
	"rt_runtime_us",
	"stat",
	"cfs_period_us",
	"cfs_quota_us",
	"shares",
};

enum cpu_param_id {
	CPU_RT_PERIOD,
	CPU_RT_RUNTIME,
	CPU_STAT,
	CPU_CFS_PERIOD,
	CPU_CFS_QUOTA,
	CPU_SHARES,
	CPU_NR_PARAMS,
};

static const char *cpuacct_params[] = {
	"stat",
	"usage_percpu",
	"usage",
};

enum cpuacct_param_id {
	CPUACCT_STAT,
	CPUACCT_USAGE_PERCPU,
	CPUACCT_USAGE,
	CPUACCT_NR_PARAMS,
};

enum memory_param_id {
	MEM_TMEM_FAILCNT,
	MEM_TMEM_LIMIT,
	MEM_TMEM_MAX_USAGE,
	MEM_TMEM_USAGE,
	MEM_KMEM_FAILCNT,
	MEM_KMEM_LIMIT,
	MEM_KMEM_MAX_USAGE,
	MEM_KMEM_USAGE,
	MEM_MEMSW_FAILCNT,
	MEM_MEMSW_LIMIT,
	MEM_MEMSW_MAX_USAGE,
	MEM_MEMSW_USAGE,
	MEM_NUMA_STAT,
	MEM_OOM_CTRL,
	MEM_MCAI,
	MEM_SWAP,
	MEM_USE_HIER,
	MEM_FORCE_EMPTY,
	MEM_STAT,
	MEM_FAILCNT,
	MEM_SOFT_LIMIT,
	MEM_LIMIT,
	MEM_MAX_USAGE,
	MEM_USAGE,
	MEM_NR_PARAMS,
};

static const char *memory_params[] = {
	"kmem.tcp.failcnt",
	"kmem.tcp.limit_in_bytes",
	"kmem.tcp.max_usage_in_bytes",
	"kmem.tcp.usage_in_bytes",
	"kmem.failcnt",
	"kmem.limit_in_bytes",
	"kmem.max_usage_in_bytes",
	"kmem.usage_in_bytes",
	"memsw.failcnt",
	"memsw.limit_in_bytes",
	"memsw.max_usage_in_bytes",
	"memsw.usage_in_bytes",
	"numa_stat",
	"oom_control",
	"move_charge_at_immigrate",
	"swappiness",
	"use_hierarchy",
	"force_empty",
	"stat",
	"failcnt",
	"soft_limit_in_bytes",
	"limit_in_bytes",
	"max_usage_in_bytes",
	"usage_in_bytes",
	NULL,
};

enum lru_list {
	LRU_INACTIVE_ANON = LRU_BASE,
	LRU_ACTIVE_ANON = LRU_BASE + LRU_ACTIVE,
	LRU_INACTIVE_FILE = LRU_BASE + LRU_FILE,
	LRU_ACTIVE_FILE = LRU_BASE + LRU_FILE + LRU_ACTIVE,
	LRU_UNEVICTABLE,
	NR_LRU_LISTS
};

enum {
	MCS_CACHE,
	MCS_RSS,
	MCS_FILE_MAPPED,
	MCS_SWAP,
	MCS_PGPGIN,
	MCS_PGPGOUT,
	MCS_PGFAULT,
	MCS_PGMAJFAULT,
	MCS_INACTIVE_ANON,
	MCS_ACTIVE_ANON,
	MCS_INACTIVE_FILE,
	MCS_ACTIVE_FILE,
	MCS_UNEVICTABLE,
	NR_MCS_STAT,
};

struct {
	char *local_name;
	char *total_name;
} memcg_stat_strings[NR_MCS_STAT] = {
	{"cache", "total_cache"},
	{"rss", "total_rss"},
	{"mapped_file", "total_mapped_file"},
	{"swap", "total_swap"},
	{"pgpgin", "total_pgpgin"},
	{"pgpgout", "total_pgpgout"},
	{"pgfault", "total_pgfault"},
	{"pgmajfault", "total_pgmajfault"},
	{"inactive_anon", "total_inactive_anon"},
	{"active_anon", "total_active_anon"},
	{"inactive_file", "total_inactive_file"},
	{"active_file", "total_active_file"},
	{"unevictable", "total_unevictable"}
};

enum freezer_state {
	CGROUP_THAWED = 0,
	CGROUP_FREEZING,
	CGROUP_FROZEN,
};

static const char *freezer_state_strs[] = {
	"THAWED",
	"FREEZING",
	"FROZEN",
};

static const char *blkio_prop_strs[] = {
	"weight",
	"weight_device",
	"io_service_bytes",
	"io_serviced",
	"time",
	"sectors",
	"io_service_time",
	"io_wait_time",
	"io_merged",
	"io_queued",
	"reset_stats",
};

static const char *blkio_thro_strs[] = {
	"throttle.read_bps_device",
	"throttle.write_bps_device",
	"throttle.read_iops_device",
	"throttle.write_iops_device",
	"throttle.io_service_bytes",
	"throttle.io_serviced",
};


enum blkio_plid {
	BLKIO_POLICY_PROP = 0,          /* Proportional Bandwidth division */
	BLKIO_POLICY_THROTL,            /* Throttling */
	BLKCG_POLICY_THROTL,            /* Id of throtl is 0 from v3.5 */
	BLKCG_POLICY_PROP,
};

/* blkio attributes owned by proportional weight policy */
enum blkcg_file_name_prop {
	BLKIO_PROP_weight = 1,
	BLKIO_PROP_weight_device,
	BLKIO_PROP_io_service_bytes,
	BLKIO_PROP_io_serviced,
	BLKIO_PROP_time,
	BLKIO_PROP_sectors,
	BLKIO_PROP_io_service_time,
	BLKIO_PROP_io_wait_time,
	BLKIO_PROP_io_merged,
	BLKIO_PROP_io_queued,
	BLKIO_PROP_avg_queue_size,
	BLKIO_PROP_group_wait_time,
	BLKIO_PROP_idle_time,
	BLKIO_PROP_empty_time,
	BLKIO_PROP_dequeue,
};

enum stat_type {
	BLKIO_STAT_SERVICE_TIME,
	BLKIO_STAT_SERVICE_BYTES,
	BLKIO_STAT_SERVICED,
	BLKIO_STAT_WAIT_TIME,
	BLKIO_STAT_MERGED,
	BLKIO_STAT_QUEUED,
	BLKIO_STAT_TIME,
	BLKIO_STAT_SECTORS,
};

/* blkio attributes owned by throttle policy */
enum blkcg_file_name_throtl {
	BLKIO_THROTL_read_bps_device,
	BLKIO_THROTL_write_bps_device,
	BLKIO_THROTL_read_iops_device,
	BLKIO_THROTL_write_iops_device,
	BLKIO_THROTL_io_service_bytes,
	BLKIO_THROTL_io_serviced,
};

/* Per cpu stats, added from kernel version 3.0 */
enum stat_type_cpu {
	BLKIO_STAT_CPU_SECTORS,
	BLKIO_STAT_CPU_SERVICE_BYTES,
	BLKIO_STAT_CPU_SERVICED,
	BLKIO_STAT_CPU_MERGED,
	BLKIO_STAT_CPU_NR
};

enum stat_sub_type {
	BLKIO_STAT_READ = 0,
	BLKIO_STAT_WRITE,
	BLKIO_STAT_SYNC,
	BLKIO_STAT_ASYNC,
	BLKIO_STAT_TOTAL
};

enum all_subsys_id {
	cpuset_subsys_id,
	debug_subsys_id,
	ns_subsys_id,
	cpu_cgroup_subsys_id,
	cpuacct_subsys_id,
	hugetlb_subsys_id,
	mem_cgroup_subsys_id,
	devices_subsys_id,
	freezer_subsys_id,
	net_cls_subsys_id,
	blkio_subsys_id,
	perf_subsys_id,
	net_prio_subsys_id,
	CGROUP_SUBSYS_MAX
};

static const char *subsys_name[] = {
	"cpuset",
	"debug",
	"ns",
	"cpu",
	"cpuacct",
	"hugetlb",
	"memory",
	"devices",
	"freezer",
	"net_cls",
	"blkio",
	"perf_event",
	"net_prio"
};

struct cgroup_subsys_table {
	int subsys_id;
	char subsys_str[CGROUP_STR_LEN];
};

static struct cgroup_subsys_table cgroup_subsys_table[CGROUP_SUBSYS_MAX];
static int cgroup_subsys_num = 0;
static int is_cgroup_supported = 0;
static uint variable_flag = 0;
static int var_num[CGROUP_SUBSYS_MAX] = {0};
static char *variable_str[CGROUP_SUBSYS_MAX][30] = {{0}};

static struct option long_options[] = {
	{"help", no_argument, 0, 'h'},
	{"group", required_argument, 0, 'g'},
	{"all", no_argument, 0, 'a'},
	{0, 0, 0, 0}
};

int _init(void);
int _fini(void);

char *help_cgget[];
void cmd_cgget(void);

/* printing functions for every subsys */
static void print_cpuset(struct cgroup_spec *, int, ulong);
static void print_cpu(struct cgroup_spec *, int, ulong);
static void print_cpuacct(struct cgroup_spec *, int, ulong);
static void print_hugetlb(struct cgroup_spec *, int, ulong);
static void print_memory(struct cgroup_spec *, int, ulong);
static void print_devices(struct cgroup_spec *, int, ulong);
static void print_freezer(struct cgroup_spec *, int, ulong);
static void print_net_cls(struct cgroup_spec *, int, ulong);
static void print_blkio(struct cgroup_spec *, int, ulong);
static void print_net_prio(struct cgroup_spec *, int, ulong);
#if 0
/* ns and perf_event has nothing to print for now*/
static void print_ns(struct cgroup_spec *, int, ulong);
static void print_perf(struct cgroup_spec *, int, ulong);
#endif

/* offset table initialization functions */
static void cgget_offset_table_init();
static void cgroupfs_root_offset_table_init();
static void cgroup_offset_table_init();
static void cpuset_offset_table_init();
static void tg_offset_table_init();
static void cpuacct_offset_table_init();
static void hugetlb_offset_table_init();
static void memory_offset_table_init();
static void devices_offset_table_init();
static void freezer_offset_table_init();
static void cls_offset_table_init();
static void blkio_offset_table_init();
static void netprio_offset_table_init();

/* printing-assisted functions */
static int read_whitelist(struct cgroup_spec *, ulong, int);
static char *hugepage_fmt(char *, uint64_t);
static inline int is_root_mem_cgroup(ulong);
static uint64_t read_res_counter(ulong, long, char *);
static uint64_t mem_cgroup_read_local_zonestat(ulong, int);
static int64_t mem_cgroup_read_stat(void*, int);
static int get_mem_local_stats(ulong, int64_t *, int);
static int get_mem_total_stats(ulong, int64_t *, int);
static void get_mem_hierarchical_limit(ulong, uint64_t *, uint64_t *, int);
static int read_blkcg_stat(ulong, enum stat_type, int, int, int, char *);
static int read_policy_node(ulong, int, int, char *);
static int blkio_read_map(ulong, int, int, char *);
static uint64_t blkio_get_stat_cpu(ulong, enum stat_type, uint32_t, char *);
static uint64_t blkio_get_stat(ulong, enum stat_type, uint32_t, char *);
static void cpuacct_print_stat(ulong);
static uint64_t cpuacct_print_usage_percpu(ulong);
static void cpu_print_stat(ulong);
static void cpu_print_bandwidth(ulong, long, int, char *);
static ulong get_mz_lru_val(ulong, int, int, int);
static int64_t get_value_acc_ver(int64_t *, int, int, int);
static void get_mem_percpu_stats(ulong, void *);
static int css_member(ulong, char *, int);
static ulong idr_get_next(ulong, int *);
static ulong mem_cgroup_iter(ulong, ulong);
static uint64_t get_mem_usage(ulong, int);
static void mem_print_oom_ctrl(ulong);
static void mem_print_swap(ulong, char *);
static void mem_print_numa_stat(ulong, uint64_t *);
static uint64_t print_u64_rw(char *, uint64_t *);
static uint64_t print_thro_u64_rw(char *, ulong, int);
static void dev_name(ulong, char *);
static int test_policy(ulong, int);
static uint64_t print_cfq_group(ulong, int, long, size_t);
static uint64_t print_throtl_grp(ulong, int, long, size_t);
static int read_policy_group(ulong, int, int, char *);
static void blkio_read_each_blkg_for35(ulong, int, int, char *);
static void blkio_read_each_blkg_for37(ulong, int, int, int, char *);
static void blkio_read_each_blkg_for300(ulong, int, int, int, int, char *);
static ulong read_blkcg_stat_old(ulong, int, char *);
static void blkio_print_param_old(ulong);
static int blkio_print_param_no_group(ulong, int, int, char *);

/* general purpose functions */
static inline int next_possible_cpu(int);
static struct list_head *list_next(void *, void *, long);
static inline int test_bit(int, ulong);
static inline int bitmap_scnlistprintf(char *, unsigned, ulong *, int);
static inline uint64_t jiffies_64_to_clock_t(uint64_t);
static inline int check_endian();
static inline uint64_t ktime_to_ns(ulong);
static inline int bitstr_edit(char *, int, int, int);
static inline void set_majmin(char *, unsigned);
static inline void set_access(char *, short);
static inline char type_to_char(short);
static ulong get_subsys_parent(ulong, int);
static inline char *get_dentry_path(ulong, char *, int);
static void format_path_str(const char *, char *);
static void filter_str(char **, int *);
static int make_cgroup_spec(struct cgroup_spec **, char **,
			    char **, int *, int*);
static int make_all_cgroup_spec(struct cgroup_spec **, char **,
				char **, int *, int *);
static void cgroup_subsys_table_init();
static int parse_variable_spec(char *, char **, int *);
static void print_specified_param(int);
static void print_cgroup_list(char *, struct cgroup_spec **, int, int);
static ulong retrieve_path(ulong, ulong, ulong *, const char *);
static ulong get_css_addr(struct cgroup_spec *, int, ulong);
static int get_subsys_id(struct cgroup_spec *);
static void print_cgroup(char *, struct cgroup_spec *, int, ulong, int);
static int64_t read_member_64(ulong, char *);
static int32_t read_member_32(ulong, char *);
static int fls(int);
static ulong get_subsys_parent(ulong, int);
static uint64_t print_u64(char *, uint64_t);
static void format_path_str(const char *, char *);

static struct command_table_entry command_table[] = {
        {"cgget", cmd_cgget, help_cgget, 0},
        {NULL}
};

char *help_cgget[] = {
	"cgget",		/* command name */
	"display parameters of cgroup.",
	"[-a] [-r <name>] [-g <controller>] <path> ...\n"
	"  or\n"
	"  cgget [-a] [-r <name>] -g <controller>:<path> ...",
	"Displays the parameter(s) of input cgroup(s).\n"
	"If no controller is specified, the values of "
	"all possible variables are printed.\n"
	"Either command line style is OK, but these can not be mixed.\n",
	"-a, --all",
	"print the variables for all controllers which consist in the given path.\n",
	"-r <name>",
	"defines parameter to display.",
	"This option can be used multiple times.\n",
	"-g <controller>",
	"defines controllers whose values should be displayed.",
	"This option can be used multiple times.\n",
	"-g <controller>:<path>",
	"defines control groups whose values should be displayed.",
	"This option can be used multiple times.\n",
	"-h, --help",
	"display this message.\n",
	"EXAMPLES",
	"1. display the controller 'cpu' in path '/'",
	" crash> cgget -g cpu:/",
	" /:",
	" cpu.rt_period_us: 1000000",
	" cpu.rt_runtime_us: 950000",
	" cpu.stat: nr_periods 0",
	" \tnr_throttled 0",
	" \tthrottled_time 0",
	" cpu.cfs_period_us: 0",
	" cpu.cfs_quota_us: 0",
	" cpu.shares: 1024",
	" or",
	" crash> cgget -g cpu /",
	" /:",
	" cpu.rt_period_us: 1000000",
	" cpu.rt_runtime_us: 950000",
	" cpu.stat: nr_periods 0",
	" \tnr_throttled 0",
	" \tthrottled_time 0",
	" cpu.cfs_period_us: 0",
	" cpu.cfs_quota_us: 0",
	" cpu.shares: 1024",
	"2. display the parameter 'cpuset.mems' in path '/libvirt'",
	" crash> cgget -r cpuset.mems /libvirt",
	" /libvirt:",
	" cpuset.mems: 0",
	"3. display the controller 'cpu' and paramter 'cpuset.mems' at same time",
	" crash> cgget -r cpuset.mems -g cpu /",
	" /:",
	" cpuset.mems: 0",
	" /:",
	" cpu.rt_period_us: 1000000",
	" cpu.rt_runtime_us: 950000",
	" cpu.stat: nr_periods 0",
	" \tnr_throttled 0",
	" \tthrottled_time 0",
	" cpu.cfs_period_us: 0",
	" cpu.cfs_quota_us: 0",
	" cpu.shares: 1024",
	NULL
};

int
_init(void)
{
	cgroup_subsys_table_init();
	cgget_offset_table_init();
	register_extension(command_table);
	return 1;
}

/*
 *  The _fini() function is called if the shared object is unloaded. 
 *  If desired, perform any cleanups here. 
 */
int 
_fini(void)
{ 
	return 1;
}

static inline int
next_possible_cpu(int cpu)
{
	ulong p, mask_addr, mask[BITS_TO_LONGS(kt->cpus)];

	if (symbol_exists("cpu_possible_mask")) {
		p = symbol_value("cpu_possible_mask");
		mask_addr = (ulong)read_member_64(p, "cpu_possible_mask");
		readmem(mask_addr, KVADDR, mask,
			BITS_TO_LONGS(kt->cpus) * sizeof(ulong),
			"cpu_possible_mask", FAULT_ON_ERROR);
	} else {
		readmem(symbol_value("cpu_possible_map"), KVADDR, mask,
			BITS_TO_LONGS(kt->cpus) * sizeof(ulong),
			"cpu_possible_mask", FAULT_ON_ERROR);
	}

	do {
		cpu++;
		if (NUM_IN_BITMAP(mask, cpu))
			return cpu;
	} while(cpu < kt->cpus);

	return kt->cpus;
}

static inline uint64_t
jiffies_64_to_clock_t(uint64_t x)
{
	/*
	 * This is only the ideal case. It's more
	 * complacated in reality.
	 */
#if HZ < USER_HZ
	x = x * USER_HZ / HZ;
#elif HZ > USER_HZ
	x = x / (HZ / USER_HZ);
#endif
	return x;
}

/*
 * The return value 0 indicates little endian,
 * and value 1 indicates big endian.
 */
static inline int
check_endian()
{
	int i = 1;
	char *p = (char *)&i;
	if (*p == 1)
		return 0;
	else
		return 1;
}

static inline uint64_t
ktime_to_ns(ulong ktime_addr)
{
	uint64_t ret;
	uint32_t sec, nsec;

	if (MEMBER_EXISTS("ktime_t", "tv64")) {
		/* if member tv64 exists in ktime_t */
		readmem(ktime_addr, KVADDR, &ret, sizeof(ulong),
			"ktime", FAULT_ON_ERROR);
	} else {
		if (check_endian()) {
			readmem(ktime_addr, KVADDR, &sec, sizeof(ulong),
				"ktime sec", FAULT_ON_ERROR);
			readmem(ktime_addr + sizeof(uint32_t), KVADDR, &nsec,
				sizeof(ulong), "ktime nsec", FAULT_ON_ERROR);
		} else {
			readmem(ktime_addr, KVADDR, &nsec, sizeof(ulong),
				"ktime nsec", FAULT_ON_ERROR);
			readmem(ktime_addr + sizeof(uint32_t), KVADDR, &sec,
				sizeof(ulong), "ktime sec", FAULT_ON_ERROR);
		}
		ret = NSEC_PER_SEC * sec + nsec;
	}

	return ret;
}

static inline int
bitstr_edit(char *buf, int rbot, int rtop, int len)
{
	if (len == 0) {
		if (rtop == rbot)
			sprintf(buf, "%s%d", buf, rtop);
		else if (rtop > rbot + 1)
			sprintf(buf, "%s%d-%d", buf, rbot, rtop);
		else
			sprintf(buf, "%s%d,%d", buf, rbot, rtop);
	} else {
		if (rtop == rbot)
			sprintf(buf, "%s,%d", buf, rtop);
		else if (rtop > rbot + 1)
			sprintf(buf, "%s,%d-%d", buf, rbot, rtop);
		else
			sprintf(buf, "%s,%d,%d", buf, rbot, rtop);
	}

	return strlen(buf);
}

static inline void
set_majmin(char *str, unsigned m)
{
	if (m == ~0)
		strcpy(str, "*");
	else
		sprintf(str, "%u", m);
}

static inline void
set_access(char *acc, short access)
{
	int idx = 0;

	memset(acc, 0, ACCLEN);
	if (access & ACC_READ)
		acc[idx++] = 'r';
	if (access & ACC_WRITE)
		acc[idx++] = 'w';
	if (access & ACC_MKNOD)
		acc[idx++] = 'm';
}

static inline char
type_to_char(short type)
{
	if (type == DEV_ALL)
		return 'a';
	if (type == DEV_CHAR)
		return 'c';
	if (type == DEV_BLOCK)
		return 'b';
	return 'X';
}

static char *
hugepage_fmt(char *buf, uint64_t size)
{
	if (size >= (1UL << 30))
		sprintf(buf, "%luGB", size >> 30);
	else if (size >= (1UL << 20))
		sprintf(buf, "%luMB", size >> 20);
	else
		sprintf(buf, "%luKB", size >> 10);
	return buf;
}

static inline int
is_root_mem_cgroup(ulong mem_addr)
{
	ulong root_mem_addr;

	if (symbol_exists("root_mem_cgroup"))
		readmem(symbol_value("root_mem_cgroup"), KVADDR, &root_mem_addr,
			sizeof(ulong), "root_mem_cgroup", FAULT_ON_ERROR);
	else
		return 1;

	if (mem_addr == root_mem_addr)
		return 1;
	return 0;
}

static inline char *
get_dentry_path(ulong dentry_addr, char *path, int len)
{
	char buf[FILENAME_MAX] = {0};
	int qstr_len;
	ulong name_addr;

	memset(path, 0, len);

	if (!readmem(dentry_addr + offset_table.dentry_d_name + offset_table.qstr_len,
		     KVADDR, &qstr_len, sizeof(unsigned int),
		     "qstr_len", FAULT_ON_ERROR))
		return NULL;
	if (!readmem(dentry_addr + offset_table.dentry_d_name + offset_table.qstr_name,
		     KVADDR, &name_addr, sizeof(char *), "name_addr", FAULT_ON_ERROR))
		return NULL;
	if (!readmem(name_addr, KVADDR, buf, qstr_len, "qstr_name", FAULT_ON_ERROR))
		return NULL;
	strncpy(path, buf, qstr_len);
	return path;
}

static int
read_whitelist(struct cgroup_spec *group_list, ulong whitelist_addr, int behavior)
{
	uint32_t major, minor;
	short type, access;
	char maj[MAJMINLEN], min[MAJMINLEN], acc[ACCLEN];

	if (!whitelist_addr)
		return -1;
	if (behavior == 0) {
		set_majmin(maj, ~0);
		set_majmin(min, ~0);
		set_access(acc, ACC_MASK);
		fprintf(fp, "%s.list: %c %s:%s %s\n", group_list->subsys_str,
			type_to_char(DEV_ALL), maj, min, acc);
	} else {
		if (!readmem(whitelist_addr + devices_offset_table.item_major,
			KVADDR, &major, sizeof(uint32_t), "item_major",
			FAULT_ON_ERROR))
			return -1;
		set_majmin(maj, major);

		if (!readmem(whitelist_addr + devices_offset_table.item_minor,
			KVADDR, &minor, sizeof(uint32_t), "item_minor",
			FAULT_ON_ERROR))
			return -1;
		set_majmin(min, minor);

		if (!readmem(whitelist_addr + devices_offset_table.item_access,
			KVADDR, &access, sizeof(short), "item_access",
			FAULT_ON_ERROR))
			return -1;
		set_access(acc, access);

		if (!readmem(whitelist_addr + devices_offset_table.item_type,
			KVADDR, &type, sizeof(short), "item_type",
			FAULT_ON_ERROR))
			return -1;
		fprintf(fp, "%s.list: %c %s:%s %s\n", group_list->subsys_str,
			type_to_char(type), maj, min, acc);
	}

	return 0;
}

/*
 * Read the value of member. Only size_t of member matters.
 * Type should be maintained by the caller.
 */
static int64_t
read_member_64(ulong ptr, char *str)
{
	int64_t val = 0;

	readmem(ptr, KVADDR, &val, sizeof(int64_t),
		str, FAULT_ON_ERROR);
	return val;
}

/*
 * Read the value of member. Only size_t of member matters.
 * Type should be maintained by the caller.
 */
static int32_t
read_member_32(ulong ptr, char *str)
{
	int32_t val = 0;

	readmem(ptr, KVADDR, &val, sizeof(int32_t),
		str, FAULT_ON_ERROR);
	return val;
}

/*
 * Read the value of member. Only size_t of member matters.
 * Type should be maintained by the caller.
 */
static long
read_member_long(ulong ptr)
{
	long val = 0;

	readmem(ptr, KVADDR, &val, sizeof(long),
		"member value", FAULT_ON_ERROR);
	return val;
}

static uint64_t
read_res_counter(ulong counter_addr, long off, char *param)
{
	uint64_t val = 0;

	if (counter_addr == -1 || off == -1)
		return 0;

	val = (uint64_t)read_member_64(counter_addr + off, "res_counter");
	if (param)
		fprintf(fp, "%s: %lu\n", param, val);
	return val;
}

static void
cpuacct_print_stat(ulong subsys_addr)
{
	int i;
	ulong cpuacct_stat_addr, stat_ptr, tmp;
	int64_t userval = 0, systemval = 0;
	uint64_t result;
	enum cpuacct_stat_index {
		CPUACCT_STAT_USER,
		CPUACCT_STAT_SYSTEM,
		CPUACCT_STAT_NSTATS,
	};
	enum cpu_usage_stat {
		CPUTIME_USER,
		CPUTIME_NICE,
		CPUTIME_SYSTEM,
		CPUTIME_SOFTIRQ,
		CPUTIME_IRQ,
		CPUTIME_IDLE,
		CPUTIME_IOWAIT,
		CPUTIME_STEAL,
		CPUTIME_GUEST,
		CPUTIME_GUEST_NICE,
		NR_STATS,
	};
	static const char *cpuacct_stat_desc[] = {
		"user",
		"system",
	};

	/* get params of cpuacct.stat */
	cpuacct_stat_addr = subsys_addr +
			    cpuacct_offset_table.cpuacct_cpustat;
	if (STRUCT_EXISTS("kernel_cpustat")) {
		/* cpustat is a percpu variable */
		int64_t stat[NR_STATS];
		readmem(cpuacct_stat_addr, KVADDR, &tmp, sizeof(ulong),
			"cpuacct cpustat", FAULT_ON_ERROR);
		for_each_possible_cpu(i) {
			if (kt->flags & PER_CPU_OFF)
				stat_ptr = tmp + kt->__per_cpu_offset[i];
			readmem(stat_ptr, KVADDR, stat,
				STRUCT_SIZE("kernel_cpustat"),
				"kernel_cpustat", FAULT_ON_ERROR);
			userval += stat[CPUTIME_USER];
			userval += stat[CPUTIME_NICE];
			systemval += stat[CPUTIME_SYSTEM];
			systemval += stat[CPUTIME_IRQ];
			systemval += stat[CPUTIME_SOFTIRQ];
		}
	} else {
		readmem(cpuacct_stat_addr +
			MEMBER_OFFSET("percpu_counter", "count"), KVADDR,
			&userval, sizeof(int64_t), "cpuacct_cpustat count",
			FAULT_ON_ERROR);
		readmem(cpuacct_stat_addr + STRUCT_SIZE("percpu_counter") +
			MEMBER_OFFSET("percpu_counter", "count"), KVADDR,
			&systemval, sizeof(int64_t), "cpuacct_cpustat count",
			FAULT_ON_ERROR);
	}

	result = jiffies_64_to_clock_t((uint64_t)userval);
	fprintf(fp, "%s %lu\n", cpuacct_stat_desc[CPUACCT_STAT_USER],
		result);
	result = jiffies_64_to_clock_t((uint64_t)systemval);
	fprintf(fp, "\t%s %lu\n", cpuacct_stat_desc[CPUACCT_STAT_SYSTEM],
		result);
}

static uint64_t
cpuacct_print_usage_percpu(ulong subsys_addr)
{
	int i;
	uint64_t val, total = 0;
	ulong cpuusage_ptr, tmp;

	/* get params of cpuacct.usage_percpu */
	readmem(subsys_addr + cpuacct_offset_table.cpuacct_cpuusage,
		KVADDR, &tmp, sizeof(uint64_t *),
		"cpuacct_cpuusage", FAULT_ON_ERROR);

	for_each_possible_cpu(i) {
		if (!STRUCT_EXISTS("percpu_data")) {
			if (kt->flags & PER_CPU_OFF)
				cpuusage_ptr = tmp + kt->__per_cpu_offset[i];
		} else {
			cpuusage_ptr = ~tmp;
			readmem(cpuusage_ptr + i * sizeof(ulong),
				KVADDR, &cpuusage_ptr, sizeof(uint64_t),
				"percpu_cpuusage", FAULT_ON_ERROR);
		}
		readmem(cpuusage_ptr, KVADDR, &val, sizeof(uint64_t),
			"percpu_cpuusage", FAULT_ON_ERROR);
		total += val;
		fprintf(fp, "%lu ", val);
	}
	fprintf(fp, "\n");

	return total;
}

static void
cpu_print_stat(ulong cfs_bandwidth_ptr)
{
	int val;
	uint64_t time;
	static const char *stat_str[] = {
		"nr_periods",
		"nr_throttled",
		"throttled_time",
	};

	val = read_member_32(cfs_bandwidth_ptr +
			     MEMBER_OFFSET("cfs_bandwidth", "nr_periods"),
			     "cfs_bandwidth nr_periods");
	fprintf(fp, "\t%s: %d\n", stat_str[0], val);
	val = read_member_32(cfs_bandwidth_ptr +
			     MEMBER_OFFSET("cfs_bandwidth", "nr_throttled"),
			     "cfs_bandwidth nr_throttled");
	fprintf(fp, "\t%s: %d\n", stat_str[1], val);
	time = (uint64_t)read_member_64(cfs_bandwidth_ptr +
			 MEMBER_OFFSET("cfs_bandwidth", "throttled_time"),
			 "cfs_bandwidth throttled_time");
	fprintf(fp, "\t%s: %lu\n", stat_str[2], time);
}

static void
cpu_print_bandwidth(ulong bandwidth_ptr, long off, int ktime, char *param)
{
	int64_t val;

	if (bandwidth_ptr == -1 || off == -1)
		return;

	if (ktime)
		val = ktime_to_ns(bandwidth_ptr + off);
	else
		val = read_member_64(bandwidth_ptr + off, "ktime");
	if (val == ~0ULL)
		val = -1;
	else
		val = val / NSEC_PER_USEC;

	fprintf(fp, "%s: %ld\n", param, val);
}

static ulong
get_mz_lru_val(ulong mem_addr, int nid, int zid, int idx)
{
	ulong mz_addr, val_addr, ret = 0;

	readmem(mem_addr + memory_offset_table.memory_info +
		nid * sizeof(void *), KVADDR, &mz_addr, sizeof(ulong),
		"lruinfo_nodeinfo", FAULT_ON_ERROR);

	val_addr = mz_addr + zid * STRUCT_SIZE("mem_cgroup_per_zone") +
		   memory_offset_table.perzone_count;

	readmem(val_addr + idx * sizeof(ulong), KVADDR, &ret,
		sizeof(ulong), "per_zone_value", FAULT_ON_ERROR);

	return ret;

}

static uint64_t
mem_cgroup_read_local_zonestat(ulong mem_addr, int idx)
{
	uint64_t tmp, total = 0;
	int nid, zid;

	for (nid = 0; nid < vt->numnodes; nid++) {
		for (zid = 0; zid < vt->nr_zones; zid++) {
			tmp = get_mz_lru_val(mem_addr, nid, zid, idx);
			total += tmp;
		}
	}

	return total;
}

/*
 * mem_cgroup_stat_cpu differs from 2.6.25--3.6
 * it's very important to identify every element here.
 * @elem_nr: how many sizeof(int64_t) in struct mem_cgroup_stat_cpu.
 */
static int64_t
get_value_acc_ver(int64_t *stat, int idx, int cpu, int elem_nr)
{
	stat = (int64_t *)((ulong)stat +
			   cpu * STRUCT_SIZE("mem_cgroup_stat_cpu"));

	switch (idx)
	{
	case MCS_CACHE:
	case MCS_RSS:
		/* the first 2 stats are same for every kernel version */
		return stat[idx];
	case MCS_FILE_MAPPED:
		if (elem_nr > 4)
			/* kernel version 2.6.31--3.6 */
			return stat[idx];
		return -1;
	case MCS_SWAP:
		switch (elem_nr)
		{
		/* kernel version 2.6.34 */
		case 7:
			return stat[5];
		/* kernel version 2.6.32--2.6.33, 2.6.35--2.6.38 */
		case 8:
			if (MEMBER_EXISTS("res_counter", "soft_limit"))
				return stat[6];
			else if (MEMBER_EXISTS("mem_cgroup_stat_cpu",
						"nocpu_base"))
				return stat[5];
			else
				return -1;
		/* kernel version 2.6.39--3.6 */
		case 11:
		case 12:
		case 13:
		case 14:
			return stat[3];
		default:
			return -1;
		}
	case MCS_PGPGIN:
	case MCS_PGPGOUT:
		switch (elem_nr)
		{
		/* kernel version 2.6.26--2.6.30 */
		case 4:
			return stat[idx - 2];
		/* kernel version 2.6.31--2.6.38 */
		case 7:
		case 8:
			return stat[idx - 1];
		/* kernel version 2.6.39, 3.0--3.3 */
		case 11:
		case 14:
			return stat[idx + 2];
		/* kernel version 3.5 */
		case 12:
			return stat[idx];
		/* kernel version 3.4 */
		case 13:
			return stat[idx + 1];
		default:
			return -1;
		}
	case MCS_PGFAULT:
	case MCS_PGMAJFAULT:
		switch (elem_nr)
		{
		/* kernel version 3.5 */
		case 12:
			return stat[idx];
		/* kernel version 3.4 */
		case 13:
			return stat[idx + 2];
		/* kernel version 3.0--3.3 */
		case 14:
			return stat[idx + 3];
		default:
			return -1;
		}
	default:
		return 0;
	}
}

static int64_t
mem_cgroup_read_stat(void *stat, int idx)
{
	int cpu, elem_nr;
	int64_t ret = 0;

	elem_nr = STRUCT_SIZE("mem_cgroup_stat_cpu") / sizeof(int64_t);
	for_each_possible_cpu(cpu)
		ret += get_value_acc_ver((int64_t *)stat, idx, cpu, elem_nr);

	return ret;

}

static void
get_mem_percpu_stats(ulong stat_addr, void *src_stat)
{
	ulong statptr, tmp;
	int cpu;

	readmem(stat_addr, KVADDR, &statptr, sizeof(ulong),
		"mem_cgroup_stat", FAULT_ON_ERROR);
	tmp = statptr;
	for_each_possible_cpu(cpu) {
		if (kt->flags & PER_CPU_OFF)
			statptr = tmp + kt->__per_cpu_offset[cpu];
		readmem(statptr, KVADDR, src_stat +
			cpu * STRUCT_SIZE("mem_cgroup_stat_cpu"),
			STRUCT_SIZE("mem_cgroup_stat_cpu"),
			"mem_cgroup_stat", FAULT_ON_ERROR);
	}
}

static int
get_mem_local_stats(ulong mem_addr, int64_t *stats, int do_swap_account)
{
	int i;
	int64_t val = 0;
	void *src_stats;
	ulong stat_addr;

	/* read memory stats */
	stat_addr = mem_addr + memory_offset_table.memory_stat;
	src_stats = calloc(kt->cpus, STRUCT_SIZE("mem_cgroup_stat_cpu"));
	if (!src_stats)
		return -1;
	if (MEMBER_EXISTS("mem_cgroup", "thresholds"))
		/* stat of mem_cgroup is a percpu variable */
		get_mem_percpu_stats(stat_addr, src_stats);
	else
		readmem(stat_addr, KVADDR, src_stats,
			kt->cpus * STRUCT_SIZE("mem_cgroup_stat_cpu"),
			"mem_cgroup_stat", FAULT_ON_ERROR);

	/* cpu stat */
	for (i = MCS_CACHE; i <= MCS_PGMAJFAULT; i++) {
		if (!do_swap_account && i == MCS_SWAP)
			continue;
		val = mem_cgroup_read_stat(src_stats, i);
		if (val < 0) {
			stats[i] = -1;
			continue;
		}
		if (i > MCS_SWAP)
			stats[i] = val;
		else
			stats[i] = val * PAGE_SIZE;
	}

	/* per zone stat */
	for (i = LRU_INACTIVE_ANON; i < NR_LRU_LISTS; i++) {
		if (MEMBER_EXISTS("mem_cgroup_per_zone", "active_list") &&
		    i > LRU_ACTIVE_ANON)
			break;
		val = mem_cgroup_read_local_zonestat(mem_addr, i);
		stats[i + MCS_INACTIVE_ANON] = val * PAGE_SIZE;
	}

	free(src_stats);
	return 0;
}

static int
css_member(ulong css_addr, char *member, int depth)
{
	ulong id_addr;
	int val = 0;

	/* get member of css_id. the member will be "id", "depth" or "stack" */
	readmem(css_addr + MEMBER_OFFSET("cgroup_subsys_state", "id"), KVADDR,
		&id_addr, sizeof(ulong), "cgroup_subsys_state css_id",
		FAULT_ON_ERROR);
	if (0 == strcmp(member, "stack"))
		/* member "stack" is depend on "depth" */
		readmem(id_addr + MEMBER_OFFSET("css_id", member) +
			depth * sizeof(short), KVADDR, &val,
			sizeof(short), "member of css_id", FAULT_ON_ERROR);
	else
		readmem(id_addr + MEMBER_OFFSET("css_id", member), KVADDR, &val,
			sizeof(short), "member of css_id", FAULT_ON_ERROR);

	return val;
}

/*
 * find first set bit in word.
 * @x: the word to search
 *
 * fls(value) returns 0 if value is 0 or the position of the last
 * set bit if value is nonzero. The last (most significant) bit is
 * at position 32.
 */
static int
fls(int x)
{
	ulong i;

	if (x == 0)
		return 0;

	for (i = 31; i >= 0; i--)
		if ((x & (1ULL << i)))
			break;

	return i + 1;
}

static ulong
idr_get_next(ulong idp, int *nextid)
{
	int id = *nextid + 1;
	int n, max, idr_bits, idr_mask, layer;
	ulong p = 0, pa[7];
	ulong *paa = &pa[0];

	if (BITS_PER_LONG == 32)
		idr_bits = 5;
	else
		idr_bits = 6;
	idr_mask = (1 << idr_bits) -1;

	/* find first ent */
	readmem(idp, KVADDR, &p, sizeof(ulong), "idr top", FAULT_ON_ERROR);
	if (!p)
		return 0;
	readmem(p + MEMBER_OFFSET("idr_layer", "layer"), KVADDR, &layer,
		sizeof(int), "idr_layer layer", FAULT_ON_ERROR);
	n = (layer + 1) * idr_bits;
	max = 1 << n;

	while (id < max) {
		while (n > 0 && p) {
			n -= idr_bits;
			*paa++ = p;
			readmem(p + MEMBER_OFFSET("idr_layer", "ary") +
				sizeof(ulong) * ((id >> n) & idr_mask),
				KVADDR, &p, sizeof(ulong), "idr_layer ary",
				FAULT_ON_ERROR);
		}

		if (p) {
			*nextid = id;
			return p;
		}

		id += 1 << n;
		while (n < fls(id)) {
			n += idr_bits;
			p = *--paa;
		}
	}
	return 0;
}

static ulong
mem_cgroup_iter(ulong root, ulong prev)
{
	ulong idp, tmp = 0;
	int depth, stack, tmpid, id = 0,
	    rootid, rootdepth;

	if (!STRUCT_EXISTS("css_id"))
		return root;
	if (prev)
		id = css_member(prev, "id", 0);

	rootid = css_member(root, "id", 0);
	rootdepth = css_member(root, "depth", 0);
	tmpid = id;
	idp = symbol_value("mem_cgroup_subsys") + MEMBER_OFFSET("cgroup_subsys", "idr");
	while (1) {
		/* scan next css_id entry from bitmap */
		tmp = idr_get_next(idp, &tmpid);
		if (!tmp)
			break;
		/* address of css is at the beginning of struct css_id*/
		readmem(tmp, KVADDR, &tmp, sizeof(ulong),
			"css_id css", FAULT_ON_ERROR);
		depth = css_member(tmp, "depth", 0);
		stack = css_member(tmp, "stack", depth);
		if (depth >= rootdepth && stack == rootid)
			break;
		tmpid++;
	}

	return tmp;
}

static int
get_mem_total_stats(ulong mem_addr, int64_t *stats, int do_swap_account)
{
	int i;
	ulong root;
	int64_t val[NR_MCS_STAT];

	if (!STRUCT_EXISTS("css_id"))
		return get_mem_local_stats(mem_addr, stats, do_swap_account);

	/*
	 * when hierarchy is enabled, walking through the tree
	 * and add every single val to get the total stats.
	 */
	root = mem_addr;
	while(mem_addr) {
		get_mem_local_stats(mem_addr, val, do_swap_account);
		for (i = MCS_CACHE; i < NR_MCS_STAT; i++) {
			if (val[i] == -1)
				stats[i] = -1;
			else
				stats[i] += val[i];
		}
		mem_addr = mem_cgroup_iter(root, mem_addr);
	}

	return 0;
}

static ulong
get_subsys_parent(ulong subsys_addr, int subsys_id)
{
	ulong cgroup_addr, parent = 0, addr = 0;

	readmem(subsys_addr, KVADDR, &cgroup_addr, sizeof(ulong),
		"subsys_css_cgroup", FAULT_ON_ERROR);
	readmem(cgroup_addr + cgroup_offset_table.cgroup_parent, KVADDR, &parent,
		sizeof(ulong), "cgroup_parent", FAULT_ON_ERROR);
	if (parent)
		readmem(parent + cgroup_offset_table.cgroup_subsys + subsys_id *
			sizeof(ulong), KVADDR, &addr, sizeof(ulong),
			"cgroup_subsys", FAULT_ON_ERROR);

	return addr;
}

static void
get_mem_hierarchical_limit(ulong memcg_addr, uint64_t *mem_limit,
			   uint64_t *memsw_limit, int subsys_id)
{
	ulong memcg_res_addr, memcg_memsw_addr, parent = 0;
	uint64_t limit = ~0ULL, limitsw = ~0ULL, tmp = 0;

	parent = memcg_addr;
	/* the result should be the smallest. */
	do {
		memcg_res_addr = parent + memory_offset_table.memory_res;
		memcg_memsw_addr = parent + memory_offset_table.memory_memsw;
		tmp = read_res_counter(memcg_res_addr,
				       memory_offset_table.counter_limit,
				       NULL);
		limit = (limit < tmp ? limit : tmp);
		tmp = read_res_counter(memcg_memsw_addr,
				       memory_offset_table.counter_limit,
				       NULL);
		limitsw = (limitsw < tmp ? limitsw : tmp);
	} while (0 != (parent = get_subsys_parent(parent, subsys_id)));

	*mem_limit = limit;
	*memsw_limit = limitsw;
}

static uint64_t
get_mem_usage(ulong memcg_addr, int swap)
{
	uint64_t val;
	int64_t stats[NR_MCS_STAT];
	ulong iter;

	if (!is_root_mem_cgroup(memcg_addr)) {
		if (!swap)
			val = read_res_counter(memcg_addr +
					memory_offset_table.memory_res,
					memory_offset_table.counter_usage,
					NULL);
		else
			val = read_res_counter(memcg_addr +
					memory_offset_table.memory_memsw,
					memory_offset_table.counter_usage,
					NULL);
		return val;
	}

	val = 0;
	/* Go through the mem_cgroup tree */
	for (iter = mem_cgroup_iter(memcg_addr, 0);
	     iter != 0;
	     iter = mem_cgroup_iter(memcg_addr, iter)) {
		/* Get all the stats */
		memset(stats, 0, sizeof(stats));
		get_mem_local_stats(iter, stats, swap);
		/*
		 * Swap? Add all the swap ones besides
		 * the sum of cache and rss
		 */
		val += stats[MCS_CACHE] + stats[MCS_RSS];
		if (swap)
			val += stats[MCS_SWAP];
		if (!STRUCT_EXISTS("css_id"))
			break;
	}

	return val;
}

static void
mem_print_oom_ctrl(ulong subsys_addr)
{
	int val = 0;
	ulong ptr;

	ptr = subsys_addr + memory_offset_table.memory_oom_kill_disable;
	val = (int)read_member_32(ptr, "oom_kill_disable");
	fprintf(fp, "\toom_kill_disable %d\n", val);
	ptr = subsys_addr + memory_offset_table.memory_under_oom;
	val = (int)read_member_32(ptr, "under_oom");
	fprintf(fp, "\tunder_oom %d\n", (val > 0 ? 1 : 0));
}

static void
mem_print_swap(ulong subsys_addr, char *buf)
{
	int val = 0;

	if (is_root_mem_cgroup(subsys_addr)) {
		if (symbol_exists("vm_swappiness") == -1)
			return;
		readmem(symbol_value("vm_swappiness"), KVADDR, &val,
			sizeof(int), "vm_swappiness", FAULT_ON_ERROR);
	} else {
		if (memory_offset_table.memory_swappiness == -1)
			return;
		readmem(subsys_addr + memory_offset_table.memory_swappiness,
			KVADDR, &val, sizeof(int), "mem_cgroup swappiness",
			FAULT_ON_ERROR);
	}
	fprintf(fp, "%s: %d\n", buf, val);
}

static void
mem_print_numa_stat(ulong mem_addr, uint64_t *lstats)
{
	uint64_t anon_node, file_node, unevictable_node, val,
		 anon_nr = 0, file_nr = 0, unevictable_nr = 0;
	int nid, zid;


	for (nid = 0; nid < vt->numnodes; nid++) {
		file_node = 0, anon_node = 0, unevictable_node = 0;
		for (zid = 0; zid < vt->nr_zones; zid++) {
			/* values per node */
			file_node += get_mz_lru_val(mem_addr, nid, zid,
						    LRU_INACTIVE_FILE);
			file_node += get_mz_lru_val(mem_addr, nid, zid,
						    LRU_ACTIVE_FILE);
			anon_node += get_mz_lru_val(mem_addr, nid, zid,
						    LRU_INACTIVE_ANON);
			anon_node += get_mz_lru_val(mem_addr, nid, zid,
						    LRU_ACTIVE_ANON);
			unevictable_node += get_mz_lru_val(mem_addr, nid, zid,
							   LRU_UNEVICTABLE);
		}
		val = file_node + anon_node + unevictable_node;
		/* values all nodes */
		file_nr += file_node;
		anon_nr += anon_node;
		unevictable_nr += unevictable_node;
		fprintf(fp, "\tfile_N%d=%lu\n", nid, file_node);
		fprintf(fp, "\tanon_N%d=%lu\n", nid, anon_node);
		fprintf(fp, "\tunevictable_N%d=%lu\n", nid, unevictable_node);
		fprintf(fp, "\ttotal_N%d=%lu\n", nid, val);
	}
	fprintf(fp, "\tfile=%lu\n", file_nr);
	fprintf(fp, "\tanon=%lu\n", anon_nr);
	fprintf(fp, "\tunevictable=%lu\n", unevictable_nr);
	val = (lstats[MCS_INACTIVE_ANON] + lstats[MCS_ACTIVE_ANON] +
		lstats[MCS_INACTIVE_FILE] + lstats[MCS_ACTIVE_FILE] +
		lstats[MCS_UNEVICTABLE]) / PAGE_SIZE;
	fprintf(fp, "\ttotal=%lu\n", val);
}

static uint64_t
blkio_get_stat_cpu(ulong blkg_addr, enum stat_type type,
		   uint32_t dev, char *buf)
{
	uint64_t total, val, tval, stats_arr_cpu[BLKIO_STAT_CPU_NR][BLKIO_STAT_TOTAL];
	char tmp[FILENAME_MAX] = {0};
	enum stat_sub_type sub_type;
	ulong stats_cpu_addr, stats_cpu_ptr;
	int i;
	static const char *sub_type_str[] = {
		"Read",
		"Write",
		"Sync",
		"Async",
		"Total",
	};

	total = 0, val = 0;
	readmem(blkg_addr + blkio_offset_table.blkg_stats_cpu,
		KVADDR, &stats_cpu_addr, sizeof(ulong),
		"blkio_group stats_cpu", FAULT_ON_ERROR);

	if (type == BLKIO_STAT_SECTORS) {
		for_each_possible_cpu(i) {
			if (kt->flags & PER_CPU_OFF)
				stats_cpu_ptr = stats_cpu_addr +
						kt->__per_cpu_offset[i];
			readmem(stats_cpu_ptr, KVADDR, &tval, sizeof(uint64_t),
				"blkio_group_stats_cpu_sectors",
				FAULT_ON_ERROR);
			val += tval;
		}
		fprintf(fp, "\t%d:%d %lu\n", MAJOR(dev), MINOR(dev), val);
		return val;
	}

	for (sub_type = BLKIO_STAT_READ; sub_type <= BLKIO_STAT_TOTAL; sub_type++) {
		tmp[0] = '\0', val = 0;
		sprintf(tmp, "%d:%d", MAJOR(dev), MINOR(dev));
		for_each_possible_cpu(i) {
			if (sub_type == BLKIO_STAT_TOTAL)
				break;
			if (kt->flags & PER_CPU_OFF)
				stats_cpu_ptr = stats_cpu_addr +
						kt->__per_cpu_offset[i];
			readmem(stats_cpu_ptr + sizeof(uint64_t), KVADDR,
				stats_arr_cpu, sizeof(uint64_t) * BLKIO_STAT_CPU_NR *
				BLKIO_STAT_TOTAL, "blkio_group_stats_cpu_stats_arr",
				FAULT_ON_ERROR);
			tval = stats_arr_cpu[type][sub_type];
			val += tval;
		}
		switch (sub_type)
		{
		case BLKIO_STAT_READ:
		case BLKIO_STAT_WRITE:
			total += val;
			fprintf(fp, "\t%s %s %lu\n", tmp,
				sub_type_str[sub_type], val);
			break;
		case BLKIO_STAT_SYNC:
		case BLKIO_STAT_ASYNC:
			fprintf(fp, "\t%s %s %lu\n", tmp,
				sub_type_str[sub_type], val);
			break;
		case BLKIO_STAT_TOTAL:
			fprintf(fp, "\t%s %s %lu\n", tmp,
				sub_type_str[sub_type], total);
			break;
		}
	}

	return total;
}

static uint64_t
blkio_get_stat(ulong blkg_addr, enum stat_type type, uint32_t dev, char *buf)
{
	uint64_t time, sectors, total,
		 stat_arr[BLKIO_STAT_QUEUED + 1][BLKIO_STAT_TOTAL];
	char tmp[FILENAME_MAX] = {0};
	enum stat_sub_type sub_type;
	static const char *sub_type_str[] = {
		"Read",
		"Write",
		"Sync",
		"Async",
		"Total",
	};

	if (type == BLKIO_STAT_TIME) {
		/* no sub_type */
		readmem(blkg_addr + blkio_offset_table.blkg_stats, KVADDR, &time,
			sizeof(uint64_t), "blkio_group_stat_time",
			FAULT_ON_ERROR);
		fprintf(fp, "\t%d:%d %lu\n", MAJOR(dev), MINOR(dev), time);
		return time;
	} else if (type == BLKIO_STAT_SECTORS) {
		/* no sub_type */
		readmem(blkg_addr + blkio_offset_table.blkg_stats +
			sizeof(uint64_t), KVADDR, &sectors,
			sizeof(uint64_t), "blkio_group_stat sectors",
			FAULT_ON_ERROR);
		fprintf(fp, "\t%d:%d %lu\n", MAJOR(dev), MINOR(dev), sectors);
		return sectors;
	}

	/* get values */
	readmem(blkg_addr + blkio_offset_table.blkg_stats +
		MEMBER_OFFSET("blkio_group_stats", "stat_arr"),
		KVADDR, stat_arr, sizeof(stat_arr),
		"blkio_group_stat_stat_arr", FAULT_ON_ERROR);
	for (sub_type = BLKIO_STAT_READ; sub_type <= BLKIO_STAT_TOTAL; sub_type++) {
		tmp[0] = '\0';
		sprintf(tmp, "%d:%d", MAJOR(dev), MINOR(dev));
		switch (sub_type)
		{
		case BLKIO_STAT_READ:
		case BLKIO_STAT_WRITE:
		case BLKIO_STAT_SYNC:
		case BLKIO_STAT_ASYNC:
			fprintf(fp, "\t%s %s %lu\n", tmp, sub_type_str[sub_type],
				stat_arr[type][sub_type]);
			break;
		case BLKIO_STAT_TOTAL:
			total = stat_arr[type][BLKIO_STAT_READ] +
				stat_arr[type][BLKIO_STAT_WRITE];
			fprintf(fp, "\t%s %s %lu\n", tmp, sub_type_str[sub_type],
				total);
			break;
		}
	}

	return total;
}

/*
 * print out the string with value.
 *@dev, the major and minor of a device
 *@val, value to be print out
 */
static uint64_t
print_u64(char *dev, uint64_t val)
{
	fprintf(fp, "\t%s %lu\n", dev, val);

	return val;
}

/*
 * print out the string with value.
 *@dev, the major and minor of a device
 *@type, 4 sub types(Read, Write, Sync, Async)
 */
static uint64_t
print_u64_rw(char *dev, uint64_t *val)
{
	uint64_t total;
	int i;
	static const char *blkio_rw_strs[] = {
		"Read",
		"Write",
		"Sync",
		"Async",
		"Total",
	};

	for (i = 0; i < BLKIO_STAT_TOTAL; i++)
		fprintf(fp, "\t%s %s %lu\n", dev, blkio_rw_strs[i], val[i]);

	total = val[BLKIO_STAT_READ] + val[BLKIO_STAT_WRITE];
	fprintf(fp, "\t%s %s %lu\n", dev, blkio_rw_strs[i], total);

	return total;
}

static uint64_t
print_thro_u64_rw(char *dev, ulong st_addr, int type)
{
	uint64_t val[4] = {0}, tval[4], total = 0;
	int i, j;
	ulong stptr;

	for_each_possible_cpu(i) {
		if (kt->flags & PER_CPU_OFF)
			stptr = st_addr + kt->__per_cpu_offset[i];
		if (type == BLKIO_THROTL_io_service_bytes)
			readmem(stptr, KVADDR, tval, sizeof(uint64_t) * 4,
				"tg_stat_cpu service_bytes",
				FAULT_ON_ERROR);
		else
			readmem(stptr + STRUCT_SIZE("blkg_rwstat"),
				KVADDR, tval, sizeof(uint64_t) * 4,
				"tg_stat_cpu serviced",
				FAULT_ON_ERROR);
		for (j = 0; j < 4; j++)
			val[j] += tval[j];
	}

	total += print_u64_rw(dev, val);
	return total;
}

static void
dev_name(ulong blkg_addr, char *buf)
{
	char tmp[FILENAME_MAX] = {0};
	ulong q_addr, dev_addr, name_addr;

	readmem(blkg_addr, KVADDR, &q_addr,
		sizeof(ulong), "blkcg_gq q", FAULT_ON_ERROR);
	readmem(q_addr + MEMBER_OFFSET("request_queue", "backing_dev_info") +
		MEMBER_OFFSET("backing_dev_info", "dev"), KVADDR, &dev_addr,
		sizeof(ulong), "dev", FAULT_ON_ERROR);
	/* Use the init name until the kobject becomes available */
	readmem(dev_addr + MEMBER_OFFSET("device", "init_name"), KVADDR,
		&name_addr, sizeof(ulong), "device init_name",
		FAULT_ON_ERROR);
	if (name_addr) {
		readmem(name_addr, KVADDR, tmp, FILENAME_MAX, "init_name",
			FAULT_ON_ERROR);
		strncpy(buf, tmp, strlen(tmp));
		return;
	}
	readmem(dev_addr + MEMBER_OFFSET("device", "kobj"), KVADDR,
		&name_addr, sizeof(ulong), "kobject name ptr", FAULT_ON_ERROR);
	/*
	 * We don't know the lenght of string, so just read enough
	 * and copy to destination
	 */
	readmem(name_addr, KVADDR, tmp, FILENAME_MAX,
		"kobject name", FAULT_ON_ERROR);
	strncpy(buf, tmp, strlen(tmp));
}

static int
test_policy(ulong blkg_addr, int policy)
{
	ulong blkcg_pols, q_addr, pol_addr = 0;

	if (policy == BLKCG_POLICY_PROP)
		pol_addr = symbol_value("blkcg_policy_cfq");
	else
		pol_addr = symbol_value("blkcg_policy_throtl");

	readmem(blkg_addr, KVADDR, &q_addr,
		sizeof(ulong), "blkcg_gq q", FAULT_ON_ERROR);
	/* there're 2 bits for pols, so only one ulong is enough */
	readmem(q_addr + MEMBER_OFFSET("request_queue", "blkcg_pols"),
		KVADDR, &blkcg_pols, sizeof(ulong),
		"request_queue blkcg_pols", FAULT_ON_ERROR);

	return pol_addr && test_bit(policy - 2, blkcg_pols);
}

static uint64_t
print_cfq_group(ulong blkg_addr, int attr_id, long off, size_t data_size)
{
	uint64_t val[4], total = 0;
	ulong pd_addr;
	char buf[FILENAME_MAX] = {0};

	do {
		memset(buf, 0, FILENAME_MAX);
		dev_name(blkg_addr, buf);
		readmem(blkg_addr + blkio_offset_table.blkg_pd +
			(BLKCG_POLICY_PROP - 2) * sizeof(ulong),
			KVADDR, &pd_addr, sizeof(ulong),
			"blkcg_gq pd", FAULT_ON_ERROR);
		/* 
		 * blkg_policy_data is at the beginning of
		 * throtl_grp or cfq_group
		 */
		if (pd_addr && test_policy(blkg_addr, BLKCG_POLICY_PROP)) {
			readmem(pd_addr + off, KVADDR, val, data_size,
				"policy_data member", FAULT_ON_ERROR);
			switch (attr_id)
			{
			case BLKIO_PROP_weight_device:
				if (val[0])
					total += print_u64(buf, val[0]);
				break;
			case BLKIO_PROP_weight:
				break;
			case BLKIO_PROP_time:
			case BLKIO_PROP_sectors:
				total += print_u64(buf, val[0]);
				break;
			case BLKIO_PROP_io_service_bytes:
			case BLKIO_PROP_io_serviced:
			case BLKIO_PROP_io_service_time:
			case BLKIO_PROP_io_wait_time:
			case BLKIO_PROP_io_merged:
			case BLKIO_PROP_io_queued:
				total += print_u64_rw(buf, val);
				break;
			default:
				break;
			}
		}
		blkg_addr = (ulong)list_next(NULL, (void *)blkg_addr,
				      blkio_offset_table.blkg_blkcg_node);
	} while (0 != blkg_addr + blkio_offset_table.blkg_blkcg_node);

	return total;
}

static uint64_t
print_throtl_grp(ulong blkg_addr, int attr_id, long off, size_t data_size)
{
	uint64_t val, total = 0;
	ulong pd_addr;
	char buf[FILENAME_MAX] = {0};

	do {
		memset(buf, 0, FILENAME_MAX);
		dev_name(blkg_addr, buf);
		readmem(blkg_addr + blkio_offset_table.blkg_pd +
			(BLKCG_POLICY_THROTL - 2) * sizeof(ulong),
			KVADDR, &pd_addr, sizeof(ulong),
			"blkcg_gq pd", FAULT_ON_ERROR);
		/* 
		 * blkg_policy_data is at the beginning of
		 * throtl_grp or cfq_group
		 */
		if (pd_addr && test_policy(blkg_addr, BLKCG_POLICY_THROTL)) {
			readmem(pd_addr + off , KVADDR, &val, data_size,
				"policy_data member", FAULT_ON_ERROR);
			switch (attr_id)
			{
			case BLKIO_THROTL_io_service_bytes:
			case BLKIO_THROTL_io_serviced:
				total += print_thro_u64_rw(buf, val, attr_id);
				break;
			case BLKIO_THROTL_read_bps_device:
			case BLKIO_THROTL_write_bps_device:
				if (val != -1)
					total += print_u64(buf, val);
				break;
			case BLKIO_THROTL_read_iops_device:
			case BLKIO_THROTL_write_iops_device:
				if ((uint)val != -1)
					total += print_u64(buf, val);
				break;
			default:
				break;
			}
		}
		blkg_addr = (ulong)list_next(NULL, (void *)blkg_addr,
				      blkio_offset_table.blkg_blkcg_node);
	} while (0 != blkg_addr + blkio_offset_table.blkg_blkcg_node);

	return total;
}

static int
read_policy_group(ulong blkcg_addr, int plid, int attr_id, char *str)
{
	uint64_t val, total = 0;
	ulong blkg_addr, hlist_head;
	long off;
	size_t data_size;
	int show_total = 0;

	readmem(blkcg_addr + blkio_offset_table.blkio_blkg_list, KVADDR,
		&hlist_head, sizeof(ulong), "blkio_cgroup blkg_list",
		FAULT_ON_ERROR);
	if (hlist_head == 0 || hlist_head == ~0UL)
		return blkio_print_param_no_group(blkcg_addr, plid,
						  attr_id, str);
	blkg_addr = hlist_head - blkio_offset_table.blkg_blkcg_node;

	fprintf(fp, "%s.", str);
	switch (plid)
	{
	case BLKCG_POLICY_PROP:
		/* target struct is cfq_group. */
		switch (attr_id)
		{
		case BLKIO_PROP_weight:
			readmem(blkcg_addr + blkio_offset_table.blkio_weight,
				KVADDR, &val, sizeof(uint64_t),
				"blkcg weight", FAULT_ON_ERROR);
			fprintf(fp, "%s: %lu\n", blkio_prop_strs[attr_id - 1],
				val);
			return 0;
		case BLKIO_PROP_weight_device:
			off = MEMBER_OFFSET("cfq_group", "dev_weight");
			data_size = sizeof(uint);
			break;
		case BLKIO_PROP_io_service_bytes:
			off = blkio_offset_table.cfq_group_stats +
			      blkio_offset_table.cfqg_stats_service_bytes +
			      MEMBER_OFFSET("blkg_rwstat", "cnt");
			data_size = sizeof(uint64_t) * 4;
			show_total = 1;
			break;
		case BLKIO_PROP_io_serviced:
			off = blkio_offset_table.cfq_group_stats +
			      blkio_offset_table.cfqg_stats_serviced +
			      MEMBER_OFFSET("blkg_rwstat", "cnt");
			data_size = sizeof(uint64_t) * 4;
			show_total = 1;
			break;
		case BLKIO_PROP_time:
			off = blkio_offset_table.cfq_group_stats +
			      blkio_offset_table.cfqg_stats_time +
			      MEMBER_OFFSET("blkg_stat", "cnt");
			data_size = sizeof(uint64_t);
			break;
		case BLKIO_PROP_sectors:
			off = blkio_offset_table.cfq_group_stats +
			      blkio_offset_table.cfqg_stats_sectors +
			      MEMBER_OFFSET("blkg_stat", "cnt");
			data_size = sizeof(uint64_t);
			break;
		case BLKIO_PROP_io_service_time:
			off = blkio_offset_table.cfq_group_stats +
			      blkio_offset_table.cfqg_stats_service_time +
			      MEMBER_OFFSET("blkg_rwstat", "cnt");
			data_size = sizeof(uint64_t) * 4;
			show_total = 1;
			break;
		case BLKIO_PROP_io_wait_time:
			off = blkio_offset_table.cfq_group_stats +
			      blkio_offset_table.cfqg_stats_wait_time +
			      MEMBER_OFFSET("blkg_rwstat", "cnt");
			data_size = sizeof(uint64_t) * 4;
			show_total = 1;
			break;
		case BLKIO_PROP_io_merged:
			off = blkio_offset_table.cfq_group_stats +
			      blkio_offset_table.cfqg_stats_merged +
			      MEMBER_OFFSET("blkg_rwstat", "cnt");
			data_size = sizeof(uint64_t) * 4;
			show_total = 1;
			break;
		case BLKIO_PROP_io_queued:
			off = blkio_offset_table.cfq_group_stats +
			      blkio_offset_table.cfqg_stats_queued +
			      MEMBER_OFFSET("blkg_rwstat", "cnt");
			data_size = sizeof(uint64_t) * 4;
			show_total = 1;
			break;
		default:
			/* doesn't support debug */
			break;
		}
		fprintf(fp, "%s: \n", blkio_prop_strs[attr_id - 1]);
		total += print_cfq_group(blkg_addr, attr_id, off, data_size);
		break;
	case BLKCG_POLICY_THROTL:
		/* target struct is throtl_grp. */
		switch (attr_id)
		{
		case BLKIO_THROTL_io_service_bytes:
		case BLKIO_THROTL_io_serviced:
			off = MEMBER_OFFSET("throtl_grp", "stats_cpu");
			data_size = sizeof(ulong);
			show_total = 1;
			break;
		case BLKIO_THROTL_read_bps_device:
			off = MEMBER_OFFSET("throtl_grp", "bps");
			data_size = sizeof(uint64_t);
			break;
		case BLKIO_THROTL_write_bps_device:
			off = sizeof(uint64_t) + MEMBER_OFFSET("throtl_grp", "bps");
			data_size = sizeof(uint64_t);
			break;
		case BLKIO_THROTL_read_iops_device:
			off = MEMBER_OFFSET("throtl_grp", "iops");
			data_size = sizeof(int);
			break;
		case BLKIO_THROTL_write_iops_device:
			off = sizeof(int) + MEMBER_OFFSET("throtl_grp", "iops");
			data_size = sizeof(int);
			break;
		default:
			break;
		}
		fprintf(fp, "%s: \n", blkio_thro_strs[attr_id]);
		total += print_throtl_grp(blkg_addr, attr_id, off, data_size);
		break;
	default:
		break;
	}

	if (show_total)
	fprintf(fp, "\tTotal %lu\n", total);

	return 0;
}

/* for kernel version 2.6.35, 2.6.36 */
static void
blkio_read_each_blkg_for35(ulong blkg_addr, int type,
			   int show_total, char *buf)
{
	uint64_t total = 0;
	uint32_t dev;

	do {
		dev = (uint32_t)read_member_32(blkg_addr +
				blkio_offset_table.blkg_dev, "blkg_dev");
		if (dev)
			total += blkio_get_stat(blkg_addr, type, dev, buf);
		blkg_addr = (ulong)list_next(NULL, (void *)blkg_addr,
				   blkio_offset_table.blkg_blkcg_node);
	} while (0 != blkg_addr + blkio_offset_table.blkg_blkcg_node);

	if (show_total)
		fprintf(fp, "\tTotal %lu\n", total);
}

/* for kernel version 2.6.37 -- 2.6.39 */
static void
blkio_read_each_blkg_for37(ulong blkg_addr, int type, int plid,
			   int show_total, char *buf)
{
	int blkg_plid;
	uint64_t total = 0;
	uint32_t dev;

	do {
		dev = (uint32_t)read_member_32(blkg_addr +
				blkio_offset_table.blkg_dev, "blkg_dev");
		blkg_plid = (int)read_member_32(blkg_addr +
				 blkio_offset_table.blkg_plid, "blkg_plid");
		if (dev && plid == blkg_plid)
			total += blkio_get_stat(blkg_addr, type, dev, buf);
		blkg_addr = (ulong)list_next(NULL, (void *)blkg_addr,
				   blkio_offset_table.blkg_blkcg_node);
	} while (0 != blkg_addr + blkio_offset_table.blkg_blkcg_node);

	if (show_total)
		fprintf(fp, "\tTotal %lu\n", total);
}

/* for kernel version 3.0 -- 3.4 */
static void
blkio_read_each_blkg_for300(ulong blkg_addr, int type, int plid,
			   int show_total, int pcpu, char *buf)
{
	int blkg_plid;
	uint64_t total = 0;
	uint32_t dev;

	/* type defined here is different from kernel v3.0 -- v3.4 */
	if (type > BLKIO_STAT_SERVICED &&
	    type < BLKIO_STAT_TIME)
		type -= 2;
	else if (type == BLKIO_STAT_SERVICE_BYTES)
		type = BLKIO_STAT_CPU_SERVICE_BYTES;
	else if (type == BLKIO_STAT_SERVICED)
		type = BLKIO_STAT_CPU_SERVICED;

	/*
	 * there is a BLKIO_STAT_MERGED before BLKIO_STAT_QUEUED in 6.3GA,
	 * while BLKIO_STAT_MERGED doesn't exist in kernel v3.0 -- v3.4
	 */
	
	if ((12 == MEMBER_SIZE("blkio_group_stats", "stat_arr") /
		   sizeof(uint64_t))) {
		if (type == BLKIO_STAT_QUEUED -2)
			type -= 1;
		else if(type == BLKIO_STAT_MERGED - 2) {
			type = BLKIO_STAT_CPU_MERGED;
			pcpu = 1;
		}
	}

	do {
		dev = (uint32_t)read_member_32(blkg_addr +
				blkio_offset_table.blkg_dev, "blkg_dev");
		blkg_plid = (int)read_member_32(blkg_addr +
				 blkio_offset_table.blkg_plid, "blkg_plid");
		if (dev && plid == blkg_plid) {
			if (pcpu)
				total += blkio_get_stat_cpu(blkg_addr, type, dev, buf);
			else
				total += blkio_get_stat(blkg_addr, type, dev, buf);
		}
		blkg_addr = (ulong)list_next(NULL, (void *)blkg_addr,
				   blkio_offset_table.blkg_blkcg_node);
	} while (0 != blkg_addr + blkio_offset_table.blkg_blkcg_node);

	if (show_total)
		fprintf(fp, "\tTotal %lu\n", total);
}

static int
read_blkcg_stat(ulong blkg_addr, enum stat_type type, int plid, int show_total, int pcpu, char *buf)
{
	if (blkio_offset_table.blkg_stats_cpu == -1) {
		if (!MEMBER_EXISTS("blkio_policy_node", "val"))
			/* kernel version 2.6.35, 2.6.36 */
			blkio_read_each_blkg_for35(blkg_addr, type,
						   show_total, buf);
		else
			/* kernel version 2.6.37 -- 2.6.39 */
			blkio_read_each_blkg_for37(blkg_addr, type, plid,
						   show_total, buf);
	} else {
		/* kernel version 3.0 -- 3.4 */
		blkio_read_each_blkg_for300(blkg_addr, type, plid,
					    show_total, pcpu, buf);
	}

	return 0;
}

static int
read_policy_node(ulong blkcg_addr, int plid, int attr_id, char *buf)
{
	ulong head;
	int policy_id, fileid;
	uint weight, iops;
	uint64_t bps;
	uint32_t dev;

	head = blkcg_addr + blkio_offset_table.blkio_policy_list;
	while (1) {
		if ((head = (ulong)list_next((void *)head, NULL, 0)) ==
			(blkcg_addr + blkio_offset_table.blkio_policy_list)) {
			fprintf(fp, "%s\n", buf);
			break;
		}
		policy_id = read_member_32(head +
				blkio_offset_table.blkp_plid, "blkp_plid");
		fileid = read_member_32(head + blkio_offset_table.blkp_fileid,
					"blkp_fileid");
		if (plid != policy_id || attr_id != fileid)
			continue;
		dev = read_member_32(head + blkio_offset_table.blkp_dev,
				     "blkp_dev");
		switch (plid)
		{
		case BLKIO_POLICY_PROP:
			if (fileid == BLKIO_PROP_weight_device) {
				weight = (uint)read_member_32(head +
						blkio_offset_table.blkp_weight,
						"blkp_weight");
				fprintf(fp, "%s%u\n", buf, weight);
			}
			break;
		case BLKIO_POLICY_THROTL:
			switch (attr_id)
			{
			case BLKIO_THROTL_read_bps_device:
			case BLKIO_THROTL_write_bps_device:
				readmem(head + blkio_offset_table.blkp_weight +
					sizeof(uint),
					KVADDR, &bps, sizeof(uint64_t),
					"blkio_policy_node val.bps",
					FAULT_ON_ERROR);
				fprintf(fp, "%s%lu\n", buf, bps);
				break;
			case BLKIO_THROTL_read_iops_device:
			case BLKIO_THROTL_write_iops_device:
				readmem(head+ blkio_offset_table.blkp_weight +
					sizeof(uint) + sizeof(uint64_t),
					KVADDR, &iops, sizeof(uint),
					"blkio_policy_node val.iops",
					FAULT_ON_ERROR);
				fprintf(fp, "%s%u\n", buf, iops);
				break;
			}
			break;
		}
	}
	return 0;
}

static ulong
read_blkcg_stat_old(ulong blkg_addr, int type, char *buf)
{
	ulong val;
	uint32_t dev;

	fprintf(fp, "%s\n", buf);
	do {
		/* get dev */
		readmem(blkg_addr + blkio_offset_table.blkg_dev,
			KVADDR, &dev, sizeof(uint32_t),
			"blkio_group dev", FAULT_ON_ERROR);
		if (dev) {
			if (type == BLKIO_STAT_TIME)
				readmem(blkg_addr +
					MEMBER_OFFSET("blkio_group", "time"),
					KVADDR, &val, sizeof(ulong),
					"blkio_group time", FAULT_ON_ERROR);
			else
				readmem(blkg_addr +
					MEMBER_OFFSET("blkio_group", "sectors"),
					KVADDR, &val, sizeof(ulong),
					"blkio_group sectors", FAULT_ON_ERROR);
			fprintf(fp, "\t%u:%u %lu\n",
				MAJOR(dev), MINOR(dev), val);
		}
		blkg_addr = (ulong)list_next(NULL, (void *)blkg_addr,
				   blkio_offset_table.blkg_blkcg_node);
	} while (0 != blkg_addr + blkio_offset_table.blkg_blkcg_node);

	return val;
}

static void
blkio_print_param_old(ulong blkcg_addr)
{
	uint weight;
	ulong blkg_addr, hlist_head;
	char buf[FILENAME_MAX] = {0};

	readmem(blkcg_addr + blkio_offset_table.blkio_blkg_list, KVADDR,
		&hlist_head, sizeof(ulong), "blkio_cgroup blkg_list",
		FAULT_ON_ERROR);
	blkg_addr = hlist_head - blkio_offset_table.blkg_blkcg_node;

	/* print weight */
	readmem(blkcg_addr + blkio_offset_table.blkio_weight,
		KVADDR, &weight, sizeof(uint),
		"blkio_cgroup weight", FAULT_ON_ERROR);
	fprintf(fp, "blkio.weight: %u\n", weight);

	if (hlist_head == 0 || hlist_head == ~0UL) {
		fprintf(fp, "blkio.time: 0\n");
		fprintf(fp, "blkio.sectors: 0\n");
		return;
	}

	/* print time */
	strcpy(buf, "blkio.time:");
	read_blkcg_stat_old(blkg_addr, BLKIO_STAT_TIME, buf);
	/* print sectors*/
	strcpy(buf, "blkio.sectors:");
	read_blkcg_stat_old(blkg_addr, BLKIO_STAT_CPU_SECTORS, buf);
}

/*
 * All the params except weight are assosiated with blkio_group.
 * So just print the params with value 0 if blkio_group does not exist.
 */
static int
blkio_print_param_no_group(ulong blkcg_addr, int plid, int attr_id, char *str)
{
	uint weight;
	char buf[FILENAME_MAX] = {0};

	fprintf(fp, "%s.", str);
	switch (plid)
	{
	case BLKIO_POLICY_PROP:
	case BLKCG_POLICY_PROP:
		sprintf(buf, "%s: ", blkio_prop_strs[attr_id - 1]);
		switch (attr_id)
		{
		case BLKIO_PROP_weight:
			weight = (uint)read_member_32(blkcg_addr +
					blkio_offset_table.blkio_weight,
					"blkio_weight");
			fprintf(fp, "%s%u\n", buf, weight);
			break;
		case BLKIO_PROP_weight_device:
		case BLKIO_PROP_time:
		case BLKIO_PROP_sectors:
			fprintf(fp, "%s\n", buf);
			break;
		case BLKIO_PROP_io_service_bytes:
		case BLKIO_PROP_io_serviced:
		case BLKIO_PROP_io_service_time:
		case BLKIO_PROP_io_wait_time:
		case BLKIO_PROP_io_merged:
		case BLKIO_PROP_io_queued:
			fprintf(fp, "%sTotal 0\n", buf);
		default:
			/* doesn't support debug */
			break;
		}
		break;
	case BLKIO_POLICY_THROTL:
	case BLKCG_POLICY_THROTL:
		sprintf(buf, "%s: ", blkio_thro_strs[attr_id]);
		switch (attr_id)
		{
		case BLKIO_THROTL_io_service_bytes:
		case BLKIO_THROTL_io_serviced:
			if (MEMBER_EXISTS("blkio_policy_node", "val"))
				fprintf(fp, "%sTotal 0\n", buf);
			else
				fprintf(fp, "%s\n", buf);
				break;
		case BLKIO_THROTL_read_bps_device:
		case BLKIO_THROTL_write_bps_device:
		case BLKIO_THROTL_read_iops_device:
		case BLKIO_THROTL_write_iops_device:
			fprintf(fp, "%s\n", buf);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return 0;
}

static int
blkio_read_map(ulong blkcg_addr, int plid, int attr_id, char *str)
{
	uint weight;
	ulong blkg_addr, hlist_head;
	char buf[FILENAME_MAX] = {0};

	readmem(blkcg_addr + blkio_offset_table.blkio_blkg_list, KVADDR,
		&hlist_head, sizeof(ulong), "blkio_cgroup blkg_list",
		FAULT_ON_ERROR);
	if (hlist_head == 0 || hlist_head == ~0UL)
		return blkio_print_param_no_group(blkcg_addr, plid,
						  attr_id, str);
	blkg_addr = hlist_head - blkio_offset_table.blkg_blkcg_node;

	switch (plid)
	{
	case BLKIO_POLICY_PROP:
		sprintf(buf, "%s.%s: ", str, blkio_prop_strs[attr_id - 1]);
		switch (attr_id)
		{
		case BLKIO_PROP_weight:
			weight = (uint)read_member_32(blkcg_addr +
					blkio_offset_table.blkio_weight,
					"blkio_weight");
			fprintf(fp, "%s%u\n", buf, weight);
			break;
		case BLKIO_PROP_weight_device:
			return read_policy_node(blkcg_addr, plid, attr_id, buf);
		case BLKIO_PROP_io_service_bytes:
			fprintf(fp, "%s\n", buf);
			return read_blkcg_stat(blkg_addr,
					       BLKIO_STAT_CPU_SERVICE_BYTES,
					       plid, 1, 1, buf);
		case BLKIO_PROP_io_serviced:
			fprintf(fp, "%s\n", buf);
			return read_blkcg_stat(blkg_addr, BLKIO_STAT_CPU_SERVICED,
					       plid, 1, 1, buf);
		case BLKIO_PROP_time:
			fprintf(fp, "%s\n", buf);
			return read_blkcg_stat(blkg_addr, BLKIO_STAT_TIME,
					       plid, 0, 0, buf);
		case BLKIO_PROP_sectors:
			fprintf(fp, "%s\n", buf);
			return read_blkcg_stat(blkg_addr,
					       BLKIO_STAT_SECTORS,
					       plid, 0, 1, buf);
		case BLKIO_PROP_io_service_time:
			fprintf(fp, "%s\n", buf);
			return read_blkcg_stat(blkg_addr, BLKIO_STAT_SERVICE_TIME,
					       plid, 1, 0, buf);
		case BLKIO_PROP_io_wait_time:
			fprintf(fp, "%s\n", buf);
			return read_blkcg_stat(blkg_addr, BLKIO_STAT_WAIT_TIME,
					       plid, 1, 0, buf);
		case BLKIO_PROP_io_merged:
			fprintf(fp, "%s\n", buf);
			return read_blkcg_stat(blkg_addr, BLKIO_STAT_MERGED,
					       plid, 1, 0, buf);
		case BLKIO_PROP_io_queued:
			fprintf(fp, "%s\n", buf);
			return read_blkcg_stat(blkg_addr, BLKIO_STAT_QUEUED,
					       plid, 1, 0, buf);
		default:
			/* doesn't support debug */
			break;
		}
		break;
	case BLKIO_POLICY_THROTL:
		sprintf(buf, "%s.%s: ", str, blkio_thro_strs[attr_id]);
		switch (attr_id)
		{
		case BLKIO_THROTL_io_service_bytes:
			if (!MEMBER_EXISTS("blkio_policy_node", "val"))
				break;
			fprintf(fp, "%s\n", buf);
			return read_blkcg_stat(blkg_addr, BLKIO_STAT_SERVICE_BYTES,
					       plid, 1, 1, buf);
		case BLKIO_THROTL_io_serviced:
			if (!MEMBER_EXISTS("blkio_policy_node", "val"))
				break;
			fprintf(fp, "%s\n", buf);
			return read_blkcg_stat(blkg_addr, BLKIO_STAT_SERVICED,
					       plid, 1, 1, buf);
		case BLKIO_THROTL_read_bps_device:
		case BLKIO_THROTL_write_bps_device:
		case BLKIO_THROTL_read_iops_device:
		case BLKIO_THROTL_write_iops_device:
			if (!MEMBER_EXISTS("blkio_policy_node", "val"))
				break;
			return read_policy_node(blkcg_addr, plid, attr_id ,buf);
		default:
			break;
		}
		break;
	default:
		break;
	}

	return 0;
}

void
cmd_cgget(void)
{
	int c;
	int ret = 0, help_flag = 0;
	int idx, i = 0, j = 0, k = 0;
	int dis_all_param = 0, group_flag = 0, var_flag = 0;
	struct cgroup_spec *group_list[CGROUP_HIER_MAX] = {NULL};
	char *subsys_str[CGROUP_HIER_MAX], *path[CGROUP_HIER_MAX],
	     *gctrlptr, *pathptr;

	if (!is_cgroup_supported) {
		command_not_supported();
		return;
	}
	while ((c = getopt_long(argcnt, args, "hg:r:a", 
		long_options, NULL)) != EOF) {
		switch(c)
		{
		case 'g':
			if (strchr(optarg, ':') != NULL) {
				group_flag |= MODE_COMBINE_PATH;
				gctrlptr = strtok(optarg, ":");
				pathptr = strtok(NULL, ":");
				if (gctrlptr == NULL || pathptr == NULL) {
					argerrs++;
					goto err;
				}
				subsys_str[j++] = strdup(gctrlptr);
				path[k++] = strdup(pathptr);
			} else {
				group_flag |= MODE_SEPARATE_PATH;
				subsys_str[j++] = strdup(optarg);
			}
			break;
		case 'r':
			var_flag = 1;
			ret = parse_variable_spec(optarg, subsys_str, &j);
			if (ret == -1)
				goto err;
			break;
		case 'a':
			dis_all_param = 1;
			break;
		case 'h':
			help_flag = 1;
		default:
			argerrs++;
			goto err;
		}
	}

	if (((group_flag & MODE_COMBINE_PATH) && args[optind]) || 
	    (!(group_flag & MODE_COMBINE_PATH) && !args[optind])) {
		argerrs++;
		goto err;
	}

	/* read the list of path */
	while (optind < argcnt) {
		if (group_flag & MODE_COMBINE_PATH) {
			argerrs++;
			goto err;
		}
		path[k++] = strdup(args[optind++]);
	}

	if (var_flag && (path[0] == NULL)) {
		argerrs++;
		goto err;
	}

	/* if only PATH is specified, treat it as -a is specified. */
	if (!group_flag && !var_flag)
		dis_all_param = 1;

	if (dis_all_param)
		i = make_all_cgroup_spec(group_list, subsys_str, path, &j, &k);
	else
		i = make_cgroup_spec(group_list, subsys_str, path, &j, &k);
	if (i < 1)
		goto err;

	print_cgroup_list(args[0], group_list, i, dis_all_param);

err:
	for (idx = 0; idx < CGROUP_SUBSYS_MAX; idx++) {
		while (--var_num[idx] >= 0)
			free(variable_str[idx][var_num[idx]]);
		var_num[idx] = 0;
	}
	variable_flag = 0;
	while (--i >= 0)
		free(group_list[i]);
	while (--j >= 0)
		free(subsys_str[j]);
	while (--k >= 0)
		free(path[k]);
	if (argerrs) {
		if (!help_flag)
			fprintf(stderr, "Invalid commandline specified.\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	}
}

/* strip off the same string */
static void
filter_str(char *str[], int *str_num)
{
	char *work_str[CGROUP_HIER_MAX];
	int i, j, k = 0;

	/* Organize the filtered strings in the temp string array */
	for (i = 0; i < *str_num; i++) {
		for (j = i + 1; j < *str_num; j++) {
			if (strcmp(str[i], str[j]) == 0)
				break;
		}
		if (j == *str_num)
			work_str[k++] = strdup(str[i]);
		free(str[i]);
	}
	/* Assign the temp buffer to original string array */
	for(i = 0; i < k; i++)
		str[i] = work_str[i];
	*str_num = k;
}

static int
make_cgroup_spec(struct cgroup_spec **group_list, char *subsys_str[],
			char *path[], int *str_num, int *path_num)
{
	int j, k, i = 0;

	filter_str(subsys_str, str_num);
	filter_str(path, path_num);
	for (j = 0; j < CGROUP_SUBSYS_MAX; j++)
		filter_str(variable_str[j], &var_num[j]);

	for (j = 0; j < *str_num; j++) {
		for (k = 0; k < *path_num; k++) {
			while (group_list[i] != NULL)
				i++;
			if (i > CGROUP_HIER_MAX) {
				fprintf(stderr, "Max allowed hierarchies %d"
					" reached.\n", CGROUP_HIER_MAX);
				return -1;
			}
			group_list[i] = calloc(1, sizeof(struct cgroup_spec));
			if (!group_list[i]) {
				fprintf(stderr, "calloc error.\n");
				return -1;
			}
			strncpy(group_list[i]->subsys_str, subsys_str[j],
				strlen(subsys_str[j]));
			strncpy(group_list[i]->path, path[k],
				strlen(path[k]));
			i++;
		}
	}

	return i;
}

static int
make_all_cgroup_spec(struct cgroup_spec **group_list, char *subsys_str[],
		     char *path[], int *str_num, int *path_num)
{
	int i, j, k;

	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		for (j = 0; j < *str_num; j++) {
			/* if matched string is found, it must be
			 * specified by user, jump out. */
			if (0 == strcmp(cgroup_subsys_table[i].subsys_str,
					subsys_str[j]))
				break;
		}
		/* "j == str_num" means no matched string is found,
		 * so add it to subsys_str. */
		if (j == *str_num &&
		    cgroup_subsys_table[i].subsys_str != NULL &&
		    *cgroup_subsys_table[i].subsys_str != '\0' &&
		    *cgroup_subsys_table[i].subsys_str != ' ') {
			subsys_str[*str_num] = strdup(cgroup_subsys_table[i].subsys_str);
			(*str_num)++;
		}
	}

	k = make_cgroup_spec(group_list, subsys_str, path, str_num, path_num);

	return k;
}

static void
cgroup_subsys_table_init()
{
	int subsys_num, subsys_id, i;
	ulong cg_subsys_addr, strptr;
	char buf[CGROUP_STR_LEN] = {0};

	/* This is the total number. There may be empty element in the array. */
	subsys_num = get_array_length("subsys", NULL, 0);
	if (!subsys_num) {
		fprintf(fp, "Warning: cgroup is not supported by this OS.\n");
		is_cgroup_supported = CGROUP_NOT_SUPPORT;
		return;
	}
	is_cgroup_supported = CGROUP_SUPPORTED;
	memset(cgroup_subsys_table, 0, sizeof(struct cgroup_subsys_table) *
	       CGROUP_SUBSYS_MAX);

	/* get subsys_id and name pairs from kernel */
	for (i = 0; i < subsys_num; i++) {
		if (!readmem(symbol_value("subsys") + i * sizeof(ulong),
			     KVADDR, &cg_subsys_addr,
			     sizeof(ulong), "subsys", FAULT_ON_ERROR))
			return;
		if (!cg_subsys_addr)
			break;
		readmem(cg_subsys_addr + MEMBER_OFFSET("cgroup_subsys", "name"),
			KVADDR, &strptr, sizeof(ulong), "cgroup_subsys name",
			FAULT_ON_ERROR);
		readmem(strptr, KVADDR, buf, CGROUP_STR_LEN, "name", FAULT_ON_ERROR);
		readmem(cg_subsys_addr + MEMBER_OFFSET("cgroup_subsys", "subsys_id"),
			KVADDR, &subsys_id, sizeof(int), "cgroup_subsys subsys_id",
			FAULT_ON_ERROR);
		cgroup_subsys_table[i].subsys_id = subsys_id;
		strncpy(cgroup_subsys_table[i].subsys_str, buf, strlen(buf));
	}

	/* this is the real number */
	cgroup_subsys_num = i;
}

static int
parse_variable_spec(char *optarg, char **subsys_str, int *j)
{
	char *cg, *var;
	int i;

	cg = strtok(optarg, ".");
	var = strtok(NULL, ".");
	if (cg == NULL || var == NULL)
		return -1;

	for (i = 0; i < CGROUP_SUBSYS_MAX; i++) {
		if (strcmp(subsys_name[i], cg) == 0) {
			subsys_str[*j] = strdup(cg);
			variable_str[i][var_num[i]] = strdup(var);
			variable_flag |= NUM_TO_BIT(i);
			(*j)++;
			var_num[i]++;
			break;
		}
	}

	if (i == CGROUP_SUBSYS_MAX) {
		fprintf(fp, "No subsys '%s' is found.\n", cg);
		return -1;
	}
	return 0;
}

static void
print_specified_param(int subsys_id)
{
	char *linebuf = NULL;
	int i, flag = 0, found = 0;
	size_t length;
	int st_idx = strlen(subsys_name[subsys_id]);

	/* reset the file discriptor */
	rewind(fp);
	while (-1 != getline(&linebuf, &length, fp)) {
		/*
		 * If flag == 1, this means the param was matched.
		 * Since we don't know if the next line belongs to
		 * this param or not, we check it. If YES, print
		 * it, too.
		 */
		if (flag == 1) {
			if (!strstr(linebuf, subsys_name[subsys_id])) {
				fprintf(pc->saved_fp, "%s", linebuf);
				continue;
			}
			flag = 0;
		}
		for (i = 0; i < var_num[subsys_id]; i++) {
			/*
			 * compare the param string after
			 * name of subsys at beginning.
			 */
			if (variable_str[subsys_id][i] != NULL &&
			    strstr(&linebuf[st_idx], variable_str[subsys_id][i])) {
				found |= NUM_TO_BIT(i);
				flag = 1;
				fprintf(pc->saved_fp, "%s", linebuf);
			}
		}
	}

	for (i = 0; i < var_num[subsys_id]; i++) {
		if (!test_bit(i, found))
			fprintf(pc->saved_fp, "Cannot find param '%s'.\n",
				variable_str[subsys_id][i]);
	}
	if (linebuf) {
		free(linebuf);
		linebuf = NULL;
	}
}

static ulong
retrieve_path(ulong start, ulong end, ulong *srcptr, const char *path)
{
	char buf[FILENAME_MAX];
	char *p, *pos;
	ulong children_addr, sibling_addr, parent_addr, dtrp, find_len;

	/* already match */
	if (*srcptr)
		return *srcptr;

	p = calloc(1, strlen(path) + 1);
	strcpy(p, path);
	pos = strchr(p, '/');
	if (pos) {
		find_len = pos - p;
		pos++;
	}

	readmem(start + cgroup_offset_table.cgroup_dentry, KVADDR,
		&dtrp, sizeof(ulong), "cgroup dentry",
		FAULT_ON_ERROR);

	/* if match */
	if (0 == strcmp("/", get_dentry_path(dtrp, buf, FILENAME_MAX)) ||
	    0 == strncmp(p, get_dentry_path(dtrp, buf, FILENAME_MAX), find_len)) {
		if ((pos != NULL) && (*pos != '\0')) {
			/* continue with children */
			readmem(start + cgroup_offset_table.cgroup_children, KVADDR,
				&children_addr, sizeof(struct list_head *),
				"cgroup children", FAULT_ON_ERROR);
			/*
			 * "children.next" of parent is pointing to
			 * the struct "sibling" of children cgroup.
			 * Except there's not any child.
			 */
			if (start != (children_addr - cgroup_offset_table.cgroup_children)) {
				start = (ulong)list_next(NULL, (void *)start,
							 cgroup_offset_table.cgroup_children);
				start = start + cgroup_offset_table.cgroup_children -
						cgroup_offset_table.cgroup_sibling;
				retrieve_path(start, end, srcptr, pos);
			}
		} else {
			*srcptr = start;
			free(p);
			return *srcptr;
		}
	} else {
		/* no match, continue with sibling */
		readmem(start + cgroup_offset_table.cgroup_sibling, KVADDR,
			&sibling_addr, sizeof(struct list_head *), "cgroup sibling",
			FAULT_ON_ERROR);
		readmem(start + cgroup_offset_table.cgroup_parent, KVADDR,
			&parent_addr, sizeof(struct list_head *), "cgroup parent",
			FAULT_ON_ERROR);
		/*
		 * "sibling.next" of one cgroup is pointing to the struct "sibling" of
		 * its sibling cgroup. Except this is the last child of its parent.
		 * "sibling.next" of the last child is pointing to the struct 
		 * "children" of its parent.
		 */
		if ((end != (sibling_addr - cgroup_offset_table.cgroup_children)) &&
		    (parent_addr != (sibling_addr - cgroup_offset_table.cgroup_children))) {
			start = (ulong)list_next(NULL, (void *)start,
						 cgroup_offset_table.cgroup_sibling);
			retrieve_path(start, end, srcptr, p);
		}
	}

	free(p);
	return *srcptr;
}

static void
format_path_str(const char *str_in, char *str_out)
{
	int len;

	if (!str_in)
		return;

	len = strlen(str_in);
	if (!len)
		return;

	/* if only "/" or "." */
	if ((0 == strcmp("/", str_in)) || (0 == strcmp(".", str_in)))
		strcpy(str_out, "/");
	else if ('.' == str_in[0] && '/' == str_in[1])
		/* if "./" is specified at the beginning */
		strcpy(str_out, &str_in[1]);
	else if ('/' != str_in[0]) {
		/* if no '/' is specified at the beginning */
		str_out[0] = '/';
		strcpy(&str_out[1], str_in);
	} else
		strcpy(str_out, str_in);

	/* strip the '/' character at the last position */
	if ('/' == str_out[strlen(str_out) - 1])
		str_out[strlen(str_out) - 1] = '\0';
}

static ulong
get_css_addr(struct cgroup_spec *group_list, int subsys_id, ulong root_addr)
{
	ulong subsys_addr, css_addr, top_cgroup, cgroup_addr = 0;
	char buf[FILENAME_MAX] = {0};

	top_cgroup = root_addr + cgroupfs_root_offset_table.cgroupfs_root_top_cgroup;

	format_path_str(group_list->path, buf);
	cgroup_addr = retrieve_path(top_cgroup, top_cgroup, &cgroup_addr, buf);

	if (cgroup_addr == 0)
		return 0;
	css_addr = cgroup_addr + cgroup_offset_table.cgroup_subsys;
	/* struct css is at the beginning of struct used by each subsystem */
	if (!readmem((css_addr + subsys_id * sizeof(ulong)), KVADDR,
		      &subsys_addr, sizeof(ulong), "cgroup subsys",
		      FAULT_ON_ERROR))
		subsys_addr = 0;
	return subsys_addr;
}

/*
 * get the address of next entry from an embedded list.
 */
static struct list_head *
list_next(void *head, void *struct_entry, long offset)
{
	ulong entry_addr;

	if (struct_entry) {
		head = (void *)((ulong)struct_entry + offset);
	} else if (head) {
		/* do nothing */
	} else {
		return NULL;
	}

	if (!readmem((ulong)head, KVADDR, &entry_addr, sizeof(struct list_head *),
		     "list_head->next", FAULT_ON_ERROR))
		return NULL;
	return (struct list_head *)(entry_addr - offset);
}

static int
get_subsys_id(struct cgroup_spec *group_list)
{
	int subsys_id = -1;
	int i;

	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		if (0 == strcmp(cgroup_subsys_table[i].subsys_str,
				 group_list->subsys_str)) {
			subsys_id = cgroup_subsys_table[i].subsys_id;
			break;
		}
	}
	return subsys_id;
}

static void
print_cgroup(char *cmd_name, struct cgroup_spec *group_list, int subsys_id,
	     ulong root_addr, int disp_flag)
{
	ulong css_addr = 0;

	css_addr = get_css_addr(group_list, subsys_id, root_addr);
	if (!css_addr) {
		if (!disp_flag)
			fprintf(fp, "%s: Cannot find controller '%s' "
				"in group '%s'\n", cmd_name,
				group_list->subsys_str,
				group_list->path);
		return;
	}

	if (0 == strcmp(group_list->subsys_str, subsys_name[cpuset_subsys_id]))
		print_cpuset(group_list, subsys_id, css_addr);
	else if (0 == strcmp(group_list->subsys_str, subsys_name[ns_subsys_id]))
		/* nothing to be printed */
		;
	else if (0 == strcmp(group_list->subsys_str, subsys_name[cpu_cgroup_subsys_id]))
		print_cpu(group_list, subsys_id, css_addr);
	else if (0 == strcmp(group_list->subsys_str, subsys_name[cpuacct_subsys_id]))
		print_cpuacct(group_list, subsys_id, css_addr);
	else if (0 == strcmp(group_list->subsys_str, subsys_name[hugetlb_subsys_id]))
		print_hugetlb(group_list, subsys_id, css_addr);
	else if (0 == strcmp(group_list->subsys_str, subsys_name[mem_cgroup_subsys_id]))
		print_memory(group_list, subsys_id, css_addr);
	else if (0 == strcmp(group_list->subsys_str, subsys_name[devices_subsys_id]))
		print_devices(group_list, subsys_id, css_addr);
	else if (0 == strcmp(group_list->subsys_str, subsys_name[freezer_subsys_id]))
		print_freezer(group_list, subsys_id, css_addr);
	else if (0 == strcmp(group_list->subsys_str, subsys_name[net_cls_subsys_id]))
		print_net_cls(group_list, subsys_id, css_addr);
	else if (0 == strcmp(group_list->subsys_str, subsys_name[blkio_subsys_id]))
		print_blkio(group_list, subsys_id, css_addr);
	else if (0 == strcmp(group_list->subsys_str, subsys_name[perf_subsys_id]))
		/* nothing to be printed */
		;
	else if (0 == strcmp(group_list->subsys_str, subsys_name[net_prio_subsys_id]))
		print_net_prio(group_list, subsys_id, css_addr);
	else
		fprintf(fp, "Not supported controller %s.\n",
			group_list->subsys_str);

}

static void
print_cpuset(struct cgroup_spec *group_list, int subsys_id, ulong subsys_addr)
{
	ulong cpuset_flags, cpuset_cpus_addr,
	      mems_allowed[BITS_TO_LONGS(vt->numnodes)],
	      cpus_allowed[BITS_TO_LONGS(kt->cpus)];
	int i, val;
	char buf[FILENAME_MAX] = {0};

	fprintf(fp, "%s:\n", group_list->path);

	/* if some param is specified, first output all into a tmpfile. */
	if (test_bit(cpuset_subsys_id, variable_flag))
		open_tmpfile();

	for (i = CS_CPU_EXCLUSIVE; i <= CS_CPUS; i++) {
		if (cpuset_offset_table.cpuset_shed_relax_domain_level == -1 &&
		    i == CS_SHED_RELAX_DOMAIN_LEVEL)
			continue;
		fprintf(fp, "%s.%s: ", group_list->subsys_str,
			cpuset_params[i]);
		switch (i)
		{
		case CS_CPU_EXCLUSIVE:
		case CS_MEM_EXCLUSIVE:
		case CS_MEM_HARDWALL:
		case CS_MEMORY_MIGRATE:
		case CS_SCHED_LOAD_BALANCE:
		case CS_SPREAD_PAGE:
		case CS_SPREAD_SLAB:
			readmem(subsys_addr + cpuset_offset_table.cpuset_flags,
				KVADDR, &cpuset_flags, sizeof(ulong),
				"cpuset flags", FAULT_ON_ERROR);
			fprintf(fp, "%d\n", test_bit(i, cpuset_flags));
			break;
		case CS_MEM_PRESSURE_ENABLE:
			readmem(symbol_value("cpuset_memory_pressure_enabled"),
				KVADDR, &val, sizeof(int),
				"cpuset_memory_pressure_enabled", FAULT_ON_ERROR);
			fprintf(fp, "%d\n", val);
			break;
		case CS_MEM_PRESSURE:
			readmem(subsys_addr + cpuset_offset_table.cpuset_fmeter +
				MEMBER_OFFSET("fmeter", "val"), KVADDR,
				&val, sizeof(int),
				"cpuset_memory_pressure", FAULT_ON_ERROR);
			fprintf(fp, "%d\n", val);
			break;
		case CS_SHED_RELAX_DOMAIN_LEVEL:
			readmem(subsys_addr +
				cpuset_offset_table.cpuset_shed_relax_domain_level,
				KVADDR, &val, sizeof(int),
				"shed_relax_domain_level", FAULT_ON_ERROR);
			fprintf(fp, "%d\n", val);
			break;
		case CS_MEMS:
			readmem(subsys_addr +
				cpuset_offset_table.cpuset_mems_allowed,
				KVADDR, mems_allowed,
				BITS_TO_LONGS(vt->numnodes) * sizeof(long),
				"cpuset_mems", FAULT_ON_ERROR);
			bitmap_scnlistprintf(buf, FILENAME_MAX,
					     mems_allowed, vt->numnodes);
			fprintf(fp, "%s\n", buf);
			break;
		case CS_CPUS:
			readmem(subsys_addr +
				cpuset_offset_table.cpuset_cpus_allowed,
				KVADDR, &cpuset_cpus_addr, sizeof(ulong),
				"cpuset_cpus address", FAULT_ON_ERROR);
			if (!symbol_exists("alloc_cpumask_var"))
				readmem(subsys_addr +
					cpuset_offset_table.cpuset_cpus_allowed,
					KVADDR, &cpus_allowed,
					BITS_TO_LONGS(kt->cpus) * sizeof(long),
					"cpuset_cpus", FAULT_ON_ERROR);
			else
				readmem(cpuset_cpus_addr, KVADDR, cpus_allowed,
					BITS_TO_LONGS(kt->cpus) * sizeof(long),
					"cpuset_cpus", FAULT_ON_ERROR);
			bitmap_scnlistprintf(buf, FILENAME_MAX, cpus_allowed, kt->cpus);
			fprintf(fp, "%s\n", buf);
			break;
		}
	}

	/* second, output the needed param */
	if (test_bit(cpuset_subsys_id, variable_flag)) {
		print_specified_param(cpuset_subsys_id);
		close_tmpfile();
	}
}

static void
print_cpu(struct cgroup_spec *group_list, int subsys_id, ulong subsys_addr)
{
	ulong rt_bandwidth_addr, cfs_bandwidth_addr;
	long i, off;
	uint64_t val;
	char buf[FILENAME_MAX];

	fprintf(fp, "%s:\n", group_list->path);

	/* if some param is specified, first output all into a tmpfile. */
	if (test_bit(cpu_cgroup_subsys_id, variable_flag))
		open_tmpfile();

	rt_bandwidth_addr = subsys_addr + tg_offset_table.tg_rt_bandwidth;
	cfs_bandwidth_addr = subsys_addr + tg_offset_table.tg_cfs_bandwidth;

	for (i = CPU_RT_PERIOD; i < CPU_NR_PARAMS; i++) {
		/*
		 * when cfs_bandwidth or rt_bandwidth is not included,
		 * do not output that item.
		 */
		if ((tg_offset_table.tg_rt_bandwidth == -1 &&
		     (i == CPU_RT_PERIOD || i == CPU_RT_RUNTIME)) ||
		    (tg_offset_table.tg_cfs_bandwidth == -1 &&
		     (i > CPU_RT_RUNTIME && i < CPU_SHARES)))
			continue;

		fprintf(fp, "%s.", group_list->subsys_str);
		/* format string of the parameter */
		memset(buf, 0, FILENAME_MAX);
		strcpy(buf, cpu_params[i]);
		switch (i)
		{
		case CPU_RT_PERIOD:
			if (tg_offset_table.tg_rt_bandwidth == -1)
				continue;
			off = MEMBER_OFFSET("rt_bandwidth", "rt_period");
			cpu_print_bandwidth(rt_bandwidth_addr, off, 1, buf);
			break;
		case CPU_RT_RUNTIME:
			if (tg_offset_table.tg_rt_bandwidth == -1)
				continue;
			off = MEMBER_OFFSET("rt_bandwidth", "rt_runtime");
			cpu_print_bandwidth(rt_bandwidth_addr, off, 0, buf);
			break;
		case CPU_STAT:
			fprintf(fp, "%s: \n", buf);
			if (tg_offset_table.tg_cfs_bandwidth == -1)
				continue;
			cpu_print_stat(cfs_bandwidth_addr);
			break;
		case CPU_CFS_PERIOD:
			if (tg_offset_table.tg_cfs_bandwidth == -1)
				continue;
			off = MEMBER_OFFSET("cfs_bandwidth", "period");
			cpu_print_bandwidth(cfs_bandwidth_addr, off, 1, buf);
			break;
		case CPU_CFS_QUOTA:
			if (tg_offset_table.tg_cfs_bandwidth == -1)
				continue;
			off = MEMBER_OFFSET("cfs_bandwidth", "quota");
			cpu_print_bandwidth(cfs_bandwidth_addr, off, 0, buf);
			break;
		case CPU_SHARES:
			val = (ulong)read_member_long(subsys_addr +
						      tg_offset_table.tg_shares);
			fprintf(fp, "%s: %lu\n", buf, val);
		default:
			break;
		}
	}

	/* second, output the needed param */
	if (test_bit(cpu_cgroup_subsys_id, variable_flag)) {
		print_specified_param(cpu_cgroup_subsys_id);
		close_tmpfile();
	}
}

static void
print_cpuacct(struct cgroup_spec *group_list, int subsys_id, ulong subsys_addr)
{
	int i = 0;
	uint64_t total;
	char buf[FILENAME_MAX];

	fprintf(fp, "%s:\n", group_list->path);

	/* if some param is specified, first output all into a tmpfile. */
	if (test_bit(cpuacct_subsys_id, variable_flag))
		open_tmpfile();

	for (i = CPUACCT_STAT; i < CPUACCT_NR_PARAMS; i++) {
		if (cpuacct_offset_table.cpuacct_cpustat == -1 &&
		    i == CPUACCT_STAT)
			continue;
		/* format string of the parameter */
		memset(buf, 0, FILENAME_MAX);
		strcpy(buf, cpuacct_params[i]);
		fprintf(fp, "%s.%s: ", group_list->subsys_str, buf);
		switch (i)
		{
		case CPUACCT_STAT:
			cpuacct_print_stat(subsys_addr);
			break;
		case CPUACCT_USAGE_PERCPU:
			total = cpuacct_print_usage_percpu(subsys_addr);
			break;
		case CPUACCT_USAGE:
			fprintf(fp, "%lu\n", total);
			break;
		default:
			break;
		}
	}

	/* second, output the needed param */
	if (test_bit(cpuacct_subsys_id, variable_flag)) {
		print_specified_param(cpuacct_subsys_id);
		close_tmpfile();
	}
}

static void
print_hugetlb(struct cgroup_spec *group_list, int subsys_id, ulong subsys_addr)
{
	ulong hugepage_addr;
	uint order;
	uint64_t val;
	char buf[FILENAME_MAX] = {0};

	fprintf(fp, "%s:\n", group_list->path);

	/* if some param is specified, first output all into a tmpfile. */
	if (test_bit(hugetlb_subsys_id, variable_flag))
		open_tmpfile();

	hugepage_addr = subsys_addr + hugetlb_offset_table.hugetlb_hugepage;

	readmem(symbol_value("hstates") + MEMBER_OFFSET("hstate", "order"), KVADDR,
		&order, sizeof(uint), "hstate_order", FAULT_ON_ERROR);
	hugepage_fmt(buf, PAGE_SIZE << order);

	val = read_res_counter(hugepage_addr, MEMBER_OFFSET("res_counter",
				"failcnt"), NULL);
	fprintf(fp, "%s.%s.failcnt: %lu\n", group_list->subsys_str, buf, val);
	val = read_res_counter(hugepage_addr, MEMBER_OFFSET("res_counter",
				"max_usage"), NULL);
	fprintf(fp, "%s.%s.max_usage_in_bytes: %lu\n",
		group_list->subsys_str, buf, val);
	val = read_res_counter(hugepage_addr, MEMBER_OFFSET("res_counter",
				"usage"), NULL);
	fprintf(fp, "%s.%s.usage_in_bytes: %lu\n",
		group_list->subsys_str, buf, val);
	val = read_res_counter(hugepage_addr, MEMBER_OFFSET("res_counter",
				"limit"), NULL);
	fprintf(fp, "%s.%s.limit_in_bytes: %lu\n",
		group_list->subsys_str, buf, val);

	/* second, output the needed param */
	if (test_bit(hugetlb_subsys_id, variable_flag)) {
		print_specified_param(hugetlb_subsys_id);
		close_tmpfile();
	}
}

static void
print_memory(struct cgroup_spec *group_list, int subsys_id, ulong subsys_addr)
{
	ulong mem_res_addr, mem_memsw_addr, mem_kmem_addr,
	      mem_tmem_addr, ptr;
	uint64_t val64 = 0, usage = 0, mem_limit, memsw_limit;
	int i, j, val32 = 0, do_swap_account = 0;
	int64_t lstats[NR_MCS_STAT] = {0}, tstats[NR_MCS_STAT] = {0};
	char buf[FILENAME_MAX];

	fprintf(fp, "%s:\n", group_list->path);

	/* if some param is specified, first output all into a tmpfile. */
	if (test_bit(mem_cgroup_subsys_id, variable_flag))
		open_tmpfile();

	/* check if do swap account */
	if (symbol_exists("do_swap_account"))
		readmem(symbol_value("do_swap_account"), KVADDR, &do_swap_account,
			sizeof(int), "do_swap_account", FAULT_ON_ERROR);

	/* get local memory stat values */
	if ( 0 != get_mem_local_stats(subsys_addr, lstats, do_swap_account)) {
		fprintf(fp, "get parameters failed.\n");
		return;
	}
	/* get total memory stat values */
	if (0 != get_mem_total_stats(subsys_addr, tstats, do_swap_account)) {
		fprintf(fp, "get parameters failed.\n");
		return;
	}

	/* address of memsw, res, kmem and tcp_mem */
	if(memory_offset_table.memory_memsw != -1)
		mem_memsw_addr = subsys_addr + memory_offset_table.memory_memsw;
	else
		mem_memsw_addr = -1;
	if(memory_offset_table.memory_kmem != -1)
		mem_kmem_addr = subsys_addr + memory_offset_table.memory_kmem;
	else
		mem_kmem_addr = -1;
	if(memory_offset_table.memory_tcp_mem != -1)
		mem_tmem_addr = subsys_addr + memory_offset_table.memory_tcp_mem +
				MEMBER_OFFSET("tcp_memcontrol",
					      "tcp_memory_allocated");
	else
		mem_tmem_addr = -1;
	mem_res_addr = subsys_addr + memory_offset_table.memory_res;

	for (i = MEM_TMEM_FAILCNT; i < MEM_NR_PARAMS; i++) {
		/* format string of the parameter */
		memset(buf, 0, FILENAME_MAX);
		sprintf(buf, "%s.%s", group_list->subsys_str,
			memory_params[i]);
		switch (i)
		{
		case MEM_TMEM_FAILCNT:
			read_res_counter(mem_tmem_addr,
					 memory_offset_table.counter_failcnt,
					 buf);
			break;
		case MEM_TMEM_LIMIT:
			read_res_counter(mem_tmem_addr,
					 memory_offset_table.counter_limit,
					 buf);
			break;
		case MEM_TMEM_MAX_USAGE:
			read_res_counter(mem_tmem_addr,
					 memory_offset_table.counter_max_usage,
					 buf);
			break;
		case MEM_TMEM_USAGE:
			read_res_counter(mem_tmem_addr,
					 memory_offset_table.counter_usage,
					 buf);
			break;
		case MEM_KMEM_FAILCNT:
			read_res_counter(mem_kmem_addr,
					 memory_offset_table.counter_failcnt,
					 buf);
			break;
		case MEM_KMEM_LIMIT:
			read_res_counter(mem_kmem_addr,
					 memory_offset_table.counter_limit,
					 buf);
			break;
		case MEM_KMEM_MAX_USAGE:
			read_res_counter(mem_kmem_addr,
					 memory_offset_table.counter_max_usage,
					 buf);
			break;
		case MEM_KMEM_USAGE:
			read_res_counter(mem_kmem_addr,
					 memory_offset_table.counter_usage,
					 buf);
			break;
		case MEM_MEMSW_FAILCNT:
			read_res_counter(mem_memsw_addr,
					 memory_offset_table.counter_failcnt,
					 buf);
			break;
		case MEM_MEMSW_LIMIT:
			read_res_counter(mem_memsw_addr,
					 memory_offset_table.counter_limit,
					 buf);
			break;
		case MEM_MEMSW_MAX_USAGE:
			read_res_counter(mem_memsw_addr,
					 memory_offset_table.counter_max_usage,
					 buf);
			break;
		case MEM_MEMSW_USAGE:
			usage = get_mem_usage(subsys_addr, do_swap_account);
			fprintf(fp, "%s: %lu\n", buf, usage);
			break;
		case MEM_NUMA_STAT:
			/* when numa is not configured, just break; */
			if (!MEMBER_EXISTS("mem_cgroup", "scan_nodes"))
				break;
			fprintf(fp, "%s:\n", buf);
			mem_print_numa_stat(subsys_addr, (uint64_t *)lstats);
			break;
		case MEM_OOM_CTRL:
			if (memory_offset_table.memory_oom_kill_disable != -1) {
				fprintf(fp, "%s:\n", buf);
				mem_print_oom_ctrl(subsys_addr);
			}
			break;
		case MEM_MCAI:
			if (memory_offset_table.memory_mcai != -1) {
				ptr = subsys_addr +
				      memory_offset_table.memory_mcai;
				val64 = (ulong)read_member_long(ptr);
				fprintf(fp, "%s: %lu\n", buf, val64);
			}
			break;
		case MEM_SWAP:
			mem_print_swap(subsys_addr, buf);
			break;
		case MEM_USE_HIER:
			if (memory_offset_table.memory_use_hierarchy != -1) {
				ptr = subsys_addr +
				      memory_offset_table.memory_use_hierarchy;
				val32 = (int)read_member_32(ptr, "use_hier");
				fprintf(fp, "%s: %d\n", buf, val32);
			}
			break;
		case MEM_FORCE_EMPTY:
			/* nothing to print out */
			fprintf(fp, "%s: \n", buf);
			break;
		case MEM_STAT:
			/* output the local stats */
			for (j = 0; j < NR_MCS_STAT; j++) {
				if (j > MCS_ACTIVE_ANON &&
				    MEMBER_EXISTS("mem_cgroup_per_zone",
						  "active_list"))
					break;
				if ((j == MCS_SWAP && !do_swap_account) ||
				     lstats[j] == -1)
					continue;
				if (j == 0)
					fprintf(fp, "%s: ", buf);
				else
					fprintf(fp, "\t");
				fprintf(fp, "%s %ld\n",
					memcg_stat_strings[j].local_name,
					lstats[j]);
			}
			if (memory_offset_table.memory_use_hierarchy != -1) {
				/* output the hierarchical memory limit */
				get_mem_hierarchical_limit(subsys_addr, &mem_limit,
							   &memsw_limit, subsys_id);
				fprintf(fp, "\thierarchical_memory_limit %lu\n",
					mem_limit);
			}
			if (do_swap_account)
				fprintf(fp, "\thierarchical_memsw_limit %lu\n",
					memsw_limit);
			/* output the total stats */
			for (j = 0; j < NR_MCS_STAT; j++) {
				if (j > MCS_ACTIVE_ANON &&
				    MEMBER_EXISTS("mem_cgroup_per_zone",
						  "active_list"))
					break;
				if ((j == MCS_SWAP && !do_swap_account) ||
				     tstats[j] == -1)
					continue;
				fprintf(fp, "\t%s %ld\n",
					memcg_stat_strings[j].total_name,
					tstats[j]);
			}
			break;
		case MEM_FAILCNT:
			read_res_counter(mem_res_addr,
					 memory_offset_table.counter_failcnt,
					 buf);
			break;
		case MEM_SOFT_LIMIT:
			read_res_counter(mem_res_addr,
					 memory_offset_table.counter_soft_limit,
					 buf);
			break;
		case MEM_LIMIT:
			read_res_counter(mem_res_addr,
					 memory_offset_table.counter_limit,
					 buf);
			break;
		case MEM_MAX_USAGE:
			read_res_counter(mem_res_addr,
					 memory_offset_table.counter_max_usage,
					 buf);
			break;
		case MEM_USAGE:
			usage = get_mem_usage(subsys_addr, 0);
			fprintf(fp, "%s: %lu\n", buf, usage);
			break;
		default:
			break;
		}
	}

	/* second, output the needed param */
	if (test_bit(mem_cgroup_subsys_id, variable_flag)) {
		print_specified_param(mem_cgroup_subsys_id);
		close_tmpfile();
	}
}

static void
print_devices(struct cgroup_spec *group_list, int subsys_id, ulong subsys_addr)
{
	ulong whitelist_addr, list_head;
	int behavior = -1;

	fprintf(fp, "%s:\n", group_list->path);

	/* if some param is specified, first output all into a tmpfile. */
	if (test_bit(devices_subsys_id, variable_flag))
		open_tmpfile();

	list_head = subsys_addr + devices_offset_table.devices_whitelist;
	whitelist_addr = (ulong)list_next((void *)list_head, NULL,
					  devices_offset_table.item_list);

	if (devices_offset_table.devices_behavior != -1)
		readmem(subsys_addr + devices_offset_table.devices_behavior,
			KVADDR, &behavior, sizeof(int), "dev_cgroup behavior",
			FAULT_ON_ERROR);

	do {
		if (0 != read_whitelist(group_list, whitelist_addr, behavior)) {
			fprintf(fp, "get parameters failed.\n");
			break;
		}
		fprintf(fp, "%s.deny: \n", group_list->subsys_str);
		fprintf(fp, "%s.allow: \n", group_list->subsys_str);
		whitelist_addr = (ulong)list_next(NULL, (void *)whitelist_addr,
					devices_offset_table.item_list);
	} while (list_head != whitelist_addr +
			      devices_offset_table.item_list);

	/* second, output the needed param */
	if (test_bit(devices_subsys_id, variable_flag)) {
		print_specified_param(devices_subsys_id);
		close_tmpfile();
	}
}

static void
print_freezer(struct cgroup_spec *group_list, int subsys_id, ulong subsys_addr)
{
	int state;
	char buf[FILENAME_MAX] = {0};

	/* there's nothing to be printed for '/' directory */
	if (!get_subsys_parent(subsys_addr, subsys_id))
		return;

	fprintf(fp, "%s:\n", group_list->path);

	/* if some param is specified, first output all into a tmpfile. */
	if (test_bit(freezer_subsys_id, variable_flag))
		open_tmpfile();

	readmem(subsys_addr + freezer_offset_table.freezer_state , KVADDR,
		&state, sizeof(enum freezer_state), "freezer_state",
		FAULT_ON_ERROR);

	switch (state)
	{
	case CGROUP_THAWED:
	case CGROUP_FREEZING:
	case CGROUP_FROZEN:
		sprintf(buf, "%s.state: %s", group_list->subsys_str,
			freezer_state_strs[state]);
		break;
	default:
		fprintf(fp, "wrong value of freezer state.\n");
		return;
	}
	fprintf(fp, "%s\n", buf);

	/* second, output the needed param */
	if (test_bit(freezer_subsys_id, variable_flag)) {
		print_specified_param(freezer_subsys_id);
		close_tmpfile();
	}
}

static void
print_net_cls(struct cgroup_spec *group_list, int subsys_id, ulong subsys_addr)
{
	uint32_t classid;

	fprintf(fp, "%s:\n", group_list->path);

	/* if some param is specified, first output all into a tmpfile. */
	if (test_bit(net_cls_subsys_id, variable_flag))
		open_tmpfile();

	readmem(subsys_addr + cls_offset_table.cls_classid , KVADDR,
		&classid, sizeof(uint32_t), "cls_classid",
		FAULT_ON_ERROR);
	fprintf(fp, "%s.classid: %d\n", group_list->subsys_str, classid);

	/* second, output the needed param */
	if (test_bit(net_cls_subsys_id, variable_flag)) {
		print_specified_param(net_cls_subsys_id);
		close_tmpfile();
	}
}

static void
print_net_prio(struct cgroup_spec *group_list, int subsys_id, ulong subsys_addr)
{
	uint32_t prioidx;

	fprintf(fp, "%s:\n", group_list->path);

	if (netprio_offset_table.netprio_prioidx == -1)
		return;

	/* if some param is specified, first output all into a tmpfile. */
	if (test_bit(net_prio_subsys_id, variable_flag))
		open_tmpfile();

	readmem(subsys_addr + netprio_offset_table.netprio_prioidx , KVADDR,
		&prioidx, sizeof(uint32_t), "netprio_prioidx",
		FAULT_ON_ERROR);
	fprintf(fp, "%s.prioidx: %d\n", group_list->subsys_str, prioidx);

	/* second, output the needed param */
	if (test_bit(net_prio_subsys_id, variable_flag)) {
		print_specified_param(net_prio_subsys_id);
		close_tmpfile();
	}
}

static void
print_blkio(struct cgroup_spec *group_list, int subsys_id, ulong subsys_addr)
{
	int plid, atid;

	fprintf(fp, "%s:\n", group_list->path);

	/* if some param is specified, first output all into a tmpfile. */
	if (test_bit(blkio_subsys_id, variable_flag))
		open_tmpfile();

	if (STRUCT_EXISTS("blkcg")) {
		for (plid = BLKCG_POLICY_THROTL; plid <= BLKCG_POLICY_PROP; plid++) {
			if (plid == BLKCG_POLICY_PROP)
				for (atid = 1; atid <= BLKIO_PROP_io_queued; atid++) {
					read_policy_group(subsys_addr,
							  plid, atid,
							  group_list->subsys_str);
				}
			else
				for (atid = BLKIO_THROTL_read_bps_device;
					atid <= BLKIO_THROTL_io_serviced; atid++) {
					read_policy_group(subsys_addr,
							  plid, atid,
							  group_list->subsys_str);
				}
		}
		/* there should be nothing to be displayed for reset_stats */
		fprintf(fp, "%s.reset_stats: \n", group_list->subsys_str);
	} else if (STRUCT_EXISTS("blkio_cgroup")) {
		for (plid = 0; plid <= BLKIO_POLICY_THROTL; plid++) {
			if (plid == BLKIO_POLICY_PROP)
				for (atid = 1; atid <= BLKIO_PROP_io_queued; atid++) {
					blkio_read_map(subsys_addr, plid, atid,
							group_list->subsys_str);
				}
			else
				for (atid = BLKIO_THROTL_read_bps_device;
					atid <= BLKIO_THROTL_io_serviced; atid++) {
					blkio_read_map(subsys_addr, plid, atid,
							group_list->subsys_str);
				}
		}
		/* there should be nothing to be displayed for reset_stats */
		fprintf(fp, "%s.reset_stats: \n", group_list->subsys_str);
	} else if (blkio_offset_table.blkg_stats == -1)
		/* for kernel version 2.6.33, 2.6.34 */
		blkio_print_param_old(subsys_addr);

	/* second, output the needed param */
	if (test_bit(blkio_subsys_id, variable_flag)) {
		print_specified_param(blkio_subsys_id);
		close_tmpfile();
	}
}

static void
print_cgroup_list(char *cmd_name, struct cgroup_spec *group_list[], int num, int disp_flag)
{
	ulong subsys_addr, css_addr, root_count = 0;
	int subsys_id;
	int i, j, found;
	struct list_head *list_head, *pos;

	list_head = (struct list_head *)symbol_value("roots");
	if (!readmem(symbol_value("root_count"), KVADDR, &root_count,
		     sizeof(int), "root_count", FAULT_ON_ERROR))
		return;

	for (j = 0; j < num; j++) {
		found = 0;
		pos = list_head;
		subsys_id = get_subsys_id(group_list[j]);
		if (subsys_id < 0) {
			fprintf(fp, "Subsys %s does not exist.\n",
				group_list[j]->subsys_str);
			continue;
		}

		for (i = 2; i <= root_count; i++) {
			/* first element is only the head of this list, skip it. */
			if (i == 2) {
				pos = list_next(pos, NULL,
						cgroupfs_root_offset_table.cgroupfs_root_root_list);
			} else {
				pos = list_next(NULL, pos,
						cgroupfs_root_offset_table.cgroupfs_root_root_list);
			}
			if (pos)
				css_addr = cgroupfs_root_offset_table.cgroupfs_root_top_cgroup +
					   cgroup_offset_table.cgroup_subsys + (ulong)pos;
			else
				continue;
			if (!readmem((css_addr + subsys_id * sizeof(ulong)), KVADDR,
				      &subsys_addr, sizeof(ulong), "cgroup subsys",
				      FAULT_ON_ERROR))
				continue;
			if (subsys_addr != 0) {
				found = 1;
				print_cgroup(cmd_name, group_list[j],
					     subsys_id, (ulong)pos,
					     disp_flag);
			}
		}

		if (!found && !disp_flag) {
			fprintf(fp, "%s: Cannot find controller '%s' "
				"in group '%s'\n", cmd_name,
				group_list[j]->subsys_str,
				group_list[j]->path);
		}
	}
}

static inline int
test_bit(int nr, ulong flags)
{
	if (NUM_TO_BIT(nr) & flags)
		return 1;
	return 0;
}

static inline int
bitmap_scnlistprintf(char *buf, unsigned int buflen, ulong *maskp, int nmaskbits)
{
	int len = 0;
	/* current bit is 'cur', most recently seen range is [rbot, rtop] */
	int cur, rbot, rtop, i;
	if (buflen == 0)
		return 0;
	memset(buf, 0, buflen);

	for (i = 0; i < nmaskbits; i++) {
		if (NUM_IN_BITMAP(maskp, i)) {
			rbot = cur = i;
			while (cur < nmaskbits) {
				if (!NUM_IN_BITMAP(maskp, cur + 1)) {
					rtop = cur;
					break;
				}
				cur++;
			}
			len = bitstr_edit(buf, rbot, rtop, len);
			i = cur + 1;
		}
	}
	return len;
}

static void
cgget_offset_table_init(void)
{
	cgroupfs_root_offset_table_init();
	cgroup_offset_table_init();
	cpuset_offset_table_init();
	tg_offset_table_init();
	cpuacct_offset_table_init();
	hugetlb_offset_table_init();
	memory_offset_table_init();
	devices_offset_table_init();
	freezer_offset_table_init();
	cls_offset_table_init();
	blkio_offset_table_init();
	netprio_offset_table_init();
}

static void
cgroupfs_root_offset_table_init()
{
	CGGET_MEMBER_OFFSET_INIT(cgroupfs_root_offset_table, cgroupfs_root_top_cgroup,
				 "cgroupfs_root", "top_cgroup");
	CGGET_MEMBER_OFFSET_INIT(cgroupfs_root_offset_table,
				 cgroupfs_root_number_of_cgroups,
				 "cgroupfs_root", "number_of_cgroups");
	CGGET_MEMBER_OFFSET_INIT(cgroupfs_root_offset_table, cgroupfs_root_root_list,
				 "cgroupfs_root", "root_list");
}

static void
cgroup_offset_table_init()
{
	CGGET_MEMBER_OFFSET_INIT(cgroup_offset_table, cgroup_sibling,
				 "cgroup", "sibling");
	CGGET_MEMBER_OFFSET_INIT(cgroup_offset_table, cgroup_children,
				 "cgroup", "children");
	CGGET_MEMBER_OFFSET_INIT(cgroup_offset_table, cgroup_parent,
				 "cgroup", "parent");
	CGGET_MEMBER_OFFSET_INIT(cgroup_offset_table, cgroup_dentry,
				 "cgroup", "dentry");
	CGGET_MEMBER_OFFSET_INIT(cgroup_offset_table, cgroup_subsys,
				 "cgroup", "subsys");
}

static void
cpuset_offset_table_init()
{
	CGGET_MEMBER_OFFSET_INIT(cpuset_offset_table, cpuset_flags,
				 "cpuset", "flags");
	CGGET_MEMBER_OFFSET_INIT(cpuset_offset_table, cpuset_cpus_allowed,
				 "cpuset", "cpus_allowed");
	CGGET_MEMBER_OFFSET_INIT(cpuset_offset_table, cpuset_mems_allowed,
				 "cpuset", "mems_allowed");
	CGGET_MEMBER_OFFSET_INIT(cpuset_offset_table, cpuset_fmeter,
				 "cpuset", "fmeter");
	CGGET_MEMBER_OFFSET_INIT(cpuset_offset_table, cpuset_shed_relax_domain_level,
				 "cpuset", "relax_domain_level");
}

static void
tg_offset_table_init()
{
	CGGET_MEMBER_OFFSET_INIT(tg_offset_table, tg_shares,
				 "task_group", "shares");
	CGGET_MEMBER_OFFSET_INIT(tg_offset_table, tg_rt_bandwidth,
				 "task_group", "rt_bandwidth");
	CGGET_MEMBER_OFFSET_INIT(tg_offset_table, tg_cfs_bandwidth,
				 "task_group", "cfs_bandwidth");
}

static void
cpuacct_offset_table_init()
{
	CGGET_MEMBER_OFFSET_INIT(cpuacct_offset_table, cpuacct_cpuusage,
				 "cpuacct", "cpuusage");
	CGGET_MEMBER_OFFSET_INIT(cpuacct_offset_table, cpuacct_cpustat,
				 "cpuacct", "cpustat");
}

static void
hugetlb_offset_table_init()
{
	CGGET_MEMBER_OFFSET_INIT(hugetlb_offset_table, hugetlb_hugepage,
				 "hugetlb_cgroup", "hugepage");
}

static void
memory_offset_table_init()
{
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, memory_res,
				 "mem_cgroup", "res");
	if (MEMBER_EXISTS("mem_cgroup", "swappiness"))
		memory_offset_table.memory_memsw = memory_offset_table.memory_res +
						   STRUCT_SIZE("res_counter");
	else
		memory_offset_table.memory_memsw = -1;
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, memory_tcp_mem,
				 "mem_cgroup", "tcp_mem");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, memory_kmem,
				 "mem_cgroup", "kmem");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, memory_info,
				 "mem_cgroup", "info");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, memory_stat,
				 "mem_cgroup", "stat");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, memory_oom_kill_disable,
				 "mem_cgroup", "oom_kill_disable");
	if (MEMBER_EXISTS("mem_cgroup", "under_oom"))
		CGGET_MEMBER_OFFSET_INIT(memory_offset_table, memory_under_oom,
					 "mem_cgroup", "under_oom");
	else
		CGGET_MEMBER_OFFSET_INIT(memory_offset_table, memory_under_oom,
					 "mem_cgroup", "oom_lock");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, memory_mcai,
				 "mem_cgroup", "move_charge_at_immigrate");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, memory_swappiness,
				 "mem_cgroup", "swappiness");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, memory_use_hierarchy,
				 "mem_cgroup", "use_hierarchy");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, counter_usage,
				 "res_counter", "usage");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, counter_max_usage,
				 "res_counter", "max_usage");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, counter_limit,
				 "res_counter", "limit");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, counter_soft_limit,
				 "res_counter", "soft_limit");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, counter_failcnt,
				 "res_counter", "failcnt");
	CGGET_MEMBER_OFFSET_INIT(memory_offset_table, perzone_count,
				 "mem_cgroup_per_zone", "count");
	if (memory_offset_table.perzone_count == -1)
		CGGET_MEMBER_OFFSET_INIT(memory_offset_table, perzone_count,
					 "mem_cgroup_per_zone", "lru_size");
}

static void
devices_offset_table_init()
{
	if (STRUCT_EXISTS("dev_whitelist_item")) {
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, devices_whitelist,
					 "dev_cgroup", "whitelist");
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, devices_behavior,
					 "dev_cgroup", "behavior");
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, item_major,
					 "dev_whitelist_item", "major");
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, item_minor,
					 "dev_whitelist_item", "minor");
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, item_type,
					 "dev_whitelist_item", "type");
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, item_access,
					 "dev_whitelist_item", "access");
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, item_list,
					 "dev_whitelist_item", "list");
	} else if (STRUCT_EXISTS("dev_exception_item")) {
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, devices_whitelist,
					 "dev_cgroup", "exceptions");
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, devices_behavior,
					 "dev_cgroup", "behavior");
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, item_major,
					 "dev_exception_item", "major");
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, item_minor,
					 "dev_exception_item", "minor");
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, item_type,
					 "dev_exception_item", "type");
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, item_access,
					 "dev_exception_item", "access");
		CGGET_MEMBER_OFFSET_INIT(devices_offset_table, item_list,
					 "dev_exception_item", "list");
	}
}

static void
freezer_offset_table_init()
{
	CGGET_MEMBER_OFFSET_INIT(freezer_offset_table, freezer_state,
				 "freezer", "state");
}

static void
cls_offset_table_init()
{
	CGGET_MEMBER_OFFSET_INIT(cls_offset_table, cls_classid,
				 "cgroup_cls_state", "classid");
}

static void
blkio_offset_table_init()
{
	if (STRUCT_EXISTS("blkcg")) {
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkio_blkg_list,
					 "blkcg", "blkg_list");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkg_blkcg_node,
					 "blkcg_gq", "blkcg_node");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkio_weight,
					 "blkcg", "cfq_weight");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkg_pd,
					 "blkcg_gq", "pd");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, cfq_group_stats,
					 "cfq_group", "stats");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, cfqg_stats_service_bytes,
					 "cfqg_stats", "service_bytes");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, cfqg_stats_serviced,
					 "cfqg_stats", "serviced");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, cfqg_stats_merged,
					 "cfqg_stats", "merged");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, cfqg_stats_queued,
					 "cfqg_stats", "queued");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, cfqg_stats_service_time,
					 "cfqg_stats", "service_time");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, cfqg_stats_wait_time,
					 "cfqg_stats", "wait_time");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, cfqg_stats_sectors,
					 "cfqg_stats", "sectors");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, cfqg_stats_time,
					 "cfqg_stats", "time");
	} else {
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkio_blkg_list,
					 "blkio_cgroup", "blkg_list");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkio_policy_list,
					 "blkio_cgroup", "policy_list");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkio_weight,
					 "blkio_cgroup", "weight");
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkg_blkcg_node,
					 "blkio_group", "blkcg_node");
	}
	CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkg_dev,
				 "blkio_group", "dev");
	CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkg_plid,
				 "blkio_group", "plid");
	CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkg_stats,
				 "blkio_group", "stats");
	CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkg_stats_cpu,
				 "blkio_group", "stats_cpu");
	CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkp_dev,
				 "blkio_policy_node", "dev");
	CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkp_plid,
				 "blkio_policy_node", "plid");
	CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkp_fileid,
				 "blkio_policy_node", "fileid");
	if (MEMBER_EXISTS("blkio_policy_node", "val"))
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkp_weight,
					 "blkio_policy_node", "val");
	else
		CGGET_MEMBER_OFFSET_INIT(blkio_offset_table, blkp_weight,
					 "blkio_policy_node", "weight");
}

static void
netprio_offset_table_init()
{
	CGGET_MEMBER_OFFSET_INIT(netprio_offset_table, netprio_prioidx,
				 "cgroup_netprio_state", "prioidx");
}

