/* cacheutils.c - crash extension module for dumping page caches
 *
 * Copyright (C) 2019-2020 NEC Corporation
 *
 * Author: Kazuhito Hagio <k-hagio-ab@nec.com>
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

#define CU_INVALID_MEMBER(X)	(cu_offset_table.X == INVALID_OFFSET)
#define CU_OFFSET_INIT(X, Y, Z)	(cu_offset_table.X = MEMBER_OFFSET(Y, Z))
#define CU_OFFSET(X)	(OFFSET_verify(cu_offset_table.X, \
			(char *)__FUNCTION__, __FILE__, __LINE__, #X))

struct cu_offset_table {
	long inode_i_size;
	long inode_i_mtime;
	long vfsmount_mnt_root;
	long dentry_d_subdirs;
	long dentry_d_child;
};
static struct cu_offset_table cu_offset_table = {};

void cacheutils_init(void);
void cacheutils_fini(void);
void cmd_ccat(void);
void cmd_cls(void);
void cmd_cfind(void);

/* for flags */
#define DUMP_FILE		(0x0001)
#define DUMP_DONT_SEEK		(0x0002)
#define DUMP_DIRECTORY		(0x0004)
#define DUMP_COUNT_ONLY		(0x0008)
#define SHOW_INFO		(0x0010)
#define SHOW_INFO_DIRS		(0x0020)
#define SHOW_INFO_NEG_DENTS	(0x0040)
#define SHOW_INFO_DONT_SORT	(0x0080)
#define SHOW_INFO_LONG		(0x0100)
#define SHOW_INFO_RECURSIVE	(0x0200)
#define SHOW_INFO_SORT_MTIME	(0x0400)
#define FIND_FILES		(0x1000)
#define FIND_COUNT_DENTRY	(0x2000)

/* for env_flags */
#define XARRAY			(0x0001)
#define TIMESPEC64		(0x0002)

/* Output formats */
static char *header_fmt   = "%-16s %-16s %7s %3s %s\n";
static char *header_lfmt  = "%-16s %-16s %7s %3s %6s %11s %-29s %s\n";
static char *dentry_fmt   = "%-16lx %-16lx %7lu %3d %s%s\n";
static char *dentry_lfmt  = "%-16lx %-16lx %7lu %3d %6o %11llu %29s %s%s\n";
static char *negdent_fmt  = "%-16lx %-16s %7s %3s %s\n";
static char *negdent_lfmt = "%-16lx %-16s %7s %3s %6s %11s %-29s %s\n";

static char *count_header_fmt = "%7s %6s %6s %s\n";
static char *count_dentry_fmt = "%7d %6d %6d %s\n";

/* Global variables */
static int flags;
static int env_flags;
static FILE *outfp;
static ulong nr_written, nr_excluded;
static ulonglong out_size;
static struct task_context *tc;
static int total_dentry, total_negdent;
static ulong total_pages;

/* Per-command caches and buffers */
static int mount_count;
static char *mount_data;
static char **mount_path;

static char *dentry_data;
static char *pgbuf;

static int
dump_slot(ulong slot)
{
	physaddr_t phys;
	ulong index, pos, size;

	if (!is_page_ptr(slot, &phys))
		return FALSE;

	if (!readmem(slot + OFFSET(page_index), KVADDR, &index,
	    sizeof(ulong), "page.index", RETURN_ON_ERROR))
		return FALSE;

	/*
	 * If the page content was excluded by makedumpfile,
	 * skip it quietly.
	 */
	if (!readmem(phys, PHYSADDR, pgbuf,
	    PAGESIZE(), "page content", RETURN_ON_ERROR|QUIET)) {
		nr_excluded++;
		return TRUE;
	}

	pos = index * PAGESIZE();
	size = (pos + PAGESIZE()) > out_size ? out_size - pos : PAGESIZE();

	if (!(flags & DUMP_DONT_SEEK))
		fseek(outfp, pos, SEEK_SET);

	if (fwrite(pgbuf, sizeof(char), size, outfp) == size)
		nr_written++;
	else if (errno != EPIPE || CRASHDEBUG(1))
		error(INFO, "%lx: write error: %s\n", slot, strerror(errno));

	return TRUE;
}

static void
set_mtime(char *dst, struct timespec i_mtime)
{
	struct timespec ts[2];

	ts[0].tv_nsec = UTIME_OMIT; /* do not set atime */
	ts[1] = i_mtime;

	if (CRASHDEBUG(1))
		fprintf(fp, "set mtime %s\n", dst);

	if (utimensat(AT_FDCWD, dst, ts, 0) < 0)
		error(INFO, "%s: cannot set mtime: %s\n", dst, strerror(errno));
}

static void
dump_file(char *src, char *dst, ulong i_mapping, ulonglong i_size,
	struct timespec i_mtime)
{
	struct list_pair lp;
	ulong root, count;

	if (dst) {
		if ((outfp = fopen(dst, "w")) == NULL) {
			error(INFO, "%s: cannot open: %s\n",
				dst, strerror(errno));
			return;
		}
		set_tmpfile2(outfp);
	} else
		outfp = fp;

	root = i_mapping + OFFSET(address_space_page_tree);
	lp.value = dump_slot;
	out_size = i_size;
	nr_written = nr_excluded = 0;

	if (env_flags & XARRAY)
		count = do_xarray(root, XARRAY_DUMP_CB, &lp);
	else
		count = do_radix_tree(root, RADIX_TREE_DUMP_CB, &lp);

	if (!(flags & DUMP_DONT_SEEK))
		ftruncate(fileno(outfp), i_size);

	if (outfp != fp) {
		close_tmpfile2();
		set_mtime(dst, i_mtime);
	}

	if (nr_excluded)
		error(INFO, "%s: %lu/%lu pages excluded\n",
			src, nr_excluded, count);
	if (CRASHDEBUG(1))
		error(INFO, "%s: %lu/%lu pages written\n",
			src, nr_written, count);
}

/*
 * NOTE: If alloc is 0, do not strdup() and no need to free(), but
 * need to copy the name if we want to get another dentry's name with
 * this function before consuming the former one.
 */
static char *
get_dentry_name(ulong dentry, char *dentry_buf, int alloc)
{
	ulong d_name_name, d_name_len, d_iname;
	static char name[NAME_MAX+1];
	static char unknown[] = "(unknown)";
	char *name_addr;

	BZERO(name, sizeof(name));

	d_name_name = ULONG(dentry_buf + OFFSET(dentry_d_name)
					+ OFFSET(qstr_name));
	d_name_len = UINT(dentry_buf + OFFSET(dentry_d_name)
					+ OFFSET(qstr_len));
	d_iname = dentry + OFFSET(dentry_d_iname);

	/*
	 * d_name.name and d_iname are guaranteed NUL-terminated.
	 * See d_alloc() in the kernel.
	 */
	if (d_name_name == d_iname)
		name_addr = dentry_buf + OFFSET(dentry_d_iname);
	else if (readmem(d_name_name, KVADDR, name, d_name_len + 1,
			"dentry.d_name.name", RETURN_ON_ERROR))
		name_addr = name;
	else
		name_addr = unknown;

	/*
	 * the number of malloc() via GETBUF() is limited to
	 * MAX_MALLOC_BUFS(2000), so require strdup() here.
	 */
	if (alloc)
		name_addr = strdup(name_addr);

	return name_addr;
}

static int
get_inode_info(ulong inode, uint *i_mode, ulong *i_mapping,
		ulonglong *i_size, ulong *nrpages, struct timespec *i_mtime)
{
	char inode_buf[SIZE(inode)];

	if (!readmem(inode, KVADDR, inode_buf, SIZE(inode),
	    "inode buffer", RETURN_ON_ERROR))
		return FALSE;

	if (i_mode) {
		if (SIZE(umode_t) == SIZEOF_32BIT)
			*i_mode = UINT(inode_buf + OFFSET(inode_i_mode));
		else
			*i_mode = USHORT(inode_buf + OFFSET(inode_i_mode));
	}
	if (i_mapping)
		*i_mapping = ULONG(inode_buf + OFFSET(inode_i_mapping));
	if (i_size)
		*i_size = ULONGLONG(inode_buf + CU_OFFSET(inode_i_size));
	if (nrpages) {
		if (!readmem(*i_mapping + OFFSET(address_space_nrpages),
		    KVADDR, nrpages, sizeof(ulong), "i_mapping.nrpages",
		    RETURN_ON_ERROR))
			return FALSE;
	}
	if (i_mtime) {
		/*
		 * There are some dirty assumptions and kludges here
		 * for some reason I can't explain :)
		 */
		if (env_flags & TIMESPEC64) {
			i_mtime->tv_sec = (long)ULONGLONG(inode_buf
						+ CU_OFFSET(inode_i_mtime));
			i_mtime->tv_nsec = LONG(inode_buf
						+ CU_OFFSET(inode_i_mtime)
						+ sizeof(long long));
		} else {
			i_mtime->tv_sec = LONG(inode_buf
						+ CU_OFFSET(inode_i_mtime));
			i_mtime->tv_nsec = LONG(inode_buf
						+ CU_OFFSET(inode_i_mtime)
						+ sizeof(long));
		}
	}

	return TRUE;
}

static ulong *
get_subdirs_list(int *cntptr, ulong dentry)
{
	struct list_data list_data, *ld;
	ulong d_subdirs, child;

	d_subdirs = dentry + CU_OFFSET(dentry_d_subdirs);

	if (!readmem(d_subdirs, KVADDR, &child, sizeof(ulong),
	    "dentry.d_subdirs", RETURN_ON_ERROR))
		return NULL;

	if (d_subdirs == child)
		return NULL;

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= (LIST_ALLOCATE|RETURN_ON_LIST_ERROR);
	ld->start = child;
	ld->end = d_subdirs;
	ld->list_head_offset = CU_OFFSET(dentry_d_child);
	if (CRASHDEBUG(3))
		ld->flags |= VERBOSE;

	if ((*cntptr = do_list(ld)) == -1)
		return NULL;

	return ld->list_ptr;
}

static char *
get_type_indicator(uint i_mode)
{
	static char c[2] = {'\0', '\0'};

	if (S_ISREG(i_mode)) {
		if (i_mode & (S_IXUSR|S_IXGRP|S_IXOTH))
			*c = '*';
		else
			*c = '\0';
	} else if (S_ISDIR(i_mode))
		*c = '/';
	else if (S_ISLNK(i_mode))
		*c = '@';
	else if (S_ISFIFO(i_mode))
		*c = '|';
	else if (S_ISSOCK(i_mode))
		*c = '=';
	else
		*c = '\0';

	return c;
}

#define TIME_LEN	30
static char *
get_strtime(struct timespec *ts)
{
	static char buf[TIME_LEN];
	static char na[2] = {'-', '\0'};
	size_t ret;

	ret = strftime(buf, TIME_LEN, "%F.%T", localtime(&ts->tv_sec));
	if (!ret)
		return na;

	ret = snprintf(buf + ret, TIME_LEN - ret, ".%09ld", ts->tv_nsec);
	if (ret < 0)
		return na;

	return buf;
}

static ulonglong
byte_to_page(ulonglong i_size)
{
	return (i_size / PAGESIZE()) + ((i_size % PAGESIZE()) ? 1 : 0);
}

static int
calc_cached_percent(ulong nrpages, ulonglong i_size)
{
	if (!i_size)
		return 0;

	return (nrpages * 100) / byte_to_page(i_size);
}

typedef struct {
	ulong dentry;
	char *name;
	ulong inode;
	ulong i_mapping;
	ulonglong i_size;
	ulong nrpages;
	uint i_mode;
	struct timespec i_mtime;
} inode_info_t;

static int
sort_by_name(const void *arg1, const void *arg2)
{
	inode_info_t *p = (inode_info_t *)arg1;
	inode_info_t *q = (inode_info_t *)arg2;

	/*
	 * NOTE: To sort files like ls command, strcoll(3) should be used,
	 * but since the crash utility doesn't call setlocale(LC_ALL, ""),
	 * it doesn't work according to the environment variables.
	 */
	return strcmp(p->name, q->name);
}

static int
sort_by_mtime(const void *arg1, const void *arg2)
{
	struct timespec *p = &((inode_info_t *)arg1)->i_mtime;
	struct timespec *q = &((inode_info_t *)arg2)->i_mtime;

	/* newest first */
	if (p->tv_sec == q->tv_sec)
		return q->tv_nsec - p->tv_nsec;

	return q->tv_sec - p->tv_sec;
}

static void
show_subdirs_info(ulong dentry, char *src)
{
	ulong *list;
	int i, count;
	ulong d, inode, i_mapping, nrpages;
	uint i_mode;
	ulonglong i_size;
	inode_info_t *inode_list, *p;
	struct timespec i_mtime;

	if (!(list = get_subdirs_list(&count, dentry)))
		return;

	inode_list = (inode_info_t *)GETBUF(sizeof(inode_info_t) * count);
	BZERO(inode_list, sizeof(inode_info_t) * count);

	for (i = 0, p = inode_list; i < count; i++) {
		d = list[i];
		if (!readmem(d, KVADDR, dentry_data, SIZE(dentry),
		    "dentry buffer", RETURN_ON_ERROR))
			continue;

		inode = ULONG(dentry_data + OFFSET(dentry_d_inode));
		if (inode && get_inode_info(inode, &i_mode, &i_mapping,
					&i_size, &nrpages, &i_mtime)) {
			p->inode = inode;
			p->i_mapping = i_mapping;
			p->i_size = i_size;
			p->nrpages = nrpages;
			p->i_mode = i_mode;
			p->i_mtime = i_mtime;
		} else {
			p->i_mapping = 0;
			if (!(flags & SHOW_INFO_NEG_DENTS))
				continue;
		}
		p->dentry = d;
		p->name = get_dentry_name(d, dentry_data, 1);
		p++;
	}
	count = p - inode_list;

	if (!(flags & SHOW_INFO_DONT_SORT))
		qsort(inode_list, count, sizeof(inode_info_t),
			(flags & SHOW_INFO_SORT_MTIME) ?
				sort_by_mtime : sort_by_name);

	for (i = 0, p = inode_list; i < count; i++, p++) {
		if (p->i_mapping) {
			int pct = calc_cached_percent(p->nrpages, p->i_size);

			if (flags & SHOW_INFO_LONG) {
				fprintf(fp, dentry_lfmt, p->dentry, p->inode,
					p->nrpages, pct, p->i_mode, p->i_size,
					get_strtime(&p->i_mtime), p->name,
					get_type_indicator(p->i_mode));
				if (CRASHDEBUG(1))
					fprintf(fp,
				    "  i_mapping:%-16lx i_mtime:%ld.%09ld\n",
						p->i_mapping, p->i_mtime.tv_sec,
						p->i_mtime.tv_nsec);
			} else {
				fprintf(fp, dentry_fmt, p->dentry, p->inode,
					p->nrpages, pct, p->name,
					get_type_indicator(p->i_mode));
				if (CRASHDEBUG(1))
					fprintf(fp, "  i_mapping:%-16lx\n",
						p->i_mapping);
			}

		} else if (flags & SHOW_INFO_NEG_DENTS) {
			if (flags & SHOW_INFO_LONG)
				fprintf(fp, negdent_lfmt, p->dentry, "-",
					"-", "-", "-", "-", "-", p->name);
			else
				fprintf(fp, negdent_fmt, p->dentry, "-",
					"-", "-", p->name);
		}

		if (!(flags & SHOW_INFO_RECURSIVE))
			free(p->name);	/* still needed below */
	}

	if (flags & SHOW_INFO_RECURSIVE) {
		char path[PATH_MAX];
		char *slash = (src[1] == '\0') ? "" : "/";

		for (i = 0, p = inode_list; i < count; i++, p++) {
			if (i_mapping && S_ISDIR(p->i_mode)) {
				snprintf(path, PATH_MAX, "%s%s%s",
					src, slash, p->name);
				fprintf(fp, "\n%s:\n", path);

				show_subdirs_info(p->dentry, path);
			}

			free(p->name);
		}
	}

	FREEBUF(inode_list);
	FREEBUF(list);
}

/*
 * If remaining_path is NULL, search for a mount point that matches exactly
 * with the path.
 */
static ulong
get_mntpoint_dentry(char *path, char **remaining_path)
{
	ulong *mount_list;
	int i;
	size_t len;
	char *mount_buf, *path_buf, *path_start, *slash_pos;
	char buf[PATH_MAX], *bufp = buf;
	ulong root, parent, mountp;
	long size;

	size = VALID_STRUCT(mount) ? SIZE(mount) : SIZE(vfsmount);
	if (!mount_data) {
		mount_list = get_mount_list(&mount_count, tc);
		mount_data = GETBUF(size * mount_count);
		mount_path = (char **)GETBUF(sizeof(char *) * mount_count);

		for (i = 0; i < mount_count; i++) {
			if (!readmem(mount_list[i], KVADDR, mount_data +
			    (size * i), size, "(vfs)mount buffer",
			    RETURN_ON_ERROR)) {
				FREEBUF(mount_list);
				goto bail_out;
			}

			mount_buf = mount_data + (size * i);

			if (VALID_STRUCT(mount)) {
				parent = ULONG(mount_buf +
					OFFSET(mount_mnt_parent));
				mountp = ULONG(mount_buf +
					OFFSET(mount_mnt_mountpoint));
				get_pathname(mountp, bufp, PATH_MAX, 1,
					parent + OFFSET(mount_mnt));
			} else {
				parent = ULONG(mount_buf +
					OFFSET(vfsmount_mnt_parent));
				mountp = ULONG(mount_buf +
					OFFSET(vfsmount_mnt_mountpoint));
				get_pathname(mountp, bufp, PATH_MAX, 1,
					parent);
			}

			len = strnlen(bufp, PATH_MAX);
			mount_path[i] = GETBUF(len + 1);
			memcpy(mount_path[i], bufp, len + 1);
		}
		FREEBUF(mount_list);
	}

	len = strlen(path);
	path_buf = GETBUF(len + 1);
	memcpy(path_buf, path, len + 1);

	path_start = path + len;

	root = 0;
	while (TRUE) {
		for (i = 0; i < mount_count; i++) {
			mount_buf = mount_data + (size * i);
			bufp = mount_path[i];

			if (CRASHDEBUG(2))
				error(INFO, "path:%s PATHEQ:%d mntp:%s\n",
					path_buf, PATHEQ(path_buf, bufp), bufp);

			if (PATHEQ(path_buf, bufp)) {
				if (VALID_STRUCT(mount))
					root = ULONG(mount_buf +
						OFFSET(mount_mnt) +
						CU_OFFSET(vfsmount_mnt_root));
				else
					root = ULONG(mount_buf +
						CU_OFFSET(vfsmount_mnt_root));
				/*
				 * Probably the last one will be what we want,
				 * so don't break here.
				 */
			}
		}
		if (root)
			break;

		if (!remaining_path) /* exact match for cfind */
			break;

		if ((slash_pos = strrchr(path_buf, '/')) == NULL)
			break;

		path_start = path + (slash_pos - path_buf) + 1;

		if (slash_pos != path_buf)
			*slash_pos = '\0';
		else if (slash_pos == path_buf && *(slash_pos+1) != '\0')
			*(slash_pos+1) = '\0';
		else
			break;
	}
	if (CRASHDEBUG(2))
		error(INFO, "root_dentry:%lx path_start:%s\n",
			root, path_start);

	if (root && remaining_path)
		*remaining_path = path_start;

	FREEBUF(path_buf);
bail_out:
	return root;
}

static ulong
path_to_dentry(char *path, ulong *inode)
{
	int i, count;
	ulong *subdirs_list, root, d, dentry;
	char *path_buf, *dentry_buf, *slash_pos, *path_start, *name;
	size_t len;

	root = get_mntpoint_dentry(path, &path_start);
	if (!root) {
		error(INFO, "%s: mount point not found\n", path);
		return 0;
	}

	len = strlen(path_start);
	path_buf = GETBUF(len + 1);
	memcpy(path_buf, path_start, len + 1);
	path_start = path_buf;

	dentry = 0;
	dentry_buf = GETBUF(SIZE(dentry));
	d = root;

	while (strlen(path_start)) {
		if ((slash_pos = strchr(path_start, '/')))
			*slash_pos = '\0';

		if (!(subdirs_list = get_subdirs_list(&count, d)))
			goto not_found;

		for (i = 0; i < count; i++) {
			d = subdirs_list[i];
			if (!readmem(d, KVADDR, dentry_buf, SIZE(dentry),
			    "dentry buffer", RETURN_ON_ERROR))
				continue;

			/* no alloc */
			name = get_dentry_name(d, dentry_buf, 0);

			if (CRASHDEBUG(2))
				error(INFO, "q:%s %3d: d:%lx name:%s\n",
					path_start, i, d, name);

			if (STREQ(path_start, name)) {
				if (slash_pos)
					break;
				else {
					FREEBUF(subdirs_list);
					goto found;
				}
			}
		}
		FREEBUF(subdirs_list);

		/* no such dentry */
		if (i == count)
			goto not_found;

		if (slash_pos)
			path_start = slash_pos + 1;
	}
	/* the path ends with '/' */
	if (!readmem(d, KVADDR, dentry_buf, SIZE(dentry),
	    "dentry buffer", RETURN_ON_ERROR))
		goto not_found;

found:
	dentry = d;
	if (inode)
		*inode = ULONG(dentry_buf + OFFSET(dentry_d_inode));

not_found:
	FREEBUF(dentry_buf);
	FREEBUF(path_buf);

	return dentry;
}

typedef struct {
	ulong dentry;
	char *name;
	uint i_mode;
} dentry_info_t;

static void
recursive_list_dir(char *arg, ulong pdentry, uint pi_mode)
{
	ulong *list;
	int i, count, nr_negdents = 0;
	char *slash;
	ulong d, inode;
	uint i_mode;
	dentry_info_t *dentry_list, *p;

	if (!(flags & FIND_COUNT_DENTRY))
		fprintf(fp, "%16lx %s\n", pdentry, arg);

	if (!S_ISDIR(pi_mode))
		return;

	if (!(list = get_subdirs_list(&count, pdentry))) {
		if (flags & FIND_COUNT_DENTRY)
			fprintf(fp, count_dentry_fmt, 0, 0, 0, arg);
		return;
	}

	slash = (arg[1] == '\0') ? "" : "/";
	dentry_list = (dentry_info_t *)GETBUF(sizeof(dentry_info_t) * count);

	for (i = 0, p = dentry_list; i < count; i++) {
		d = list[i];
		readmem(d, KVADDR, dentry_data, SIZE(dentry),
			"dentry", FAULT_ON_ERROR);

		inode = ULONG(dentry_data + OFFSET(dentry_d_inode));
		if (inode && get_inode_info(inode, &i_mode, NULL, NULL, NULL,
					NULL))
			p->i_mode = i_mode;
		else {
			if (flags & FIND_COUNT_DENTRY) {
				nr_negdents++;
				continue;
			}
			if (!(flags & SHOW_INFO_NEG_DENTS))
				continue;
		}
		p->dentry = d;
		p->name = get_dentry_name(d, dentry_data, 1);
		p++;
	}

	if (flags & FIND_COUNT_DENTRY) {
		fprintf(fp, count_dentry_fmt,
			count, count - nr_negdents, nr_negdents, arg);
		total_dentry += count;
		total_negdent += nr_negdents;
	}

	count = p - dentry_list;

	for (i = 0, p = dentry_list; i < count; i++, p++) {
		if (S_ISDIR(p->i_mode)) {
			char path[PATH_MAX];
			snprintf(path, PATH_MAX, "%s%s%s", arg, slash, p->name);

			d = get_mntpoint_dentry(path, NULL);
			if (d) {
				readmem(d, KVADDR, dentry_data, SIZE(dentry),
					"dentry", FAULT_ON_ERROR);

				inode = ULONG(dentry_data +
						OFFSET(dentry_d_inode));
				if (inode && get_inode_info(inode, &i_mode,
						NULL, NULL, NULL, NULL))
					recursive_list_dir(path, d, i_mode);
				else
					error(INFO, "%s: invalid inode\n", path);
			} else /* normal directory */
				recursive_list_dir(path, p->dentry, p->i_mode);

		} else if (!(flags & FIND_COUNT_DENTRY))
			fprintf(fp, "%16lx %s%s%s\n",
				p->dentry, arg, slash, p->name);

		free(p->name);
	}

	FREEBUF(dentry_list);
	FREEBUF(list);
}

#define MODE_RWX (S_IRWXU|S_IRWXG|S_IRWXO)

static void
recursive_dump_dir(char *src, char *dst, ulong pdentry, struct timespec pmtime)
{
	ulong *list;
	int i, count;
	char *slash, *name;
	ulong d, dentry, inode, i_mapping, nrpages;
	ulonglong i_size;
	uint i_mode;
	char srcpath[PATH_MAX], dstpath[PATH_MAX];
	struct timespec i_mtime;

	if (!(flags & DUMP_COUNT_ONLY)) {
		if (CRASHDEBUG(1))
			fprintf(fp, "create dir  %s\n", dst);

		if (mkdir(dst, MODE_RWX) < 0) {
			error(INFO, "%s: cannot create directory: %s\n",
				dst, strerror(errno));
			return;
		}
	}

	if (!(list = get_subdirs_list(&count, pdentry)))
		goto no_subdirs;

	slash = (src[1] == '\0') ? "" : "/";

	for (i = 0; i < count; i++) {
		d = dentry = list[i];
		readmem(d, KVADDR, dentry_data, SIZE(dentry), "dentry",
			FAULT_ON_ERROR);

		name = get_dentry_name(d, dentry_data, 0); /* no alloc */
		inode = ULONG(dentry_data + OFFSET(dentry_d_inode));

		if (!inode || !get_inode_info(inode, &i_mode, &i_mapping,
					&i_size, &nrpages, &i_mtime))
			continue;

		snprintf(srcpath, PATH_MAX, "%s%s%s", src, slash, name);
		snprintf(dstpath, PATH_MAX, "%s/%s", dst, name);

		if (S_ISDIR(i_mode)) {
			d = get_mntpoint_dentry(srcpath, NULL);
			if (d) {
				readmem(d, KVADDR, dentry_data, SIZE(dentry),
					"dentry", FAULT_ON_ERROR);

				inode = ULONG(dentry_data +
						OFFSET(dentry_d_inode));
				if (!inode || !get_inode_info(inode, &i_mode,
						NULL, NULL, NULL, NULL)) {
					error(INFO, "%s: invalid inode\n",
						srcpath);
					continue;
				}
				dentry = d;
			}
			recursive_dump_dir(srcpath, dstpath, dentry, i_mtime);

		} else if (S_ISREG(i_mode)) {
			if (!nrpages) {
				if (CRASHDEBUG(1))
					fprintf(fp, "%s: no cached pages\n",
						srcpath);
				continue;
			} else if (flags & DUMP_COUNT_ONLY) {
				total_pages += nrpages;
				continue;
			}

			if (CRASHDEBUG(1))
				fprintf(fp, "create file %s\n", dstpath);

			dump_file(srcpath, dstpath, i_mapping, i_size, i_mtime);
			total_pages += nr_written;
		}
	}

	FREEBUF(list);

no_subdirs:
	if (!(flags & DUMP_COUNT_ONLY)) {
		set_mtime(dst, pmtime);
	}
}

/*
 * Currently just squeeze a series of slashes into a slash,
 * and remove the last slash.
 */
static void
normalize_path(char *path)
{
	char *s, *d;

	if (!path || *path == '\0')
		return;

	s = d = path;
	while (*s) {
		if (*s == '/' && *(s+1) == '/') {
			s++;
			continue;
		}
		*d++ = *s++;
	}
	*d = '\0';

	d--;
	if (d != path && *d == '/')
		*d = '\0';
}

static void
do_command(char *src, char *dst)
{
	ulong inode, i_mapping, dentry, nrpages;
	ulonglong i_size;
	uint i_mode;
	struct timespec i_mtime;

	inode = dentry = 0;
	if (flags & DUMP_FILE)
		inode = htol(src, RETURN_ON_ERROR|QUIET, NULL);

	if (inode == 0 || inode == BADADDR) {
		if (src[0] != '/')
			cmd_usage(pc->curcmd, SYNOPSIS);

		normalize_path(src);

		dentry = path_to_dentry(src, &inode);
		if (!dentry) {
			error(INFO, "%s: not found in dentry cache\n", src);
			return;
		} else if (!inode) {
			error(INFO, "%s: negative dentry\n", src);
			return;
		}
	}

	if (!get_inode_info(inode, &i_mode, &i_mapping, &i_size, &nrpages,
				&i_mtime))
		return;

	if (flags & DUMP_FILE) {
		if (!S_ISREG(i_mode)) {
			error(INFO, "%s: not regular file\n", src);
			return;
		} else if (!nrpages) {
			error(INFO, "%s: no cached pages\n", src);
			return;
		} else if (flags & DUMP_COUNT_ONLY) {
			fprintf(fp, "Estimated %lu pages (%lu KiB)\n",
				nrpages, PAGESIZE() * nrpages >> 10);
			return;
		}

		dump_file(src, dst, i_mapping, i_size, i_mtime);

	} else if (flags & DUMP_DIRECTORY) {
		if (!S_ISDIR(i_mode)) {
			error(INFO, "%s: not directory\n", src);
			return;
		}

		if (flags & DUMP_COUNT_ONLY)
			fprintf(fp, "Estimating %s...\n", src);
		else
			fprintf(fp, "Extracting %s to %s...\n", src, dst);

		total_pages = 0;

		recursive_dump_dir(src, dst, dentry, i_mtime);

		fprintf(fp, "Total %lu pages (%lu KiB)\n",
			total_pages, PAGESIZE() * total_pages >> 10);

	} else if (flags & SHOW_INFO) {
		int pct = calc_cached_percent(nrpages, i_size);
		char *name = src;

		if (S_ISDIR(i_mode) && !(flags & SHOW_INFO_DIRS))
			name = ".";

		if (flags & SHOW_INFO_LONG) {
			fprintf(fp, header_lfmt, "DENTRY", "INODE", "NRPAGES",
				"%", "MODE", "SIZE", "MTIME", "PATH");
			fprintf(fp, dentry_lfmt, dentry, inode, nrpages,
				pct, i_mode, i_size, get_strtime(&i_mtime),
				name, get_type_indicator(i_mode));
			if (CRASHDEBUG(1))
				fprintf(fp,
				    "  i_mapping:%-16lx i_mtime:%ld.%09ld\n",
					i_mapping, i_mtime.tv_sec,
					i_mtime.tv_nsec);
		} else {
			fprintf(fp, header_fmt, "DENTRY", "INODE", "NRPAGES",
				"%", "PATH");
			fprintf(fp, dentry_fmt, dentry, inode, nrpages,
				pct, name, get_type_indicator(i_mode));
			if (CRASHDEBUG(1))
				fprintf(fp, "  i_mapping:%-16lx\n", i_mapping);
		}

		if (S_ISDIR(i_mode) && !(flags & SHOW_INFO_DIRS))
			show_subdirs_info(dentry, src);

	} else if (flags & FIND_FILES) {
		if (flags & FIND_COUNT_DENTRY) {
			fprintf(fp, count_header_fmt,
				"TOTAL", "DENTRY", "N_DENT", "PATH");
			total_dentry = total_negdent = 0;
		}

		recursive_list_dir(src, dentry, i_mode);

		if (flags & FIND_COUNT_DENTRY) {
			fprintf(fp, count_dentry_fmt,
				total_dentry, total_dentry - total_negdent,
				total_negdent, "TOTAL");
		}
	}
}

static void
init_cache(void) {
	/* In case that the last command was interrupted. */
	if (mount_data) {
		mount_data = NULL;
		mount_path = NULL;
		mount_count = 0;
	}
	dentry_data = GETBUF(SIZE(dentry));
	pgbuf = GETBUF(PAGESIZE());
}

static void
clear_cache(void)
{
	int i;

	if (mount_data) {
		FREEBUF(mount_data);
		for (i = 0; i < mount_count; i++) {
			FREEBUF(mount_path[i]);
		}
		FREEBUF(mount_path);
		mount_data = NULL;
		mount_path = NULL;
		mount_count = 0;
	}
	FREEBUF(dentry_data);
	FREEBUF(pgbuf);
}

static void
set_default_task_context(void)
{
	ulong pid = 0;

	while ((tc = pid_to_context(pid)) == NULL)
		pid++;
}

void
cmd_ccat(void)
{
	int c;
	char *src, *dst;
	ulong value;

	flags = DUMP_FILE;
	tc = NULL;

	while ((c = getopt(argcnt, args, "cdn:S")) != EOF) {
		switch(c) {
		case 'c':
			flags |= DUMP_COUNT_ONLY;
			break;
		case 'd':
			flags &= ~DUMP_FILE; /* exclusive */
			flags |= DUMP_DIRECTORY;
			break;
		case 'n':
			switch (str_to_context(optarg, &value, &tc)) {
			case STR_PID:
			case STR_TASK:
				break;
			case STR_INVALID:
				error(FATAL, "invalid task or pid value: %s\n",
					optarg);
				break;
			}
			break;
		case 'S':
			flags |= DUMP_DONT_SEEK;
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	src = args[optind++];
	dst = args[optind];

	if (dst) {
		if (dst[0] == '\0')
			cmd_usage(pc->curcmd, SYNOPSIS);

		normalize_path(dst);

		if (access(dst, F_OK) == 0) {
			error(INFO, "%s: %s\n", dst, strerror(EEXIST));
			return;
		}
	} else if (flags & DUMP_DIRECTORY)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!tc)
		set_default_task_context();

	init_cache();

	do_command(src, dst);

	clear_cache();
}

char *help_ccat[] = {
"ccat",				/* command name */
"dump page caches",		/* short description */
"   [-cS] [-n pid|task] abspath|inode [outfile]\n"
"  ccat -d [-cS] [-n pid|task] abspath outdir",
				/* argument synopsis, or " " if none */
"  This command dumps the page caches of a specified inode or path like",
"  \"cat\" command.",
"",
"       -c  only count the total pages to be written without creating any",
"           files or directories.",
"       -d  extract a directory and its contents to outdir.",
"       -S  do not fseek() and ftruncate() to outfile in order to",
"           create a non-sparse file.",
"    inode  a hexadecimal inode pointer.",
"  abspath  the absolute path of a file (or directory with the -d option).",
"  outfile  a file path to be written. If a file already exists there,",
"           the command fails.",
"   outdir  a directory path to be created by the -d option.",
"",
"  For kernels supporting mount namespaces, the -n option may be used to",
"  specify a task that has the target namespace:",
"",
"    -n pid   a process PID.",
"    -n task  a hexadecimal task_struct pointer.",
"",
"EXAMPLE",
"  Dump the existing page caches of the \"/var/log/messages\" file:",
"",
"    %s> ccat /var/log/messages",
"    Sep 16 03:13:01 host systemd: Started Session 559694 of user root.",
"    Sep 16 03:13:01 host systemd: Starting Session 559694 of user root.",
"    Sep 16 03:13:39 host dnsmasq-dhcp[24341]: DHCPREQUEST(virbr0) 192.168",
"    Sep 16 03:13:39 host dnsmasq-dhcp[24341]: DHCPACK(virbr0) 192.168.122",
"    ...",
"",
"  Restore the size and data offset of the \"messages\" file as well to the",
"  \"messages.sparse\" file even if some of its page caches don't exist, so",
"  it could become sparse:",
"",
"    %s> ccat /var/log/messages messages.sparse",
"",
"  Create the non-sparse \"messages.non-sparse\" file:",
"",
"    %s> ccat -S /var/log/messages messages.non-sparse",
"",
"  NOTE: Redirecting to a file will also works, but it can contain crash's",
"  messages, so specifying an outfile is recommended for restoring a file.",
"",
"  Extract the \"/var/log\" directory and its contents to the new \"/tmp/log\"",
"  directory with one command:",
"",
"    %s> ccat -d /var/log /tmp/log",
"    Extracting /var/log to /tmp/log...",
"    Total 127034 pages (508136 KiB)",
"",
"  Count the total pages to be written in advance without creating any",
"  files or directories:",
"",
"    %s> ccat -c -d /var/log /tmp/log",
"    Estimating /var/log...",
"    Total 127034 pages (508136 KiB)",
NULL
};

void
cmd_cls(void)
{
	int c;
	ulong value;

	flags = SHOW_INFO;
	tc = NULL;

	while ((c = getopt(argcnt, args, "adln:RtU")) != EOF) {
		switch(c) {
		case 'a':
			flags |= SHOW_INFO_NEG_DENTS;
			break;
		case 'd':
			flags |= SHOW_INFO_DIRS;
			break;
		case 'l':
			flags |= SHOW_INFO_LONG;
			break;
		case 'n':
			switch (str_to_context(optarg, &value, &tc)) {
			case STR_PID:
			case STR_TASK:
				break;
			case STR_INVALID:
				error(FATAL, "invalid task or pid value: %s\n",
					optarg);
				break;
			}
			break;
		case 'R':
			flags |= SHOW_INFO_RECURSIVE;
			break;
		case 't':
			flags |= SHOW_INFO_SORT_MTIME;
			break;
		case 'U':
			flags |= SHOW_INFO_DONT_SORT;
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!tc)
		set_default_task_context();

	init_cache();

	do_command(args[optind++], NULL);

	while (args[optind]) {
		fprintf(fp, "\n");
		do_command(args[optind++], NULL);
	}

	clear_cache();
}

char *help_cls[] = {
"cls",				/* command name */
"list dentry and inode caches",	/* short description */
"[-adlRU] [-n pid|task] abspath...",	/* argument synopsis, or " " if none */

"  This command displays the addresses of dentry, inode and nrpages of a",
"  specified absolute path and its subdirs if they exist in dentry cache.",
"",
"    -a  also display negative dentries in the subdirs list.",
"    -d  display the directory itself only, without its contents.",
"    -l  use a long format to display mode, size and mtime additionally.",
"    -R  display subdirs recursively.",
"    -t  sort subdirs by modification time, newest first.",
"    -U  do not sort, list dentries in directory order.",
"",
"  For kernels supporting mount namespaces, the -n option may be used to",
"  specify a task that has the target namespace:",
"",
"    -n pid   a process PID.",
"    -n task  a hexadecimal task_struct pointer.",
"",
"EXAMPLE",
"  Display the \"/var/log/messages\" regular file's information:",
"",
"    %s> cls /var/log/messages",
"    DENTRY           INODE            NRPAGES   % PATH",
"    ffff9c0c28fda480 ffff9c0c22c675b8     220 100 /var/log/messages",
"",
"  The '\%' column shows the percentage of cached pages in the file.",
"",
"  Display the \"/var/log\" directory and its subdirs information:",
"",
"    %s> cls /var/log",
"    DENTRY           INODE            NRPAGES   % PATH",
"    ffff9c0c3eabe300 ffff9c0c3e875b78       0   0 ./",
"    ffff9c0c16a22900 ffff9c0c16ada2f8       0   0 anaconda/",
"    ffff9c0c37611000 ffff9c0c3759f5b8       0   0 audit/",
"    ffff9c0c375ccc00 ffff9c0c3761c8b8       1 100 btmp",
"    ffff9c0c28fda240 ffff9c0c22c713f8       6 100 cron",
"    ffff9c0c3eb7f180 ffff9c0bfd402a78      36   7 dnf.librepo.log",
"    ...",
"",
"  In addition to the same information, display their mode, size and mtime:",
"",
"    %s> cls -l /var/log",
"    DENTRY           INODE            NRPAGES   %   MODE        SIZE MTIME                         PATH",
"    ffff9c0c3eabe300 ffff9c0c3e875b78       0   0  40755        4096 2018-11-25.03:39:01.479315763 ./",
"    ffff9c0c16a22900 ffff9c0c16ada2f8       0   0  40755         250 2018-03-21.13:18:38.816000000 anaconda/",
"    ffff9c0c37611000 ffff9c0c3759f5b8       0   0  40700          80 2018-10-25.19:02:13.968692776 audit/",
"    ffff9c0c375ccc00 ffff9c0c3761c8b8       1 100 100660         384 2018-11-28.16:39:34.538315763 btmp",
"    ffff9c0c28fda240 ffff9c0c22c713f8       6 100 100600       23435 2018-11-28.16:01:01.667315763 cron",
"    ffff9c0c3eb7f180 ffff9c0bfd402a78      36   7 100600     1921580 2018-11-28.16:41:24.073315763 dnf.librepo.log",
"    ...",
"",
"  Display the \"/var/log\" directory itself only:",
"",
"    %s> cls -d /var/log",
"    DENTRY           INODE            NRPAGES   % PATH",
"    ffff9c0c3eabe300 ffff9c0c3e875b78       0   0 /var/log/",
"",
"  Display the \"/var/log\" directory and its subdirs recursively:",
"",
"    crash> cls -R /var/log",
"    DENTRY           INODE            NRPAGES   % PATH",
"    ffff9c0c3eabe300 ffff9c0c3e875b78       0   0 ./",
"    ffff9c0c16a22900 ffff9c0c16ada2f8       0   0 anaconda/",
"    ffff9c0c37611000 ffff9c0c3759f5b8       0   0 audit/",
"    ...",
"",
"    /var/log/anaconda:",
"",
"    /var/log/audit:",
"    ffff9c0c37582e40 ffff9c0c3759d038     208  19 audit.log",
"    ...",
NULL
};

void
cmd_cfind(void)
{
	int c;
	ulong value;

	flags = FIND_FILES;
	tc = NULL;

	while ((c = getopt(argcnt, args, "acn:")) != EOF) {
		switch(c) {
		case 'a':
			flags |= SHOW_INFO_NEG_DENTS;
			break;
		case 'c':
			flags |= FIND_COUNT_DENTRY;
			break;
		case 'n':
			switch (str_to_context(optarg, &value, &tc)) {
			case STR_PID:
			case STR_TASK:
				break;
			case STR_INVALID:
				error(FATAL, "invalid task or pid value: %s\n",
					optarg);
				break;
			}
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!tc)
		set_default_task_context();

	init_cache();

	do_command(args[optind], NULL);

	clear_cache();
}

char *help_cfind[] = {
"cfind",
"search for files in a directory hierarchy",
"[-ac] [-n pid|task] abspath",

"  This command searches for files in a directory hierarchy across mounted",
"  file systems like a \"find\" command.",
"",
"    -a  also display negative dentries.",
"    -c  count dentries in each directory.",
"",
"  For kernels supporting mount namespaces, the -n option may be used to",
"  specify a task that has the target namespace:",
"",
"    -n pid   a process PID.",
"    -n task  a hexadecimal task_struct pointer.",
"",
"EXAMPLE",
"  Search for \"messages\" files through the root file system with the grep",
"  command:",
"",
"    %s> cfind / | grep messages",
"    ffff88010113be00 /var/log/messages",
"    ffff880449f86b40 /usr/lib/python2.7/site-packages/babel/messages",
"",
"  Count dentries in the /boot directory and its subdirectories:",
"",
"    %s> cfind -c /boot",
"      TOTAL DENTRY N_DENT PATH",
"         18     12      6 /boot",
"          8      6      2 /boot/grub2",
"         34     34      0 /boot/grub2/locale",
"        268    268      0 /boot/grub2/i386-pc",
"          1      1      0 /boot/grub2/fonts",
"          1      1      0 /boot/efi",
"          2      1      1 /boot/efi/EFI",
"          3      0      3 /boot/efi/EFI/redhat",
"        335    323     12 TOTAL",
NULL
};

static struct command_table_entry command_table[] = {
	{ "ccat", cmd_ccat, help_ccat, 0},
	{ "cls", cmd_cls, help_cls, 0},
	{ "cfind", cmd_cfind, help_cfind, 0},
	{ NULL },
};

#define DL_EXCLUDE_CACHE_PRI	(0x04)

void __attribute__((constructor))
cacheutils_init(void)
{
	int dump_level;

	register_extension(command_table);

	CU_OFFSET_INIT(inode_i_size, "inode", "i_size");
	CU_OFFSET_INIT(inode_i_mtime, "inode", "i_mtime");
	CU_OFFSET_INIT(vfsmount_mnt_root, "vfsmount", "mnt_root");
	CU_OFFSET_INIT(dentry_d_subdirs, "dentry", "d_subdirs");
	CU_OFFSET_INIT(dentry_d_child, "dentry", "d_child");
	if (CU_INVALID_MEMBER(dentry_d_child))	/* RHEL7 and older */
		CU_OFFSET_INIT(dentry_d_child, "dentry", "d_u");

	if (MEMBER_EXISTS("address_space", "i_pages") &&
	    STREQ(MEMBER_TYPE_NAME("address_space", "i_pages"), "xarray"))
		env_flags |= XARRAY;

	if (MEMBER_EXISTS("inode", "i_mtime") &&
	    STREQ(MEMBER_TYPE_NAME("inode", "i_mtime"), "timespec64"))
		env_flags |= TIMESPEC64;

	if (CRASHDEBUG(1)) {
		fprintf(fp, "          env_flags: 0x%x", env_flags);
		fprintf(fp, " %s", (env_flags & XARRAY) ?
					"XARRAY" : "RADIX_TREE");
		fprintf(fp, " %s", (env_flags & TIMESPEC64) ?
					"TIMESPEC64" : "TIMESPEC");
		fprintf(fp, "\n");

		fprintf(fp, "       inode_i_size: %lu\n",
			CU_OFFSET(inode_i_size));
		fprintf(fp, "  vfsmount_mnt_root: %lu\n",
			CU_OFFSET(vfsmount_mnt_root));
		fprintf(fp, "   dentry_d_subdirs: %lu\n",
			CU_OFFSET(dentry_d_subdirs));
		fprintf(fp, "     dentry_d_child: %lu\n",
			CU_OFFSET(dentry_d_child));
	}

	if ((*diskdump_flags & KDUMP_CMPRS_LOCAL) &&
	    ((dump_level = get_dump_level()) >= 0) &&
	    (dump_level & DL_EXCLUDE_CACHE_PRI))
		error(WARNING, "\"ccat\" command is unusable because all of"
			" cache pages are excluded (dump_level:%d)\n",
			dump_level);
}

void __attribute__((destructor))
cacheutils_fini(void)
{
}
