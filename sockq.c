/* sockq.c - sockq extension module for crash
 *
 * Copyright (C) 2014 FUJITSU LIMITED
 * Author: Qiao Nuohan <qiaonuohan cn fujitsu com>
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

#include "defs.h"      /* From the crash source top-level directory */

void sockq_init(void);      /* constructor function */
void sockq_fini(void);      /* destructor function (optional) */

void cmd_sockq(void);       /* Declare the commands and their help data. */
char *help_sockq[];

static struct command_table_entry command_table[] = {
    { "sockq", cmd_sockq, help_sockq, 0},       /* One or more commands, */
    { NULL },                                   /* terminated by NULL, */
};

char *help_sockq[] = {
"sockq",                                    /* command name */
"get socket receive queue into a file",     /* short description */
"file_address outfile",                     /* argument synopsis */

"  This command gets the data from the socket receive queue.",
" ",
"    file_address       A hexadecimal value of socket's file structure address.",
"    outfile            A name of output file. If the file already exists,",
"                       it is overwritten.",
NULL
};

void __attribute__((constructor))
sockq_init(void) /* Register the command set. */
{
    register_extension(command_table);
}

/*
 *  This function is called if the shared object is unloaded.
 *  If desired, perform any cleanups here.
 */
void __attribute__((destructor))
sockq_fini(void) { }

static int
get_member_data(ulonglong addr, char *name, char *member, void* buf)
{
    ulong member_offset;

    member_offset = MEMBER_OFFSET(name, member);

    if (!readmem(addr + member_offset, KVADDR, buf,
        MEMBER_SIZE(name, member), name, FAULT_ON_ERROR))
        return FALSE;

    return TRUE;
}

/*
 * write receive data in the specified file
 */
static int
write_data(int fd, char *buf, ulong addr, ulong size)
{
    ulong wsize;

    while (size > 0) {
    /* size of the buffer is pagesize */
        wsize =  (size > PAGESIZE()) ? PAGESIZE() : size;

        if (!readmem(addr, KVADDR, buf, wsize, "vaddr", FAULT_ON_ERROR)) {
            fprintf(fp, "cannot read data from packet buffer\n");
            return 1;
        }

        if (write(fd, buf, wsize) < 0) {
            fprintf(fp, "cannot write data in a file\n");
            return 1;
        }

        addr += wsize;
        size -= wsize;
    }

    return 0;
}

int
do_sockq(ulong file_addr, char *output_file, int fd)
{
    int rc = 1;
    ulong pd, sk;
    uint qlen;
    char *buf = NULL;
    ulong next, head;
    unsigned int len;
    ulong wnext;

    if (!get_member_data(file_addr, "file", "private_data", &pd)) {
        fprintf(fp, "cannot get private_data of file structure\n");
        goto cleanup;
    }

    if (!get_member_data(pd, "socket", "sk", &sk)) {
        fprintf(fp, "cannot get sk of socket structure\n");
        goto cleanup;
    }

    if (!get_member_data(sk + MEMBER_OFFSET("sock", "sk_receive_queue"),
                         "sk_buff_head", "next", &next)) {
        fprintf(fp, "cannot get the first queue of sock structure\n");
        goto cleanup;
    }

    if (!get_member_data(sk + MEMBER_OFFSET("sock", "sk_receive_queue"),
                         "sk_buff_head", "qlen", &qlen)) {
        fprintf(fp, "cannot get the number of queue list\n");
        goto cleanup;
    }

    /* create a output file */
    if (output_file != NULL &&
        (fd = open(output_file,
                   O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR)) < 0) {
        fprintf(fp, "cannot create %s\n", output_file);
        goto cleanup;
    }

    if (qlen == 0) {
        /* receive queue is empty */
        rc = 0;
        goto cleanup;
    }

    /* get work area */
    buf = GETBUF(PAGESIZE());

    while (qlen-- > 0) {
        /* get packet buffer are info */
        if (!get_member_data(next, "sk_buff", "head", &head)) {
            fprintf(fp, "cannot head of sk_buff structure\n");
            goto cleanup;
        }

        if (!get_member_data(next, "sk_buff", "len", &len)) {
            fprintf(fp, "cannot tail of sk_buff structure\n");
            goto cleanup;
        }

        /* write data in the output file */
        if (write_data(fd, buf, head, len))
            goto cleanup;

        /* next receive queue */
        wnext = next;
        if (!get_member_data(wnext, "sk_buff", "next", &next)) {
            fprintf(fp, "cannot get next of sk_buff structure\n");
            goto cleanup;
        }
    }

    /* all process normally ends */
    rc = 0;

cleanup:
    if (output_file != NULL)
        close(fd);
    if (buf)
        FREEBUF(buf);

    return rc;
}

void
cmd_sockq(void)
{
    ulong file_addr;

    if (argcnt != 3)
        cmd_usage(pc->curcmd, SYNOPSIS);

    optind++;
    file_addr = htol(args[optind], FAULT_ON_ERROR, NULL);

    optind++;
    if (strlen(args[optind]) > PATH_MAX) {
    fprintf(fp, "cannot create specified output file\n");
    return;
    }

    do_sockq(file_addr, args[optind], -1);
}
