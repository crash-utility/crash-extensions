/* qemu-vtop.c - qemu-vtop extension module for crash
 *
 * Copyright (C) 2011, 2012 FUJITSU LIMITED
 * Auther: Qiao Nuohan <qiaonuohan@cn.fujitsu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "defs.h"    /* From the crash source top-level directory */

#define PHYSICAL_ADDR     (0x1)
#define USER_SPECIFY_TASK (0x4)

#define MAXTOKENS         (100)

struct qemu_vtop_offset_table {
        long file_private_data;
        long kvm_memslots;
        long kvm_memslots_nmemslots;
        long kvm_memslots_memslots;
        long kvm_memory_slot_base_gfn;
        long kvm_memory_slot_npages;
        long kvm_memory_slot_userspace_addr;
};

struct qemu_vtop_size_table {
        long kvm_memory_slot;
};

int _init(void);
int _fini(void);

void cmd_qemu_vtop(void);
char *help_qemu_vtop[];
static void qemu_vtop_init();
static void do_qemu_vtop_physical(ulong, struct task_context *);
static ulong get_file_ref(ulong, struct reference *);
static ulong parse_for_file(char *);
static ulong gpa_to_hva(ulong , ulong );
static void print_vtop(ulong, ulong, struct task_context *);

static struct command_table_entry command_table[] = {
        { "qemu-vtop", cmd_qemu_vtop, help_qemu_vtop, 0 },    /* One or more commands, */
        { NULL }                                              /* terminated by NULL, */
};

static struct qemu_vtop_offset_table qemu_vtop_offset_table = { 0 };
static struct qemu_vtop_size_table qemu_vtop_size_table = { 0 };

#define QEMU_VTOP_MEMBER_OFFSET_INIT(X, Y, Z) (qemu_vtop_offset_table.X = MEMBER_OFFSET(Y, Z))
#define QEMU_VTOP_ANON_MEMBER_OFFSET_INIT(X, Y, Z) (qemu_vtop_offset_table.X = ANON_MEMBER_OFFSET(Y, Z))
#define QEMU_VTOP_STRUCT_SIZE_INIT(X, Y) (qemu_vtop_size_table.X = STRUCT_SIZE(Y))

#define QEMU_VTOP_OFFSET(X) (OFFSET_verify(qemu_vtop_offset_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
#define QEMU_VTOP_SIZE(X) (SIZE_verify(qemu_vtop_size_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))

int 
_init(void) /* Register the command set. */
{ 
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

void
cmd_qemu_vtop(void)
{
        int c;
        int other;
        ulong vaddr, context;
        struct task_context *tc;
        ulong qemu_vtop_flag;

        tc = NULL;

        while ((c = getopt(argcnt, args, "g:p")) != EOF) {
                switch(c)
                {
                case 'g':
                        switch (str_to_context(optarg, &context, &tc)) {
                        case STR_PID:
                        case STR_TASK:
                                qemu_vtop_flag |= USER_SPECIFY_TASK;
                                break;
                        case STR_INVALID:
                                error(FATAL, "invalid task or pid value: %s\n",
                                        optarg);
                                break;
                        }
                        break;
                case 'p':
                        qemu_vtop_flag |= PHYSICAL_ADDR;
                        break;
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs || !args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

        if (!(qemu_vtop_flag & USER_SPECIFY_TASK))
                error(FATAL, "-g [pid | taskp] must be specified\n");

        if ((qemu_vtop_flag & PHYSICAL_ADDR) == 0)
                error(FATAL, "-p should be specified\n");

        qemu_vtop_init();

        other = 0;
        while (args[optind]) {
                vaddr = htol(args[optind], FAULT_ON_ERROR, NULL);
                
                if (other++)
                        fprintf(fp, "\n");

                if (qemu_vtop_flag & PHYSICAL_ADDR)
                        do_qemu_vtop_physical(vaddr, tc);

                optind++;
        }

        fprintf(fp, "\n");
}

/* 
 *  The optional help data is simply an array of strings in a defined format.
 *  For example, the "help qemu-vtop" command will use the help_qemu_vtop[] string
 *  array below to create a help page that looks like this:
 *
 *    NAME
 *      qemu-vtop - KVM guest's address to host's address
 *  
 *    SYNOPSIS
 *      qemu-vtop -g [pid | taskp] -p address ...
 *
 *    DESCRIPTION
 *      This command translates a guest's address on a KVM to its host's physical
 *      address. It first gets the host's virtual address related to the guest's
 *      address, then display the information of "vtop <host's virtual address>".
 *
 *       -p address          The address is a physical address of a guest
 *       -g [pid | taskp]    Translate the guest's address of the KVM specified by
 *                         PID(pid) or hexadecimal task_struct pointer(taskp).
 *  
 *    EXAMPLE
 *      Translate guest(pid:191579)'s physical address 34de5840:
 *
 *        crash> qemu-vtop -g 191579 -p 34de5840
 *        GUEST PHYSICAL    HOST VIRTUAL      HOST PHYSICAL
 *        34de5840          7f060cbe5840      611de5840
 *
 *           PML: 72dbb67f0 => 875afa067
 *           PUD: 875afa0c0 => 736871067
 *           PMD: 736871328 => 8000000611c000e7
 *          PAGE: 611c00000  (2MB)
 *
 *              PTE         PHYSICAL   FLAGS
 *        8000000611c000e7  611c00000  (PRESENT|RW|USER|ACCESSED|DIRTY|PSE|NX)
 *
 *              VMA           START       END     FLAGS FILE
 *        ffff8806edca49e0 7f05d7e00000 7f0697e00000 80120073
 *
 *              PAGE        PHYSICAL      MAPPING       INDEX CNT FLAGS
 *        ffffea00153e8a18 611de5000                0 7f9e743e5  0 c0000000008000
 *
 */
 
char *help_qemu_vtop[] = {
"qemu-vtop",                                    /* command name */
"KVM guest's address to host's address",        /* short description */
"-g [pid | taskp] -p address ...",              /* argument synopsis */

"  This command translates a guest's address on a KVM to its host's physical",
"  address. It first gets the host's virtual address related to the guest's",
"  address, then display the information of \"vtop <host's virtual address>\".",
" ",
"   -p address          The address is a physical address of a guest",
"   -g [pid | taskp]    Translate the guest's address of the KVM specified by",
"                       PID(pid) or hexadecimal task_struct pointer(taskp).",
"\nEXAMPLE",
"  Translate guest(pid:191579)'s physical address 34de5840:",
" ",
"    crash> qemu-vtop -g 191579 -p 34de5840",
"    GUEST PHYSICAL    HOST VIRTUAL      HOST PHYSICAL",
"    34de5840          7f060cbe5840      611de5840",
" ",
"       PML: 72dbb67f0 => 875afa067",
"       PUD: 875afa0c0 => 736871067",
"       PMD: 736871328 => 8000000611c000e7",
"      PAGE: 611c00000  (2MB)",
" ",
"          PTE         PHYSICAL   FLAGS",
"    8000000611c000e7  611c00000  (PRESENT|RW|USER|ACCESSED|DIRTY|PSE|NX)",
" ",
"          VMA           START       END     FLAGS FILE",
"    ffff8806edca49e0 7f05d7e00000 7f0697e00000 80120073",
" ",
"          PAGE        PHYSICAL      MAPPING       INDEX CNT FLAGS",
"    ffffea00153e8a18 611de5000                0 7f9e743e5  0 c0000000008000",
NULL
};

/*
 * init some offsets and sizes
 */
static void qemu_vtop_init()
{
        QEMU_VTOP_MEMBER_OFFSET_INIT(file_private_data, "file","private_data");
        QEMU_VTOP_MEMBER_OFFSET_INIT(kvm_memslots, "kvm", "memslots");
        QEMU_VTOP_MEMBER_OFFSET_INIT(kvm_memslots_nmemslots, "kvm_memslots", "nmemslots");
        QEMU_VTOP_MEMBER_OFFSET_INIT(kvm_memslots_memslots, "kvm_memslots", "memslots");
        QEMU_VTOP_MEMBER_OFFSET_INIT(kvm_memory_slot_base_gfn, "kvm_memory_slot", "base_gfn");
        QEMU_VTOP_MEMBER_OFFSET_INIT(kvm_memory_slot_npages, "kvm_memory_slot", "npages");
        QEMU_VTOP_MEMBER_OFFSET_INIT(kvm_memory_slot_userspace_addr, "kvm_memory_slot", "userspace_addr");

        QEMU_VTOP_STRUCT_SIZE_INIT(kvm_memory_slot, "kvm_memory_slot");
}

static void
do_qemu_vtop_physical(ulong gpa, struct task_context *tc)
{
        struct reference reference, *ref;
        ulong filep, private_data, memslots, nmemslots, hva;
        filep = 0;
        private_data = 0;
        memslots = 0;
        nmemslots = 0;

        ref = &reference;
        BZERO(ref, sizeof(struct reference));
        ref->str = "anon_inode:/kvm-vm";

        filep = get_file_ref(tc->task, ref);
        if (!filep) {
                error(INFO, "task(pid:%ld task:%lx) is not a qemu process\n", tc->pid, tc->task);
                return;
        }

        readmem(filep + QEMU_VTOP_OFFSET(file_private_data),
                        KVADDR, &private_data, sizeof(ulong),
                        "file private_data", FAULT_ON_ERROR);
        if (!private_data) {
                error(INFO, "failed to get information of qemu process(pid:%ld task:%lx)\n",
                                tc->pid, tc->task);
                return;
        }

        readmem(private_data + QEMU_VTOP_OFFSET(kvm_memslots),
                        KVADDR, &memslots, sizeof(ulong),
                        "kvm memslots", FAULT_ON_ERROR);
        if (!memslots) {
                error(INFO, "failed to get information of KVM, please check "
                                "whether KVM module is loaded\n");
                return;
        }

        hva = gpa_to_hva(gpa, memslots);
        if (!hva) {
                error(INFO, "%lx has not been allocated\n", gpa);
                return;
        }

        print_vtop(gpa, hva, tc);
}

/*
 * get the pointer to the file struct of a file descriptor, ref->str
 * is used to search for the specified file descriptor.
 */
static ulong
get_file_ref(ulong task, struct reference *ref)
{
        ulong file = 0;
        open_tmpfile();
        open_files_dump(task, 0, NULL);
        file = parse_for_file(ref->str);
        close_tmpfile();
        return file;
}

static ulong
parse_for_file(char *str)
{
        char buf[BUFSIZE];
        char *tokens[MAXTOKENS];
        ulong file = 0;

        rewind(pc->tmpfile);

        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (strstr(buf, str)) {
                        parse_line(buf, tokens);
                        file = htol(tokens[1], FAULT_ON_ERROR, NULL);
                        break;
                }
        }

        return file;
}

static ulong
gpa_to_hva(ulong gpa, ulong memslots)
{
        ulong nmemslots, kvm_memory_slot_size, memslots_offset;
        ulong base_gfn_offset, npages_offset, userspace_addr_offset;
        ulong hva = 0;
        ulong gfn = gpa >> PAGE_SHIFT;

        readmem(memslots + QEMU_VTOP_OFFSET(kvm_memslots_nmemslots),
                        KVADDR, &nmemslots, sizeof(ulong),
                        "kvm_memslots nmemslots", FAULT_ON_ERROR);
        kvm_memory_slot_size = QEMU_VTOP_SIZE(kvm_memory_slot);
        memslots_offset = QEMU_VTOP_OFFSET(kvm_memslots_memslots);

        base_gfn_offset = QEMU_VTOP_OFFSET(kvm_memory_slot_base_gfn);
        npages_offset = QEMU_VTOP_OFFSET(kvm_memory_slot_npages);
        userspace_addr_offset = QEMU_VTOP_OFFSET(kvm_memory_slot_userspace_addr);

        int i = 0;
        int found = 0;
        ulong hfn;
        ulong base_gfn, npages, userspace_addr;

        /*
         * search every kvm_memory_slot to find which one the gfn is located in.
         */
        while (i<=nmemslots) {
                readmem(memslots + memslots_offset + i*kvm_memory_slot_size +
                                QEMU_VTOP_OFFSET(kvm_memory_slot_base_gfn),
                        KVADDR, &base_gfn, sizeof(ulong),
                        "kvm_memory_slot base_gfn", FAULT_ON_ERROR);
                readmem(memslots + memslots_offset + i*kvm_memory_slot_size +
                                QEMU_VTOP_OFFSET(kvm_memory_slot_npages),
                        KVADDR, &npages, sizeof(ulong),
                        "kvm_memory_slot npages", FAULT_ON_ERROR);
                if (gfn>=base_gfn && gfn <base_gfn+npages) {
                        found = 1;
                        break;
                }
                i++;
        }

        /*
         * if the kvm_memory slot is find, calculate the hva.
         */
        if (found) {
                readmem(memslots + memslots_offset + i*kvm_memory_slot_size +
                                QEMU_VTOP_OFFSET(kvm_memory_slot_userspace_addr),
                        KVADDR, &userspace_addr, sizeof(ulong),
                        "kvm_memory_slot userspace_addr", FAULT_ON_ERROR);
                hfn = userspace_addr + (gfn - base_gfn) * PAGE_SIZE;
                hva = hfn + (gpa - gfn * PAGE_SIZE);
        }

        return hva;
}

/*
 * get the information of vtop hva, then change the first two line.
 */
static void
print_vtop(ulong gpa, ulong hva, struct task_context *tc)
{
        int linenum;
        int glen, hlen;
        char buf[BUFSIZE];
        char buf1[BUFSIZE];
        char buf2[BUFSIZE];
        char buf3[BUFSIZE];

        open_tmpfile();
        do_vtop(hva, tc, UVADDR);
        
        rewind(pc->tmpfile);

        linenum = 0;
        glen = 16;
        hlen = VADDR_PRLEN;

        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (linenum==0) {
                        fprintf(pc->saved_fp, "%s  %s  %s\n",
                                        mkstring(buf1, glen, LJUST, "GUEST PHYSICAL"),
                                        mkstring(buf2, hlen, LJUST, "HOST VIRTUAL"),
                                        mkstring(buf3, hlen, LJUST, "HOST PHYSICAL"));
                }
                else if(linenum==1) {
                        char *host_physical;
                        host_physical = strstr(buf, " ");
                        while (!strncmp(host_physical, " ", 1)) {
                                host_physical++;
                        }
                        fprintf(pc->saved_fp, "%*lx  %*lx  %s", -glen, gpa, -hlen, hva, host_physical);
                }
                else
                        fprintf(pc->saved_fp, "%s", buf);

                linenum++;
        }
        close_tmpfile();
}
