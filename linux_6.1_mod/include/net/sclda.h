/*
 * include/net/sclda.h
 * Copyright (C) [2023] [Naru3 (Narumi Yoneda)
 * (7423530@ed.tus.ac.jp,naru99yoneda@gmail.com)]
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA.
 */

#ifndef SCLDA_H
#define SCLDA_H

#include <linux/delay.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/netpoll.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// splitting syscall data by this delimiter
#define SCLDA_DELIMITER ((char)0x05)
// server ip address, Virtualbox's Hostonly adaptor
#define SCLDA_SERVER_IP ((unsigned long int)0xc0a83801)
// pid-ppid relationship server port
#define SCLDA_PIDPPID_PORT ((int)15001)
// syscall server port, BASEPORT + i
#define SCLDA_PORT_NUMBER ((int)16)
#define SCLDA_SYSCALL_BASEPORT ((int)15002)
// chunksize for spliting data
#define SCLDA_CHUNKSIZE ((size_t)1000)
// bufsize for utime, PID
#define SCLDA_PID_CLOCK_SIZE ((int)50)
// bufsize for syscall_info struct
#define SCLDA_NUM_TO_SEND_SINFO ((int)5000)
// num for head of syscall_info struct
#define SCLDA_SCI_NUM ((int)16)

// client struct
struct sclda_client_struct {
    struct socket *sock;
    struct sockaddr_in addr;
    struct msghdr msg;
    struct iov_iter iov_it;
    struct mutex mtx;
};

// char + len struct
struct sclda_iov {
    int len;
    char *str;
};

// PID information linked list
struct sclda_pidinfo_ls {
    struct sclda_pidinfo_ls *next;  // pointer for next
    struct sclda_iov pid_info;      // pid-ppid-comm information
};

// syscall information linked list
struct sclda_syscallinfo_ls {
    struct sclda_syscallinfo_ls *next;  // pointer for next
    struct sclda_iov pid_time;          // invoked pid & time information
    int sc_iov_len;                     // length for iov
    struct sclda_iov *syscall;          // strings
};

// common.c
int sclda_init(void);
int is_sclda_init_fin(void);
int sclda_send(char *, int, struct sclda_client_struct *);
int sclda_send_mutex(char *, int, struct sclda_client_struct *);

// pid.c
struct sclda_client_struct *sclda_get_pid_client(void);
int sclda_add_pidinfo(char *, int);
void sclda_sendall_pidinfo(void);
int is_sclda_allsend_fin(void);

extern struct sclda_client_struct sclda_pid_client;

// syscall.c
int sclda_send_syscall_info(char *, int);
int sclda_send_syscall_info2(struct sclda_iov *, int);
struct sclda_client_struct *sclda_decide_struct(void);

extern struct sclda_client_struct sclda_syscall_client[SCLDA_PORT_NUMBER];

extern struct mutex sclda_syscall_mutex[SCLDA_SCI_NUM];
extern struct sclda_syscallinfo_ls sclda_syscall_heads[SCLDA_SCI_NUM];
extern struct sclda_syscallinfo_ls *sclda_syscall_tails[SCLDA_SCI_NUM];
extern int sclda_syscallinfo_num[SCLDA_SCI_NUM];

// other.c
int sclda_get_current_pid(void);
int kernel_timespec_to_str(const struct __kernel_timespec __user *, char *,
                           int);
#endif  // SCLDA_H
