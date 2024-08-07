/*
 * net/sclda/common.c
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
#include <net/sclda.h>

int sclda_init_fin = 0;

int __sclda_create_socket(struct sclda_client_struct *sclda_cs_ptr) {
    return sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP,
                            &(sclda_cs_ptr->sock));
}

int __sclda_connect_socket(struct sclda_client_struct *sclda_cs_ptr, int port) {
    sclda_cs_ptr->addr.sin_family = PF_INET;
    sclda_cs_ptr->addr.sin_port = htons(port);
    sclda_cs_ptr->addr.sin_addr.s_addr = htonl(SCLDA_SERVER_IP);

    return kernel_connect(sclda_cs_ptr->sock,
                          (struct sockaddr *)(&(sclda_cs_ptr->addr)),
                          sizeof(struct sockaddr_in), 0);
}

int __init_sclda_client(struct sclda_client_struct *sclda_cs_ptr, int port) {
    if (__sclda_create_socket(sclda_cs_ptr) < 0) {
        printk(KERN_INFO "SCLDA_ERROR socket create error: %d", port);
        return -1;
    }
    if (__sclda_connect_socket(sclda_cs_ptr, port) < 0)
        printk(KERN_INFO "SCLDA_ERROR socket connect error: %d", port);

    sclda_cs_ptr->msg.msg_name = &(sclda_cs_ptr->addr);
    sclda_cs_ptr->msg.msg_namelen = sizeof(struct sockaddr_in);
    sclda_cs_ptr->msg.msg_iter = sclda_cs_ptr->iov_it;
    sclda_cs_ptr->msg.msg_control = NULL;
    sclda_cs_ptr->msg.msg_controllen = 0;
    sclda_cs_ptr->msg.msg_flags = 0;
    mutex_init(&sclda_cs_ptr->mtx);
    return 0;
}

// This function will invoked once in init/main.c
int sclda_init(void) {
    // prepare for syscall.c
    for (size_t i = 0; i < SCLDA_SCI_NUM; i++) {
        mutex_init(&sclda_syscall_mutex[i]);
        sclda_syscall_heads[i].next = NULL;
        sclda_syscall_tails[i] = &sclda_syscall_heads[i];
        sclda_syscallinfo_num[i] = 0;
    }

    // init pid_client
    __init_sclda_client(&sclda_pid_client, SCLDA_PIDPPID_PORT);

    // init syscall_client
    for (size_t i = 0; i < SCLDA_PORT_NUMBER; i++)
        __init_sclda_client(&sclda_syscall_client[i],
                            SCLDA_SYSCALL_BASEPORT + i);

    sclda_init_fin = 1;
    return 0;
}

int is_sclda_init_fin(void) { return sclda_init_fin; }

int sclda_send(char *buf, int len,
               struct sclda_client_struct *sclda_struct_ptr) {
    struct kvec iov;
    iov.iov_base = buf;
    iov.iov_len = len;
    return kernel_sendmsg(sclda_struct_ptr->sock, &(sclda_struct_ptr->msg),
                          &iov, 1, len);
}

int sclda_send_mutex(char *buf, int len,
                     struct sclda_client_struct *sclda_struct_ptr) {
    int ret;

    mutex_lock(&(sclda_struct_ptr->mtx));
    ret = sclda_send(buf, len, sclda_struct_ptr);
    mutex_unlock(&(sclda_struct_ptr->mtx));
    return ret;
}