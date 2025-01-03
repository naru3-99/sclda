/*
 * common.c
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

// getter for int sclda_init_fin
int is_sclda_init_fin(void) { return sclda_init_fin; }

int init_sclda_client(struct sclda_client_struct *sclda_cs_ptr, int port) {
#ifdef SCLDA_USE_TCP
    return init_sclda_client_tcp(sclda_cs_ptr, port);
#else
    return init_sclda_client_udp(sclda_cs_ptr, port);
#endif
}

// This function will invoked once in init/main.c
int sclda_init(void) {
    int retval;

    if (is_sclda_init_fin()) return 0;

    // init pid.c code
    retval = sclda_pid_init();
    if (retval < 0) return retval;

    // init syscall.c code
    retval = sclda_syscall_init();
    if (retval < 0) return retval;

    sclda_init_fin = 1;
    printk(KERN_INFO "SCLDA_INIT_FIN");
    return 0;
}

int sclda_send(char *buf, int len,
               struct sclda_client_struct *sclda_struct_ptr) {
    struct kvec iov;

    if (!buf || len == 0) return 0;
    iov.iov_base = buf;
    iov.iov_len = len;

    return kernel_sendmsg(sclda_struct_ptr->sock, &(sclda_struct_ptr->hdr),
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

int sclda_send_vec(struct sclda_iov *siov_ls, size_t vlen,
                   struct sclda_client_struct *sclda_struct_ptr) {
    // this is for tcp only
    struct kvec *iov;
    size_t i, total_len = 0;

    iov = (struct kvec *)siov_ls;
    for (i = 0; i < vlen; i++) total_len += iov[i].iov_len;

    return kernel_sendmsg(sclda_struct_ptr->sock, &(sclda_struct_ptr->hdr), iov,
                          vlen, total_len);
}

int sclda_send_vec_mutex(struct sclda_iov *siov_ls, size_t vlen,
                         struct sclda_client_struct *sclda_struct_ptr) {
    int ret;

    mutex_lock(&(sclda_struct_ptr->mtx));
    ret = sclda_send_vec(siov_ls, vlen, sclda_struct_ptr);
    mutex_unlock(&(sclda_struct_ptr->mtx));
    return ret;
}