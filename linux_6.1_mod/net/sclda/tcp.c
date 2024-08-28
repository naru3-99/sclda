/*
 * syscall.c
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

// this file is an additional impl for common.c

int init_sclda_client_tcp(struct sclda_client_struct *sclda_cs_ptr, int port) {
    int retval;
    if (sclda_cs_ptr == NULL) return -EFAULT;

    // ソケットの作成
    retval = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
                              &(sclda_cs_ptr->sock));
    if (retval < 0) {
        printk(KERN_ERR
               "SCLDA_ERR init_sclda_client_tcp socket_create, port = %d\n",
               port);
        return retval;
    }

    // サーバーのアドレス設定
    sclda_cs_ptr->addr.sin_family = PF_INET;
    sclda_cs_ptr->addr.sin_port = htons(port);
    sclda_cs_ptr->addr.sin_addr.s_addr = htonl(SCLDA_SERVER_IP);

    // サーバーに接続
    retval = kernel_connect(sclda_cs_ptr->sock,
                            (struct sockaddr *)(&(sclda_cs_ptr->addr)),
                            sizeof(struct sockaddr_in), O_WRONLY);

    if (retval < 0) {
        printk(KERN_ERR "SCLDA_ERR init_sclda_client_tcp connect, port = %d\n",
               port);
        sock_release(sclda_cs_ptr->sock);
        return retval;
    }

    // メッセージヘッダーの設定
    sclda_cs_ptr->hdr.msg_name = &(sclda_cs_ptr->addr);
    sclda_cs_ptr->hdr.msg_namelen = sizeof(struct sockaddr_in);
    sclda_cs_ptr->hdr.msg_control = NULL;
    sclda_cs_ptr->hdr.msg_controllen = 0;
    sclda_cs_ptr->hdr.msg_flags = 0;
    sclda_cs_ptr->hdr.msg_control_is_user = false;
    sclda_cs_ptr->hdr.msg_get_inq = false;
    sclda_cs_ptr->hdr.msg_iocb = NULL;
    sclda_cs_ptr->hdr.msg_ubuf = NULL;

    // ミューテックスの初期化
    mutex_init(&sclda_cs_ptr->mtx);
    return 0;
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

int sclda_sendall_syscallinfo_tcp(int target_index) {
    size_t i, cnt = 0;
    int send_ret, failed = 0;
    struct sclda_iov siov;
    struct sclda_syscallinfo_ls *curptr, *next, temp_head, *temp_tail;

    temp_tail = temp_head.next;

    mutex_lock(&sclda_syscall_mutex[target_index]);
    curptr = sclda_syscall_heads[target_index].next;
    while (curptr != NULL) {
        for (i = 0; i < curptr->sc_iov_len; i++) {
            siov.str = NULL;
            siov.len = curptr->pid_time.len + curptr->syscall[i].len + 1;
            siov.str = kmalloc(siov.len, GFP_KERNEL);
            if (!siov.str) {
                // 失敗したため、引き継ぎを行う
                sclda_syscall_heads[target_index].next = curptr;
                sclda_syscallinfo_num[target_index] -= cnt;
                goto out;
            }
            siov.len = snprintf(siov.str, siov.len, "%s%s",
                                curptr->pid_time.str, curptr->syscall[i].str);
            kfree(curptr->syscall[i].str);
            curptr->syscall[i].str = siov.str;
            curptr->syscall[i].len = siov.len;
        }
        send_ret = sclda_send_vec_mutex(
            curptr->syscall, curptr->sc_iov_len,
            &(sclda_syscall_client[cnt % SCLDA_PORT_NUMBER]));
        if (send_ret < 0) {
            temp_tail->next = curptr;
            temp_tail = temp_tail->next;
            failed += 1;
        }
        next = curptr->next;
        if (send_ret >= 0) kfree_scinfo_ls(curptr);

        curptr = next;
        cnt += 1;
    }
    // scinfoのhead, tailを再初期化する
    sclda_syscall_heads[target_index].next = temp_head.next;
    temp_tail->next = NULL;
    sclda_syscall_tails[target_index] = temp_tail;
    sclda_syscallinfo_num[target_index] = failed;
out:
    mutex_unlock(&sclda_syscall_mutex[target_index]);
    return cnt;
}