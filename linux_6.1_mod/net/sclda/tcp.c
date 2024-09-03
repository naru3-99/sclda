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

static int sclda_tcp_init_thread(void *data) {
    while (sclda_init()) msleep(1000);
    return 0;
}

int sclda_tcp_init(void) {
    struct task_struct *newkthread;

    newkthread = kthread_create(sclda_tcp_init_thread, NULL, "sclda_init");
    if (!IS_ERR(newkthread)) wake_up_process(newkthread);
    return 0;
}

// returns 0 or error code
int init_sclda_client_tcp(struct sclda_client_struct *sclda_cs_ptr, int port) {
    int retval;
    if (sclda_cs_ptr == NULL) return -EFAULT;
    if (sclda_cs_ptr->init_ok) return 0;

    // ソケットの作成
    retval = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
                              &(sclda_cs_ptr->sock));
    if (retval < 0) return retval;

    // サーバーのアドレス設定
    sclda_cs_ptr->addr.sin_family = PF_INET;
    sclda_cs_ptr->addr.sin_port = htons(port);
    sclda_cs_ptr->addr.sin_addr.s_addr = htonl(SCLDA_SERVER_IP);

    // サーバーに接続
    retval = kernel_connect(sclda_cs_ptr->sock,
                            (struct sockaddr *)(&(sclda_cs_ptr->addr)),
                            sizeof(struct sockaddr_in), 0);

    if (retval < 0) {
        sock_release(sclda_cs_ptr->sock);
        return retval;
    }

    // メッセージヘッダーの設定
    sclda_cs_ptr->hdr.msg_name = NULL;
    sclda_cs_ptr->hdr.msg_namelen = 0;
    sclda_cs_ptr->hdr.msg_control = NULL;
    sclda_cs_ptr->hdr.msg_controllen = 0;

    // ミューテックスの初期化
    mutex_init(&sclda_cs_ptr->mtx);
    sclda_cs_ptr->init_ok = 1;
    return 0;
}