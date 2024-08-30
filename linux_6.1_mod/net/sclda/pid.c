/*
 * net/sclda/pid.c
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

int sclda_allsend_fin = 0;

struct sclda_client_struct sclda_pid_client;

// linked list's mutex-dummyhead-tail
DEFINE_MUTEX(sclda_pidinfo_mutex);
struct sclda_pidinfo_ls sclda_pidinfo_head = {
    .next = NULL, .pid_info.len = 0, .pid_info.str = NULL};
struct sclda_pidinfo_ls *sclda_pidinfo_tail = &sclda_pidinfo_head;

// returns 0 on success, minus value on failed
int sclda_pid_init(void) {
    return init_sclda_client(&sclda_pid_client, SCLDA_PIDPPID_PORT);
}

static int sclda_add_pidinfo(struct sclda_iov *siov) {
    struct sclda_pidinfo_ls *new_node;
    new_node = kmalloc(sizeof(struct sclda_pidinfo_ls), GFP_KERNEL);
    if (!new_node) return -ENOMEM;

    new_node->pid_info.str = siov->str;
    new_node->pid_info.len = siov->len;
    new_node->next = NULL;

    mutex_lock(&sclda_pidinfo_mutex);
    sclda_pidinfo_tail->next = new_node;
    sclda_pidinfo_tail = sclda_pidinfo_tail->next;
    mutex_unlock(&sclda_pidinfo_mutex);
    return 0;
}

static void sclda_sendall_pidinfo(void) {
    struct sclda_pidinfo_ls *curptr, *next;
    curptr = sclda_pidinfo_head.next;
    mutex_lock(&sclda_pidinfo_mutex);
    while (curptr != NULL) {
        sclda_send_mutex(curptr->pid_info.str, curptr->pid_info.len,
                         &sclda_pid_client);
        next = curptr->next;
        kfree(curptr->pid_info.str);
        kfree(curptr);
        curptr = next;
    }
    sclda_allsend_fin = 1;
    mutex_unlock(&sclda_pidinfo_mutex);
}

int is_sclda_allsend_fin(void) { return sclda_allsend_fin; }

int sclda_send_pidinfo(struct sclda_iov *siov) {
    siov->len = SCLDA_PID_PPID_BUFSIZE;
    // まだscldaが初期化されていない場合
    if (!is_sclda_init_fin()) {
        sclda_add_pidinfo(siov);
        return 0;
    }
    // 初期化され、allsendも終わった場合
    if (is_sclda_allsend_fin()) {
        sclda_send_mutex(siov->str, siov->len, &sclda_pid_client);
        kfree(siov->str);
        return 0;
    }
    // scldaは初期化済み、allsendは終わっていない
    if (sclda_send_mutex("sclda\0", 6, &sclda_pid_client) == 6) {
        // 送信可能-> sendall
        sclda_sendall_pidinfo();
        sclda_send_mutex(siov->str, siov->len, &sclda_pid_client);
        kfree(siov->str);
    } else {
        // まだ送信できない
        sclda_add_pidinfo(siov);
    }
    return 0;
}