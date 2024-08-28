/*
 * udp.c
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

int init_sclda_client_udp(struct sclda_client_struct *sclda_cs_ptr, int port) {
    int retval;
    if (sclda_cs_ptr == NULL) return -EFAULT;

    // create socket
    retval = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP,
                              &(sclda_cs_ptr->sock));
    if (retval < 0)
        printk(KERN_ERR
               "SCLDA_ERR init_sclda_client_udp socket_create, port = %d",
               port);

    // setting for ipv4 udp communication
    sclda_cs_ptr->addr.sin_family = PF_INET;
    sclda_cs_ptr->addr.sin_port = htons(port);
    sclda_cs_ptr->addr.sin_addr.s_addr = htonl(SCLDA_SERVER_IP);

    // setting for msghdr struct
    sclda_cs_ptr->hdr.msg_name = &(sclda_cs_ptr->addr);
    sclda_cs_ptr->hdr.msg_namelen = sizeof(struct sockaddr_in);
    sclda_cs_ptr->hdr.msg_control = NULL;
    sclda_cs_ptr->hdr.msg_controllen = 0;
    sclda_cs_ptr->hdr.msg_flags = 0;
    sclda_cs_ptr->hdr.msg_control_is_user = false;
    sclda_cs_ptr->hdr.msg_get_inq = false;
    sclda_cs_ptr->hdr.msg_iocb = NULL;
    sclda_cs_ptr->hdr.msg_ubuf = NULL;

    // init mutex
    mutex_init(&sclda_cs_ptr->mtx);
    return 0;
}

static int kfree_scinfo_ls(struct sclda_syscallinfo_ls *scinfo_ptr) {
    size_t i;
    kfree(scinfo_ptr->pid_time.str);
    for (i = 0; i < scinfo_ptr->sc_iov_len; i++)
        kfree(scinfo_ptr->syscall[i].str);
    kfree(scinfo_ptr->syscall);
    kfree(scinfo_ptr);
    return 0;
}

static int init_siovls(struct sclda_iov_ls **siov) {
    struct sclda_iov_ls *temp;

    temp = kmalloc(sizeof(struct sclda_iov_ls), GFP_KERNEL);
    if (!temp) return -EFAULT;
    temp->next = NULL;
    temp->data.len = 0;
    temp->data.str = kmalloc(SCLDA_CHUNKSIZE, GFP_KERNEL);
    if (!(temp->data.str)) {
        kfree(temp);
        return -EFAULT;
    }
    memset(temp->data.str, 0, SCLDA_CHUNKSIZE);
    *siov = temp;
    return 0;
}

static int save_siovls(struct sclda_iov_ls *siov, int target_index) {
    // データを保存
    mutex_lock(&sclda_siov_mutex[target_index]);
    siov_tails[target_index]->next = siov;
    siov_tails[target_index] = siov_tails[target_index]->next;
    mutex_unlock(&sclda_siov_mutex[target_index]);
    return 0;
}

static int scinfo_to_siov(int target_index) {
    int cnt = 0;
    size_t i, chnk_remain, data_remain;
    struct sclda_syscallinfo_ls *curptr, *next;
    struct sclda_iov_ls *temp;

    if (init_siovls(&temp) < 0) return -EFAULT;

    mutex_lock(&sclda_syscall_mutex[target_index]);

    curptr = sclda_syscall_heads[target_index].next;
    while (curptr != NULL) {
        for (i = 0; i < curptr->sc_iov_len; i++) {
            // まだchunkに余裕がある場合
            if (temp->data.len + curptr->pid_time.len + curptr->syscall[i].len <
                SCLDA_CHUNKSIZE) {
                temp->data.len +=
                    snprintf(temp->data.str + temp->data.len,
                             SCLDA_CHUNKSIZE - temp->data.len, "%s%s%c",
                             curptr->pid_time.str, curptr->syscall[i].str,
                             SCLDA_EACH_DLMT);
            } else {
                // chunkに余裕が無い場合
                data_remain = curptr->syscall[i].len;
                while (data_remain != 0) {
                    chnk_remain = SCLDA_CHUNKSIZE - temp->data.len - 1;
                    if (chnk_remain < curptr->pid_time.len ||
                        temp->data.len > SCLDA_CHUNKSIZE) {
                        // これ以上書き込めないため、
                        // データを保存 + tempを再初期化
                        save_siovls(temp, target_index);
                        if (init_siovls(&temp) < 0) {
                            // 失敗したため、引き継ぎを行う
                            sclda_syscall_heads[target_index].next = curptr;
                            sclda_syscallinfo_num[target_index] -= cnt;
                            goto out;
                        };
                        chnk_remain = SCLDA_CHUNKSIZE - 1;
                    }
                    // 分割して書き込む
                    chnk_remain -= 2 + curptr->pid_time.len;
                    chnk_remain = min(chnk_remain, data_remain);

                    temp->data.len +=
                        snprintf(temp->data.str + temp->data.len,
                                 SCLDA_CHUNKSIZE - temp->data.len, "%s%.*s%c",
                                 curptr->pid_time.str, (int)chnk_remain,
                                 curptr->syscall[i].str, SCLDA_EACH_DLMT);

                    data_remain -= chnk_remain;
                }
            }
        }
        next = curptr->next;
        kfree_scinfo_ls(curptr);
        curptr = next;
        cnt += 1;
    }

    // scinfoのhead, tailを再初期化する
    sclda_syscall_heads[target_index].next = NULL;
    sclda_syscall_tails[target_index] = &sclda_syscall_heads[target_index];
    sclda_syscallinfo_num[target_index] = 0;
out:
    mutex_unlock(&sclda_syscall_mutex[target_index]);
    return cnt;
}

static int sclda_sendall_siovls(int target_index) {
    int send_ret;
    size_t cnt;
    struct sclda_iov_ls *curptr, *next;

    mutex_lock(&sclda_siov_mutex[target_index]);

    cnt = 0;
    curptr = siov_heads[target_index].next;
    siov_tails[target_index] = &siov_heads[target_index];

    while (curptr != NULL) {
        send_ret = sclda_send_siov_mutex(
            &(curptr->data), &(sclda_syscall_client[cnt % SCLDA_PORT_NUMBER]));
        if (send_ret < 0) {
            siov_tails[target_index]->next = curptr;
            siov_tails[target_index] = siov_tails[target_index]->next;
        }

        next = curptr->next;
        if (send_ret >= 0) {
            kfree(curptr->data.str);
            kfree(curptr);
        }
        curptr = next;
        cnt += 1;
    }
    siov_tails[target_index]->next = NULL;
    mutex_unlock(&sclda_siov_mutex[target_index]);
    return 0;
}

int sclda_sendall_syscallinfo_udp(int target_index) {
    // scinfo_ls -> siov_ls
    scinfo_to_siov(target_index);
    // send all siov in linked list
    sclda_sendall_siovls(target_index);

    return 0;
}