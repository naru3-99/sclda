/*
 * sclda.c
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

struct sclda_client_struct sclda_syscall_client[SCLDA_PORT_NUMBER];

struct mutex sclda_syscall_mutex[SCLDA_SCI_NUM];
struct sclda_syscallinfo_ls sclda_syscall_heads[SCLDA_SCI_NUM];
struct sclda_syscallinfo_ls *sclda_syscall_tails[SCLDA_SCI_NUM];
int sclda_syscallinfo_num[SCLDA_SCI_NUM];
int sclda_sci_index = 0;

int __sclda_send_split(struct sclda_syscallinfo_ls *ptr, int which_port) {
    // 大きいサイズの文字列を分割して送信する実装
    // ヘッダ情報としてPIDとutimeを最初にくっつける
    // system-call関連情報を送信するときのみ使用する
    int retval = -EFAULT;
    char *sending_msg;
    int send_ret, sending_len, max_packet_len;
    size_t offset, len, i;

    // まだnetのinit が済んでいない場合
    if (!is_sclda_init_fin()) goto out;

    // 一度に送信するパケットのバッファを段取り
    max_packet_len = SCLDA_CHUNKSIZE + ptr->pid_time.len + 1;
    sending_msg = kmalloc(max_packet_len, GFP_KERNEL);
    if (!sending_msg) goto out;

    // 分割して送信する
    for (i = 0; i < ptr->sc_iov_len; i++) {
        offset = 0;
        len = 0;
        if (ptr->syscall[i].str == NULL) continue;
        if (ptr->syscall[i].len == 0) continue;
        while (offset < ptr->syscall[i].len) {
            memset(sending_msg, 0, max_packet_len);
            len = min(SCLDA_CHUNKSIZE, (size_t)(ptr->syscall[i].len - offset));

            sending_len = snprintf(sending_msg, max_packet_len, "%s%.*s",
                                   ptr->pid_time.str, (int)len,
                                   ptr->syscall[i].str + offset);
            if (sending_len < 0) goto free_sending_msg;

            send_ret = sclda_send_mutex(sending_msg, sending_len,
                                        &sclda_syscall_client[which_port]);
            if (send_ret < 0) goto free_sending_msg;
            offset += len;
        }
    }

    retval = 0;

free_sending_msg:
    kfree(sending_msg);
out:
    return retval;
}

int sclda_sendall_syscallinfo(void *data) {
    int target_index, cnt, send_ret, failed_cnt, i;
    struct sclda_syscallinfo_ls *curptr, *next;

    // ターゲットになるindexを特定
    target_index = *(int *)data;
    kfree(data);

    // 順次送信を開始
    mutex_lock(&sclda_syscall_mutex[target_index]);
    // curptrを初期化し、全リストのデータを送信する
    curptr = sclda_syscall_heads[target_index].next;
    cnt = 0;
    failed_cnt = 0;
    // 失敗したときのために初期化する
    sclda_syscall_tails[target_index] = &sclda_syscall_heads[target_index];
    while (curptr != NULL) {
        ndelay(1000);
        send_ret = __sclda_send_split(curptr, cnt % SCLDA_PORT_NUMBER);
        next = curptr->next;
        if (send_ret < 0) {
            // 送信できていないため、tempに退避する
            failed_cnt++;
            sclda_syscall_tails[target_index]->next = curptr;
            sclda_syscall_tails[target_index] =
                sclda_syscall_tails[target_index]->next;
        } else {
            // 送信できたので解放する
            kfree(curptr->pid_time.str);
            for (i = 0; i < curptr->sc_iov_len; i++) {
                kfree(curptr->syscall[i].str);
            }
            kfree(curptr->syscall);
        }
        curptr = next;
        cnt = cnt + 1;
    }
    // 頭・尻の再初期化
    sclda_syscallinfo_num[target_index] = failed_cnt;
    mutex_unlock(&sclda_syscall_mutex[target_index]);
    return 0;
}

int sclda_syscallinfo_init(struct sclda_syscallinfo_ls **ptr) {
    // メモリ割り当て
    struct sclda_syscallinfo_ls *s;
    s = kmalloc(sizeof(struct sclda_syscallinfo_ls), GFP_KERNEL);
    if (!s) goto out;

    s->pid_time.str = kmalloc(SCLDA_PID_CLOCK_SIZE, GFP_KERNEL);
    if (!(s->pid_time.str)) goto free_scinfo;

    // メモリ割り当てが成功したら、情報を初期化する
    s->next = NULL;
    s->pid_time.len = snprintf(s->pid_time.str, SCLDA_PID_CLOCK_SIZE,
                               "%d%c%llu%c", sclda_get_current_pid(),
                               SCLDA_DELIMITER, sched_clock(), SCLDA_DELIMITER);

    *ptr = s;
    return 0;

free_scinfo:
    kfree(s);
out:
    return -ENOMEM;
}

int sclda_add_syscallinfo(struct sclda_syscallinfo_ls *ptr) {
    // リストを末端に追加する
    mutex_lock(&sclda_syscall_mutex[sclda_sci_index]);
    // 末尾に追加する
    sclda_syscall_tails[sclda_sci_index]->next = ptr;
    sclda_syscall_tails[sclda_sci_index] =
        sclda_syscall_tails[sclda_sci_index]->next;
    // 一つ増やす
    sclda_syscallinfo_num[sclda_sci_index]++;
    mutex_unlock(&sclda_syscall_mutex[sclda_sci_index]);
    return 0;
}

int sclda_start_to_send(void) {
    struct task_struct *newkthread;

    int *arg;
    arg = kmalloc(sizeof(int), GFP_KERNEL);
    if (!arg) return -ENOMEM;
    *arg = sclda_sci_index;

    // current_indexの更新
    sclda_sci_index = (sclda_sci_index + 1) % SCLDA_SCI_NUM;

    // 送信メカニズムを呼び出す
    newkthread = kthread_create(sclda_sendall_syscallinfo, arg, "sclda");
    if (!IS_ERR(newkthread)) wake_up_process(newkthread);
    return 0;
}

// SYSCALL_DEFINEマクロ内で使用する関数
// 送信し終えたときに、送信したものが、
// msg_buf, syscallinfoを解放する責任を負う
static DEFINE_MUTEX(send_by_kthread);
int sclda_send_syscall_info(char *msg_buf, int msg_len) {
    int retval;
    struct sclda_syscallinfo_ls *s;

    // ノードを初期化する
    retval = sclda_syscallinfo_init(&s);
    if (retval < 0) {
        kfree(msg_buf);
        return retval;
    }

    s->syscall = kmalloc_array(1, sizeof(struct sclda_iov), GFP_KERNEL);
    if (!(s->syscall)) goto free_syscallinfo;
    s->sc_iov_len = 1;
    s->syscall[0].len = msg_len;
    s->syscall[0].str = msg_buf;

    // リストにノードを追加する
    retval = sclda_add_syscallinfo(s);

    // リストが溜まっていたら、送信する
    if (mutex_is_locked(&send_by_kthread)) return retval;
    mutex_lock(&send_by_kthread);
    if (sclda_syscallinfo_num[sclda_sci_index] >= SCLDA_NUM_TO_SEND_SINFO)
        sclda_start_to_send();
    mutex_unlock(&send_by_kthread);
    return retval;

free_syscallinfo:
    kfree(s->pid_time.str);
    kfree(s);
    kfree(msg_buf);
    return -ENOMEM;
}

int sclda_send_syscall_info2(struct sclda_iov *siov_ls, int num) {
    int retval;
    struct sclda_syscallinfo_ls *s;

    // ノードを初期化する
    retval = sclda_syscallinfo_init(&s);
    if (retval < 0) goto out;
    s->syscall = siov_ls;
    s->sc_iov_len = num;

    // リストにノードを追加する
    retval = sclda_add_syscallinfo(s);

    // リストが溜まっていたら、送信する
    if (mutex_is_locked(&send_by_kthread)) return retval;
    mutex_lock(&send_by_kthread);
    if (sclda_syscallinfo_num[sclda_sci_index] >= SCLDA_NUM_TO_SEND_SINFO)
        sclda_start_to_send();
    mutex_unlock(&send_by_kthread);
    return retval;
out:
    for (size_t i = 0; i < num; i++) kfree(siov_ls[i].str);
    return retval;
}