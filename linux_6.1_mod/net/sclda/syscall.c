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

// struct for udp communication
struct sclda_client_struct sclda_syscall_client[SCLDA_PORT_NUMBER];

// linked list for siov, to store failed data
struct mutex sclda_siov_mutex[SCLDA_SCI_NUM];
struct sclda_iov_ls siov_heads[SCLDA_SCI_NUM];
struct sclda_iov_ls *siov_tails[SCLDA_SCI_NUM];


// linked list's mutex, head, tail, number in list
struct mutex sclda_syscall_mutex[SCLDA_SCI_NUM];
struct sclda_syscallinfo_ls sclda_syscall_heads[SCLDA_SCI_NUM];
struct sclda_syscallinfo_ls *sclda_syscall_tails[SCLDA_SCI_NUM];
int sclda_syscallinfo_num[SCLDA_SCI_NUM];

// current index
// we must use get_sclda_sci_index() and
// add_sclda_sci_index() to protect this value by mutex
static DEFINE_MUTEX(sclda_sci_index_mutex);
int sclda_sci_index = 0;

static int get_sclda_sci_index(void) {
    int current_index;

    mutex_lock(&sclda_sci_index_mutex);
    current_index = sclda_sci_index;
    mutex_unlock(&sclda_sci_index_mutex);
    return current_index;
}

static void add_sclda_sci_index(void) {
    mutex_lock(&sclda_sci_index_mutex);
    sclda_sci_index = (sclda_sci_index + 1) % SCLDA_SCI_NUM;
    mutex_unlock(&sclda_sci_index_mutex);
}

// for common.c: init
int sclda_syscall_init(void) {
    size_t i;
    // init syscallinfo linked list
    for (i = 0; i < SCLDA_SCI_NUM; i++) {
        mutex_init(&sclda_siov_mutex[i]);
        siov_heads[i].next = NULL;
        siov_tails[i] = &siov_heads[i];
        mutex_init(&sclda_syscall_mutex[i]);
        sclda_syscall_heads[i].next = NULL;
        sclda_syscall_tails[i] = &sclda_syscall_heads[i];
        sclda_syscallinfo_num[i] = 0;
    }

    // init sclda_client_struct
    for (i = 0; i < SCLDA_PORT_NUMBER; i++)
        init_sclda_client(&sclda_syscall_client[i], SCLDA_SYSCALL_BASEPORT + i);
    return 0;
}

static int kfree_scinfo_ls(struct sclda_syscallinfo_ls *scinfo_ptr) {
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
    temp->data.str = kmallc(SCLDA_CHUNKSIZE, GFP_KERNEL);
    if (!(temp->data.str)) {
        kfree(temp);
        return -EFAULT;
    }
    *siov = temp;
    return 0;
}

static int scinfo_to_siov(int target_index) {
    int cnt = 0;
    size_t i, chnk_remain, data_remain, written;
    struct sclda_syscallinfo_ls *curptr, *next;
    struct sclda_iov_ls *temp;
    if (!init_siovls(&temp)) return -EFAULT;

    mutex_lock(&sclda_syscall_mutex[target_index]);

    curptr = sclda_syscall_heads[target_index].next;
    while (curptr != NULL) {
        for (i = 0; i < curptr->sc_iov_len; i++) {
            if (temp->data.len + curptr->pid_time.len + curptr->syscall[i].len <
                SCLDA_CHUNKSIZE) {
                // まだchunkに余裕がある場合
                temp->data.len +=
                    snprintf(temp->data.str + temp->data.len,
                             SCLDA_CHUNKSIZE - temp->data.len, "%s%c%s%c",
                             curptr->pid_time.str, SCLDA_EACH_DLMT,
                             curptr->syscall[i].str, SCLDA_EACH_DLMT);
            } else {
                // chunkに余裕が無い場合
                data_remain = curptr->syscall[i].len;
                while (data_remain != 0) {
                    chnk_remain = SCLDA_CHUNKSIZE - temp->data.len - 1;
                    if (chnk_remain < curptr->pid_time.len) {
                        // これ以上書き込めないため、先に
                        // データを保存 + tempを再初期化
                        mutex_lock(&sclda_siov_mutex[target_index]);
                        siov_tails[target_index]->next = temp;
                        siov_tails[target_index] =
                            siov_tails[target_index]->next;
                        mutex_unlock(&sclda_siov_mutex[target_index]);
                        if (!init_siovls(&temp)) {
                            // 失敗したため、終わった部分と
                            // 終わってない部分を切り分け、引き継ぎを行う
                            sclda_syscall_heads[target_index].next = curptr;
                            sclda_syscallinfo_num[target_index] -= cnt;
                            goto out;
                        };
                        chnk_remain = SCLDA_CHUNKSIZE;
                    }
                    // 分割して書き込む
                    chnk_remain -= 2 + curptr->pid_time.len;
                    chnk_remain = min(chnk_remain, data_remain);
                    temp->data.len += snprintf(
                        temp->data.str + temp->data.len,
                        SCLDA_CHUNKSIZE - temp->data.len, "%s%c%.*s%c",
                        curptr->pid_time.str, SCLDA_EACH_DLMT, (int)chnk_remain,
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

static int sclda_sendall_syscallinfo(void *data) {
    int target_index, send_ret;
    size_t cnt = 0;
    struct sclda_iov_ls dmhead, *dmtail;
    struct sclda_iov_ls *curptr, *next;

    target_index = *(int *)data;
    kfree(data);

    dmhead.next = NULL;
    dmtail = &dmhead;

    // scinfo_ls -> siov_ls
    scinfo_to_siov(target_index);

    // send all siov
    mutex_lock(&sclda_siov_mutex[target_index]);
    curptr = siov_heads[target_index].next;
    while (curptr != NULL) {
        send_ret = sclda_send_siov_mutex(
            &(curptr->data), sclda_syscall_client[cnt % SCLDA_PORT_NUMBER]);

        if (send_ret < 0) {
            dmtail->next = curptr;
            dmtail = dmtail->next;
        }

        next = curptr->next;
        if (send_ret >= 0) {
            kfree(curptr->data.str);
            kfree(curptr);
        }
        curptr = next;
        cnt += 1;
    }

    mutex_unlock(&sclda_siov_mutex[target_index]);
    return 0;
}

// this is a helper function which init the single link list
// if return -ENOMEM, init was failed
static int sclda_syscallinfo_init(struct sclda_syscallinfo_ls **ptr) {
    struct sclda_syscallinfo_ls *s;

    s = kmalloc(sizeof(struct sclda_syscallinfo_ls), GFP_KERNEL);
    if (!s) goto out;

    s->pid_time.str = kmalloc(SCLDA_PID_CLOCK_SIZE, GFP_KERNEL);
    if (!(s->pid_time.str)) goto free_scinfo;

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

// This function simply add the element
// to the current sclda_sci_index head
static int sclda_add_syscallinfo(struct sclda_syscallinfo_ls *ptr) {
    int current_index;

    current_index = get_sclda_sci_index();
    mutex_lock(&sclda_syscall_mutex[current_index]);

    sclda_syscall_tails[current_index]->next = ptr;
    sclda_syscall_tails[current_index] =
        sclda_syscall_tails[current_index]->next;
    sclda_syscallinfo_num[current_index]++;

    mutex_unlock(&sclda_syscall_mutex[current_index]);
    return 0;
}

// this function starts to send the data
// in current sclda_sci_index list
// if the number in list >= SCLDA_NUM_TO_SEND_SINFO
static int sclda_wakeup_kthread(void) {
    int current_index;
    int *arg;
    struct task_struct *newkthread;

    current_index = get_sclda_sci_index();
    mutex_lock(&sclda_syscall_mutex[current_index]);

    if (sclda_syscallinfo_num[current_index] < SCLDA_NUM_TO_SEND_SINFO)
        goto out;

    add_sclda_sci_index();

    arg = kmalloc(sizeof(int), GFP_KERNEL);
    if (!arg) return -ENOMEM;
    *arg = current_index;
    newkthread = kthread_create(sclda_sendall_syscallinfo, arg, "sclda_thread");
    if (!IS_ERR(newkthread)) wake_up_process(newkthread);

out:
    mutex_unlock(&sclda_syscall_mutex[current_index]);
    return 0;
}

int sclda_send_syscall_info(char *msg_buf, int msg_len) {
    int retval;
    struct sclda_syscallinfo_ls *s;

    if (!is_sclda_allsend_fin()) return 0;

    retval = sclda_syscallinfo_init(&s);
    if (retval < 0) goto free_msg_buf;

    s->syscall = kmalloc_array(1, sizeof(struct sclda_iov), GFP_KERNEL);
    if (!(s->syscall)) {
        retval = -ENOMEM;
        goto free_syscallinfo;
    }

    s->sc_iov_len = 1;
    s->syscall[0].len = msg_len;
    s->syscall[0].str = msg_buf;
    sclda_add_syscallinfo(s);
    sclda_wakeup_kthread();
    return 0;

free_syscallinfo:
    kfree(s->pid_time.str);
    kfree(s);
free_msg_buf:
    kfree(msg_buf);
    return retval;
}

int sclda_send_syscall_info2(struct sclda_iov *siov_ls, unsigned long num) {
    size_t i;
    int retval;
    struct sclda_syscallinfo_ls *s;

    if (!is_sclda_allsend_fin()) return 0;

    retval = sclda_syscallinfo_init(&s);
    if (retval < 0) {
        for (i = 0; i < num; i++) kfree(siov_ls[i].str);
        return retval;
    }

    s->sc_iov_len = num;
    s->syscall = siov_ls;

    sclda_add_syscallinfo(s);
    sclda_wakeup_kthread();
    return 0;
}
