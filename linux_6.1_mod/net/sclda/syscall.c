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

// struct for communication
struct sclda_client_struct sclda_syscall_client[SCLDA_PORT_NUMBER];

// id for system call
static DEFINE_MUTEX(sclda_scid_mutex);
unsigned long long sclda_scid = 0;

// linked list for siov, to store failed data
struct mutex sclda_siov_mutex[SCLDA_SCI_NUM];
struct sclda_iov_ls siov_heads[SCLDA_SCI_NUM];
struct sclda_iov_ls *siov_tails[SCLDA_SCI_NUM];
int sclda_siovls_num[SCLDA_SCI_NUM];

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

// prototype
static int sclda_sendall_syscallinfo(void *data);

// getter/ setter for current sci_index
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

// identical number for each syscall
static unsigned long long get_scid(void) {
    unsigned long long ret;

    mutex_lock(&sclda_scid_mutex);
    ret = sclda_scid;
    sclda_scid += 1;
    mutex_unlock(&sclda_scid_mutex);
    return ret;
}

// for common.c: init
int sclda_syscall_init(void) {
    int retval;
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
        sclda_syscall_client[i].init_ok = 0;
        sclda_siovls_num[i] = 0;
    }

    // init sclda_client_struct
    for (i = 0; i < SCLDA_PORT_NUMBER; i++) {
        retval = init_sclda_client(&sclda_syscall_client[i],
                                   SCLDA_SYSCALL_BASEPORT + i);
        if (retval < 0) return retval;
    }

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
    s->syscall_id = get_scid();

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
    newkthread =
        kthread_create(sclda_sendall_syscallinfo, (void *)arg, "sclda_thread");
    if (!IS_ERR(newkthread)) wake_up_process(newkthread);

out:
    mutex_unlock(&sclda_syscall_mutex[current_index]);
    return 0;
}

// use these in SYSCALL_DEFINE MACRO
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

// for sclda_sendall_syscallinfo
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
    // +1 はNULL終端のため
    temp->data.str = kmalloc(SCLDA_CHUNKSIZE + 1, GFP_KERNEL);
    if (!(temp->data.str)) {
        kfree(temp);
        return -EFAULT;
    }

    memset(temp->data.str, 0, SCLDA_CHUNKSIZE + 1);
    *siov = temp;
    return 0;
}

static int save_siovls(struct sclda_iov_ls *siov, int target_index) {
    // データを保存
    mutex_lock(&sclda_siov_mutex[target_index]);
    siov_tails[target_index]->next = siov;
    siov_tails[target_index] = siov_tails[target_index]->next;
    sclda_siovls_num[target_index] += 1;
    mutex_unlock(&sclda_siov_mutex[target_index]);
    return 0;
}

static int scinfo_to_siov(int target_index, int use_mutex) {
    int i, cnt, succeeded = 0;
    size_t chnk_remain, written, writable;
    struct sclda_iov_ls *temp;
    struct sclda_syscallinfo_ls *curptr, *next;

    // init node
    if (init_siovls(&temp) < 0) return -EFAULT;

    // lock mutex and start to iterate
    if (use_mutex) mutex_lock(&sclda_syscall_mutex[target_index]);

    curptr = sclda_syscall_heads[target_index].next;
    while (curptr != NULL) {
        cnt = 0;
        for (i = 0; i < curptr->sc_iov_len; i++) {
            if (temp->data.len + curptr->syscall[i].len <
                SCLDA_LEAST_CHUNKSIZE) {
                // chunkに余裕がある場合
                temp->data.len +=
                    snprintf(temp->data.str + temp->data.len,
                             SCLDA_CHUNKSIZE - temp->data.len, "%c%llu%c%d%c",
                             SCLDA_MSG_START, curptr->syscall_id,
                             SCLDA_DELIMITER, cnt, SCLDA_DELIMITER);
                if (cnt == 0)
                    temp->data.len += snprintf(temp->data.str + temp->data.len,
                                               SCLDA_CHUNKSIZE - temp->data.len,
                                               "%s", curptr->pid_time.str);

                temp->data.len +=
                    snprintf(temp->data.str + temp->data.len,
                             SCLDA_CHUNKSIZE - temp->data.len, "%s%c",
                             curptr->syscall[i].str, SCLDA_MSG_END);
                cnt += 1;
                continue;
            }
            // chunkに余裕が無い場合
            // 分割して書き込む
            written = 0;
            while (curptr->syscall[i].len > written) {
                // 80% 以上埋まってたら保存する
                if (temp->data.len > SCLDA_LEAST_CHUNKSIZE) {
                    save_siovls(temp, target_index);
                    if (init_siovls(&temp) < 0) {
                        // 失敗 -> 引き継ぎ
                        sclda_syscall_heads[target_index].next = curptr;
                        sclda_syscallinfo_num[target_index] -= succeeded;
                        goto out;
                    }
                }
                // Least(80%)を使うのは、SCLDA_MSG_STARTや
                // pid_time_strなどが入る可能性があるため
                chnk_remain = SCLDA_LEAST_CHUNKSIZE - temp->data.len;
                writable = min(chnk_remain, curptr->syscall[i].len - written);
                temp->data.len +=
                    snprintf(temp->data.str + temp->data.len,
                             SCLDA_CHUNKSIZE - temp->data.len, "%c%llu%c%d%c",
                             SCLDA_MSG_START, curptr->syscall_id,
                             SCLDA_DELIMITER, cnt, SCLDA_DELIMITER);
                if (cnt == 0)
                    temp->data.len += snprintf(temp->data.str + temp->data.len,
                                               SCLDA_CHUNKSIZE - temp->data.len,
                                               "%s", curptr->pid_time.str);

                temp->data.len += snprintf(
                    temp->data.str + temp->data.len,
                    SCLDA_CHUNKSIZE - temp->data.len, "%.*s%c", (int)writable,
                    curptr->syscall[i].str + written, SCLDA_MSG_END);

                cnt += 1;
                written += writable;
            }
        }

        next = curptr->next;
        kfree_scinfo_ls(curptr);
        curptr = next;
        succeeded += 1;
    }
    // 残っているやつがあれば保存する
    if (temp->data.len > 0) save_siovls(temp, target_index);

    // scinfoのhead, tailを再初期化する
    sclda_syscall_heads[target_index].next = NULL;
    sclda_syscall_tails[target_index] = &sclda_syscall_heads[target_index];
    sclda_syscallinfo_num[target_index] = 0;
out:
    if (use_mutex) mutex_unlock(&sclda_syscall_mutex[target_index]);
    return 0;
}

static int sclda_sendall_siovls(int target_index) {
    struct sclda_iov_ls *curptr, *next;
    struct sclda_client_struct *target = &sclda_syscall_client[target_index];

    mutex_lock(&sclda_siov_mutex[target_index]);
    curptr = siov_heads[target_index].next;
    while (curptr != NULL) {
        sclda_send_mutex(curptr->data.str, curptr->data.len, target);
        next = curptr->next;
        kfree(curptr->data.str);
        kfree(curptr);
        curptr = next;
    }
    siov_tails[target_index] = &siov_heads[target_index];
    siov_tails[target_index]->next = NULL;
    mutex_unlock(&sclda_siov_mutex[target_index]);
    return 0;
}

static int sclda_sendall_syscallinfo(void *data) {
    int target_index;
    target_index = *(int *)data;
    kfree(data);

    // scinfo_ls -> siov_ls
    scinfo_to_siov(target_index, 1);
    // send all siov in linked list
    sclda_sendall_siovls(target_index);
    sclda_siovls_num[target_index] = 0;
    return 0;
}

int sclda_sendall_on_reboot(void) {
    size_t i;
    char buf[20];
    int len;

    // すべてのmutexロックを取得し、
    // これ以上データを追加しないようにする
    for (i = 0; i < SCLDA_SCI_NUM; i++) mutex_lock(&sclda_syscall_mutex[i]);

    // すべての残っている情報を送信する
    for (i = 0; i < SCLDA_SCI_NUM; i++) {
        if (sclda_syscallinfo_num[i] == 0 && sclda_siovls_num[i] == 0) continue;
        // sclda_sendall_siovlsがロックしている可能性があるため
        while(mutex_is_locked(&sclda_siov_mutex[i]));
        scinfo_to_siov(i, 0);
        sclda_sendall_siovls(i);
    }

    len = snprintf(buf, 20, "%csclda_reboot%c", SCLDA_MSG_START, SCLDA_MSG_END);

    // 終了したというメッセージを送信する
    sclda_send_mutex(buf, len, &(sclda_syscall_client[0]));

    // 一応アンロックして終了する
    for (i = 0; i < SCLDA_SCI_NUM; i++) mutex_unlock(&sclda_syscall_mutex[i]);
    return 0;
}

int print_sclda_debug(void) {
    struct sclda_iov siov;
    size_t i, written = 0;

    siov.len = 200;
    siov.str = kmalloc(siov.len, GFP_KERNEL);
    if (!siov.str) return 0;

    written = snprintf(siov.str, siov.len, "SCLDA_DEBUG siovls:");
    for (i = 0; i < SCLDA_SCI_NUM; i++)
        written += snprintf(siov.str + written, siov.len - written, "%d,",
                            sclda_siovls_num[i]);
    written +=
        snprintf(siov.str + written, siov.len - written, "\nscinfo:");
    for (i = 0; i < SCLDA_SCI_NUM; i++)
        written += snprintf(siov.str + written, siov.len - written, "%d,",
                            sclda_syscallinfo_num[i]);
    printk(KERN_ERR "%s", siov.str);

    kfree(siov.str);
    return 0;
}