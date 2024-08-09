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

// linked list's mutex, head, tail, number in list
struct mutex sclda_syscall_mutex[SCLDA_SCI_NUM];
struct sclda_syscallinfo_ls sclda_syscall_heads[SCLDA_SCI_NUM];
struct sclda_syscallinfo_ls *sclda_syscall_tails[SCLDA_SCI_NUM];
int sclda_syscallinfo_num[SCLDA_SCI_NUM];

// current index
// we must use get_sclda_sci_index() and
// add_sclda_sci_index; to protect this value by mutex
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

int sclda_syscall_init(void) {
    size_t i;
    // init syscallinfo linked list
    for (i = 0; i < SCLDA_SCI_NUM; i++) {
        mutex_init(&sclda_syscall_mutex[i]);
        sclda_syscall_heads[i].next = NULL;
        sclda_syscall_tails[i] = &sclda_syscall_heads[i];
        sclda_syscallinfo_num[i] = 0;
    }

    // init sclda_client_struct
    for (i = 0; i < SCLDA_PORT_NUMBER; i++)
        __init_sclda_client(&sclda_syscall_client[i],
                            SCLDA_SYSCALL_BASEPORT + i);
    return 0;
}

// split the data (length = SCLDA_CHUNKSIZE)
// and send it to the sclda_host server
static int sclda_send_split(struct sclda_syscallinfo_ls *ptr, int which_port) {
    int retval = -EFAULT;
    int send_ret;
    char *packet_buf;
    size_t packet_len, max_packet_len;
    size_t offset, len, i;

    max_packet_len = SCLDA_CHUNKSIZE + (size_t)ptr->pid_time.len + 1;
    packet_buf = kmalloc(max_packet_len, GFP_KERNEL);
    if (!packet_buf) goto out;

    for (i = 0; i < ptr->sc_iov_len; i++) {
        offset = 0;
        len = 0;
        if (ptr->syscall[i].str == NULL) continue;
        if (ptr->syscall[i].len <= 0) continue;

        while (offset < ptr->syscall[i].len) {
            memset(packet_buf, 0, max_packet_len);
            len = min(SCLDA_CHUNKSIZE, ptr->syscall[i].len - offset);

            packet_len = snprintf(packet_buf, max_packet_len, "%s%.*s",
                                  ptr->pid_time.str, (int)len,
                                  ptr->syscall[i].str + offset);
            if (packet_len <= 0) goto free_packet_buf;

            send_ret = sclda_send_mutex(packet_buf, packet_len,
                                        &sclda_syscall_client[which_port]);
            if (send_ret < 0) goto free_packet_buf;
            offset += len;
        }
    }
    retval = 0;

free_packet_buf:
    kfree(packet_buf);
out:
    return retval;
}

// operate single link list(sclda_syscallinfo_ls)
// to send data to the host server
static int sclda_sendall_syscallinfo(void *data) {
    int target_index, send_ret, failed_cnt, i, cnt;
    struct sclda_syscallinfo_ls *curptr, *next;
    struct sclda_syscallinfo_ls dummy_head, *dummy_tail;
    dummy_head.next = NULL;
    dummy_tail = &dummy_head;
    cnt = 0;
    failed_cnt = 0;

    target_index = *(int *)data;
    kfree(data);

    mutex_lock(&sclda_syscall_mutex[target_index]);
    curptr = sclda_syscall_heads[target_index].next;
    while (curptr != NULL) {
        send_ret = sclda_send_split(curptr, cnt % SCLDA_PORT_NUMBER);
        next = curptr->next;
        if (send_ret < 0) {
            failed_cnt++;
            dummy_tail->next = curptr;
            dummy_tail = dummy_tail->next;
        } else {
            kfree(curptr->pid_time.str);
            for (i = 0; i < curptr->sc_iov_len; i++) {
                kfree(curptr->syscall[i].str);
            }
            kfree(curptr->syscall);
        }
        curptr = next;
        cnt = cnt + 1;
    }

    dummy_tail->next = NULL;
    sclda_syscallinfo_num[target_index] = failed_cnt;
    sclda_syscall_heads[target_index].next = dummy_head.next;
    mutex_unlock(&sclda_syscall_mutex[target_index]);
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
