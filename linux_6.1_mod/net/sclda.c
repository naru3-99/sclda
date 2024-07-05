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

// PIDの情報を送信するためのソケットなど
struct sclda_client_struct pidppid_sclda;
// システムコールの情報を送信するためのソケット
// CPUのIDのに応じて送信するポートを変更する
struct sclda_client_struct syscall_sclda[SCLDA_PORT_NUMBER];

// PIDの配列を操作するときのmutex
static DEFINE_MUTEX(pidinfo_mutex);
// PID情報のダミーヘッド
struct sclda_pidinfo_ls sclda_pidinfo_head = { .next = NULL,
					       .pid_info.len = 0,
					       .pid_info.str = NULL };
// PID情報の末尾
struct sclda_pidinfo_ls *sclda_pidinfo_tail = &sclda_pidinfo_head;

// syscallの配列を操作するときのmutex
static struct mutex syscall_mutex[SCLDA_SCI_NUM];
// システムコール情報のダミーヘッド
struct sclda_syscallinfo_ls sclda_syscall_heads[SCLDA_SCI_NUM];
// システムコール情報の末尾
struct sclda_syscallinfo_ls *sclda_syscall_tails[SCLDA_SCI_NUM];
// syscallinfo_structがいくつ溜まっているか
int sclda_syscallinfo_exist[SCLDA_SCI_NUM];

// どのsyscallinfo構造体のヘッド or mutexに追加するか
int sclda_sci_index = 0;

// ソケットなどの初期化が済んだかどうか
int sclda_init_fin = 0;
// PIDの情報を送信したかどうか
int sclda_allsend_fin = 0;

// 各ソケットに関数を一つづつ用意する
DEFINE_SCLDA_SEND_FUNC(0)
DEFINE_SCLDA_SEND_FUNC(1)
DEFINE_SCLDA_SEND_FUNC(2)
DEFINE_SCLDA_SEND_FUNC(3)
DEFINE_SCLDA_SEND_FUNC(4)
DEFINE_SCLDA_SEND_FUNC(5)
DEFINE_SCLDA_SEND_FUNC(6)
DEFINE_SCLDA_SEND_FUNC(7)
DEFINE_SCLDA_SEND_FUNC(8)
DEFINE_SCLDA_SEND_FUNC(9)
DEFINE_SCLDA_SEND_FUNC(10)
DEFINE_SCLDA_SEND_FUNC(11)
DEFINE_SCLDA_SEND_FUNC(12)
DEFINE_SCLDA_SEND_FUNC(13)
DEFINE_SCLDA_SEND_FUNC(14)
DEFINE_SCLDA_SEND_FUNC(15)

// 関数を関数ポインタ配列に格納する
sclda_send_f sclda_send_funcs[SCLDA_PORT_NUMBER];

int __sclda_create_socket(struct sclda_client_struct *sclda_cs_ptr)
{
	return sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP,
				&(sclda_cs_ptr->sock));
}

int __sclda_connect_socket(struct sclda_client_struct *sclda_cs_ptr, int port)
{
	sclda_cs_ptr->addr.sin_family = PF_INET;
	sclda_cs_ptr->addr.sin_port = htons(port);
	sclda_cs_ptr->addr.sin_addr.s_addr = htonl(SCLDA_SERVER_IP);

	return kernel_connect(sclda_cs_ptr->sock,
			      (struct sockaddr *)(&(sclda_cs_ptr->addr)),
			      sizeof(struct sockaddr_in), 0);
}

int __init_sclda_client(struct sclda_client_struct *sclda_cs_ptr, int port)
{
	if (__sclda_create_socket(sclda_cs_ptr) < 0) {
		printk(KERN_INFO "SCLDA_ERROR socket create error: %d", port);
		return -1;
	}
	if (__sclda_connect_socket(sclda_cs_ptr,
				   port + SCLDA_SYSCALL_BASEPORT) < 0) {
		// 今回はUDP通信なので、ここがエラーはいても問題ない
		// UDP通信はコネクションレスな通信であるため
		printk(KERN_INFO "SCLDA_ERROR socket connect error: %d", port);
	}

	sclda_cs_ptr->msg.msg_name = &(sclda_cs_ptr->addr);
	sclda_cs_ptr->msg.msg_namelen = sizeof(struct sockaddr_in);
	sclda_cs_ptr->msg.msg_iter = sclda_cs_ptr->iov_it;
	sclda_cs_ptr->msg.msg_control = NULL;
	sclda_cs_ptr->msg.msg_controllen = 0;
	sclda_cs_ptr->msg.msg_flags = 0;
	mutex_init(&sclda_cs_ptr->mtx);
	sclda_cs_ptr->send_mesg = sclda_send_funcs[port];
	return 0;
}

int sclda_init(void)
{
	// scldaの初期化を行う
	// init/main.cで呼び出す
	for (size_t i = 0; i < SCLDA_SCI_NUM; i++) {
		// mutexの初期化
		mutex_init(&syscall_mutex[i]);
		// 末尾の初期化
		sclda_syscall_tails[i] = &sclda_syscall_heads[i];
		// まだ溜まっていないから0で初期化
		sclda_syscallinfo_exist[i] = 0;
	}

	sclda_send_funcs[0] = SCLDA_SEND_FUNC_NAME(0);
	sclda_send_funcs[1] = SCLDA_SEND_FUNC_NAME(1);
	sclda_send_funcs[2] = SCLDA_SEND_FUNC_NAME(2);
	sclda_send_funcs[3] = SCLDA_SEND_FUNC_NAME(3);
	sclda_send_funcs[4] = SCLDA_SEND_FUNC_NAME(4);
	sclda_send_funcs[5] = SCLDA_SEND_FUNC_NAME(5);
	sclda_send_funcs[6] = SCLDA_SEND_FUNC_NAME(6);
	sclda_send_funcs[7] = SCLDA_SEND_FUNC_NAME(7);
	sclda_send_funcs[8] = SCLDA_SEND_FUNC_NAME(8);
	sclda_send_funcs[9] = SCLDA_SEND_FUNC_NAME(9);
	sclda_send_funcs[10] = SCLDA_SEND_FUNC_NAME(10);
	sclda_send_funcs[11] = SCLDA_SEND_FUNC_NAME(11);
	sclda_send_funcs[12] = SCLDA_SEND_FUNC_NAME(12);
	sclda_send_funcs[13] = SCLDA_SEND_FUNC_NAME(13);
	sclda_send_funcs[14] = SCLDA_SEND_FUNC_NAME(14);
	sclda_send_funcs[15] = SCLDA_SEND_FUNC_NAME(15);

	__init_sclda_client(&pidppid_sclda, SCLDA_PIDPPID_PORT);
	for (size_t i = 0; i < SCLDA_PORT_NUMBER; i++) {
		__init_sclda_client(&syscall_sclda[i], i);
	}

	sclda_init_fin = 1;
	return 0;
}

// 文字列を送信するための最もかんたんな実装
int sclda_send(char *buf, int len, struct sclda_client_struct *sclda_struct_ptr)
{
	struct kvec iov;
	iov.iov_base = buf;
	iov.iov_len = len;
	return kernel_sendmsg(sclda_struct_ptr->sock, &(sclda_struct_ptr->msg),
			      &iov, 1, len);
}

// システムコールを送信するときのみ使用
int sclda_send_syscall(char *buf, int len, int which_port)
{
	int retval;
	retval = syscall_sclda[which_port].send_mesg(
		buf, len, syscall_sclda[which_port].sock,
		syscall_sclda[which_port].msg, syscall_sclda[which_port].mtx);
	ndelay(100);
	return retval;
}

// 送信する際に使うmutex
static DEFINE_MUTEX(send_mutex);
int sclda_send_mutex(char *buf, int len,
		     struct sclda_client_struct *sclda_struct_ptr)
{
	int ret = -1;
	if (!sclda_init_fin)
		return ret;
	mutex_lock(&send_mutex);
	ret = sclda_send(buf, len, sclda_struct_ptr);
	mutex_unlock(&send_mutex);
	return ret;
}

int __sclda_send_split(struct sclda_syscallinfo_ls *ptr, int which_port)
{
	// 大きいサイズの文字列を分割して送信する実装
	// ヘッダ情報としてPIDとutimeを最初にくっつける
	// system-call関連情報を送信するときのみ使用する
	int retval = -EFAULT;

	struct sclda_client_struct *sclda_to_send;
	char *chunkbuf, *sending_msg;
	int send_ret, sending_len, max_packet_len;

	// まだnetのinit が済んでいない場合
	if (!sclda_init_fin)
		goto out;

	// 送信先になるポートのclient_struct
	sclda_to_send = &syscall_sclda[which_port];

	// chunksizeのバッファを段取り
	chunkbuf = kmalloc(SCLDA_CHUNKSIZE + 1, GFP_KERNEL);
	if (!chunkbuf)
		goto out;

	// 一度に送信するパケットのバッファを段取り
	max_packet_len = SCLDA_CHUNKSIZE + ptr->pid_time.len + 1;
	sending_msg = kmalloc(max_packet_len, GFP_KERNEL);
	if (!sending_msg)
		goto free_chunkbuf;

	// 分割して送信する
	size_t offset, len, i;
	for (i = 0; i < ptr->sc_iov_len; i++) {
		offset = 0;
		len = 0;
		while (offset < ptr->syscall[i].len) {
			// chunksizeごとに文字列を分割
			len = min(SCLDA_CHUNKSIZE,
				  (size_t)(ptr->syscall[i].len - offset));
			memcpy(chunkbuf, ptr->syscall[i].str + offset, len);
			chunkbuf[len] = '\0';

			// 送信する文字列を段取り
			sending_len = snprintf(sending_msg, max_packet_len,
					       "%s%s", ptr->pid_time.str,
					       chunkbuf);
			// 文字列を送信
			send_ret = sclda_send_syscall(sending_msg, sending_len,
						      which_port);
			if (send_ret < 0)
				goto free_sending_msg;
			offset += len;
		}
	}
	retval = 0;

free_sending_msg:
	kfree(sending_msg);
free_chunkbuf:
	kfree(chunkbuf);
out:
	return retval;
}

int sclda_sendall_syscallinfo(void *data)
{
	int target_index, cnt, send_ret, failed_cnt, i;
	// while文でイテレーションを回すためのポインタ
	struct sclda_syscallinfo_ls *curptr, *next;
	// 失敗したときに退避するための頭・尻
	struct sclda_syscallinfo_ls temp_head, *temp_tail;

	// ターゲットになるindexを特定
	target_index = *(int *)data;
	kfree(data);

	// 順次送信を開始
	mutex_lock(&syscall_mutex[target_index]);
	// curptrを初期化し、全リストのデータを送信する
	curptr = sclda_syscall_heads[target_index].next;
	cnt = 0;
	failed_cnt = 0;
	// ダミ頭・尻の初期化
	temp_head.next = NULL;
	temp_tail = &temp_head;

	while (curptr != NULL) {
		send_ret = __sclda_send_split(curptr, cnt % SCLDA_PORT_NUMBER);
		next = curptr->next;
		if (send_ret < 0) {
			// 送信できていないため、tempに退避する
			failed_cnt++;
			temp_tail->next = curptr;
			temp_tail = temp_tail->next;
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
	sclda_syscall_heads[target_index].next = temp_head.next;
	if (temp_tail == &temp_head) {
		// 全て送信できた場合は、tailも初期化
		sclda_syscall_tails[target_index] =
			&sclda_syscall_heads[target_index];
	} else {
		sclda_syscall_tails[target_index] = temp_tail;
		sclda_syscall_tails[target_index]->next = NULL;
	}
	sclda_syscallinfo_exist[target_index] = failed_cnt;

	mutex_unlock(&syscall_mutex[target_index]);
	return 0;
}

int sclda_syscallinfo_init(struct sclda_syscallinfo_ls **ptr)
{
	// メモリ割り当て
	struct sclda_syscallinfo_ls *s;
	s = kmalloc(sizeof(struct sclda_syscallinfo_ls), GFP_KERNEL);
	if (!s)
		goto out;

	s->pid_time.str = kmalloc(SCLDA_PID_CLOCK_SIZE, GFP_KERNEL);
	if (!(s->pid_time.str))
		goto free_scinfo;

	// メモリ割り当てが成功したら、情報を初期化する
	s->next = NULL;
	s->pid_time.len = snprintf(s->pid_time.str, SCLDA_PID_CLOCK_SIZE,
				   "%d%c%llu%c", sclda_get_current_pid(),
				   SCLDA_DELIMITER, sched_clock(),
				   SCLDA_DELIMITER);

	*ptr = s;
	return 0;

free_scinfo:
	kfree(s);
out:
	return -ENOMEM;
}

int sclda_add_syscallinfo(struct sclda_syscallinfo_ls *ptr)
{
	// リストを末端に追加する
	mutex_lock(&syscall_mutex[sclda_sci_index]);
	// 末尾に追加する
	sclda_syscall_tails[sclda_sci_index]->next = ptr;
	sclda_syscall_tails[sclda_sci_index] =
		sclda_syscall_tails[sclda_sci_index]->next;
	// 一つ増やす
	sclda_syscallinfo_exist[sclda_sci_index]++;
	mutex_unlock(&syscall_mutex[sclda_sci_index]);
	return 0;
}

// 溜まってたときに送信し始める関数
int sclda_start_to_send(void)
{
	struct task_struct *newkthread;
	int *arg;

	arg = kmalloc(sizeof(int), GFP_KERNEL);
	if (!arg)
		return -ENOMEM;
	*arg = sclda_sci_index;

	// current_indexの更新
	sclda_sci_index = (sclda_sci_index + 1) % SCLDA_SCI_NUM;

	// 送信メカニズムを呼び出す
	newkthread =
		kthread_create(sclda_sendall_syscallinfo, arg, "sclda_sendall");
	if (!IS_ERR(newkthread))
		wake_up_process(newkthread);
	return 0;
}

// SYSCALL_DEFINEマクロ内で使用する関数
// 送信し終えたときに、送信したものが、
// msg_buf, syscallinfoを解放する責任を負う
static DEFINE_MUTEX(send_by_kthread);
int sclda_send_syscall_info(char *msg_buf, int msg_len)
{
	int retval;
	struct sclda_syscallinfo_ls *s;

	// ノードを初期化する
	retval = sclda_syscallinfo_init(&s);
	if (retval < 0) {
		kfree(msg_buf);
		return retval;
	}

	s->syscall = kmalloc_array(1, sizeof(struct sclda_iov), GFP_KERNEL);
	if (!(s->syscall))
		goto free_syscallinfo;
	s->sc_iov_len = 1;
	s->syscall[0].len = msg_len;
	s->syscall[0].str = msg_buf;

	// リストにノードを追加する
	retval = sclda_add_syscallinfo(s);

	// リストが溜まっていたら、送信する
	if (mutex_is_locked(&send_by_kthread))
		return retval;

	mutex_lock(&send_by_kthread);
	if (sclda_syscallinfo_exist[sclda_sci_index] < SCLDA_NUM_TO_SEND_SINFO)
		goto out;
	sclda_start_to_send();

out:
	mutex_unlock(&send_by_kthread);
	return retval;

free_syscallinfo:
	kfree(s->pid_time.str);
	kfree(s);
	kfree(msg_buf);
	return -ENOMEM;
}

int sclda_send_syscall_info2(struct sclda_iov *siov_ls, int num)
{
	int retval;
	struct sclda_syscallinfo_ls *s;

	// ノードを初期化する
	retval = sclda_syscallinfo_init(&s);
	if (retval < 0)
		goto out;
	s->syscall = siov_ls;
	s->sc_iov_len = num;

	// リストにノードを追加する
	retval = sclda_add_syscallinfo(s);

	// リストが溜まっていたら、送信する
	if (mutex_is_locked(&send_by_kthread))
		goto out;

	mutex_lock(&send_by_kthread);
	if (sclda_syscallinfo_exist[sclda_sci_index] < SCLDA_NUM_TO_SEND_SINFO)
		goto unlock_mutex;
	sclda_start_to_send();
unlock_mutex:
	mutex_unlock(&send_by_kthread);
out:
	return retval;
}

struct sclda_client_struct *sclda_get_pidppid_struct(void)
{
	return &pidppid_sclda;
}

int sclda_add_pidinfo(char *msg, int len)
{
	struct sclda_pidinfo_ls *new_node;
	new_node = kmalloc(sizeof(struct sclda_pidinfo_ls), GFP_KERNEL);
	if (!new_node)
		return -ENOMEM;

	new_node->pid_info.str = msg;
	new_node->pid_info.len = len;
	new_node->next = NULL;

	mutex_lock(&pidinfo_mutex);
	sclda_pidinfo_tail->next = new_node;
	sclda_pidinfo_tail = sclda_pidinfo_tail->next;
	mutex_unlock(&pidinfo_mutex);
	return 0;
}

void sclda_sendall_pidinfo(void)
{
	struct sclda_pidinfo_ls *curptr, *next;
	curptr = sclda_pidinfo_head.next;
	mutex_lock(&pidinfo_mutex);
	while (curptr != NULL) {
		sclda_send_mutex(curptr->pid_info.str, curptr->pid_info.len,
				 &pidppid_sclda);
		next = curptr->next;
		kfree(curptr->pid_info.str);
		kfree(curptr);
		curptr = next;
	}
	sclda_allsend_fin = 1;
	mutex_unlock(&pidinfo_mutex);
}

int sclda_get_current_pid(void)
{
	// 現在のPIDを取得する関数
	return (int)pid_nr(get_task_pid(current, PIDTYPE_PID));
}

int is_sclda_init_fin(void)
{
	return sclda_init_fin;
}

int is_sclda_allsend_fin(void)
{
	return sclda_allsend_fin;
}

int kernel_timespec_to_str(const struct __kernel_timespec __user *uptr,
			   char *msg_buf, int msg_len)
{
	// NULLだった場合は即返
	if (!uptr)
		return -EFAULT;

	struct __kernel_timespec kptr;
	if (copy_from_user(&kptr, uptr, sizeof(struct __kernel_timespec)))
		return -EFAULT;
	return snprintf(msg_buf, msg_len, "%lld%c%lld", kptr.tv_sec,
			SCLDA_DELIMITER, kptr.tv_nsec);
}