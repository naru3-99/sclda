#include <net/sclda.h>

// PIDの情報を送信するためのソケットなど
struct sclda_client_struct pidppid_sclda;
// システムコールの情報を送信するためのソケット
// CPUのIDのに応じて送信するポートを変更する
struct sclda_client_struct syscall_sclda[SCLDA_PORT_NUMBER];

// PIDの配列を操作するときのmutex
static DEFINE_MUTEX(pidinfo_mutex);
// PID情報のダミーヘッド
struct sclda_pidinfo_ls sclda_pidinfo_head = {
	"\0", 1, (struct sclda_pidinfo_ls *)NULL
};
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
	if (__sclda_connect_socket(sclda_cs_ptr, port) < 0) {
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
	return 0;
}

int sclda_init(void)
{
	// scldaの初期化を行う
	// init/main.cで呼び出す
	for (size_t i = 0; i < SCLDA_SCI_NUM; i++) {
		// mutexの初期化
		mutex_init(&syscall_mutex[i]);
		// ダミーヘッドの初期化
		sclda_syscall_heads[i].s =
			(struct sclda_syscallinfo_struct *)NULL;
		sclda_syscall_heads[i].next =
			(struct sclda_syscallinfo_ls *)NULL;
		// 末尾の初期化
		sclda_syscall_tails[i] = &sclda_syscall_heads[i];
		// まだ溜まっていないから0で初期化
		sclda_syscallinfo_exist[i] = 0;
	}

	__init_sclda_client(&pidppid_sclda, SCLDA_PIDPPID_PORT);
	for (size_t i = 0; i < SCLDA_PORT_NUMBER; i++) {
		__init_sclda_client(&syscall_sclda[i],
				    SCLDA_SYSCALL_BASEPORT + i);
	}
	sclda_init_fin = 1;
	return 0;
}

// 文字列を送信するための最もかんたんな実装
int sclda_send(char *buf, int len, struct sclda_client_struct *sclda_struct_ptr)
{
	if (!sclda_init_fin)
		return -1;
	struct kvec iov;
	iov.iov_base = buf;
	iov.iov_len = len;
	return kernel_sendmsg(sclda_struct_ptr->sock, &(sclda_struct_ptr->msg),
			      &iov, 1, len);
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

int __sclda_send_split(struct sclda_syscallinfo_struct *ptr, int which_port)
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
	max_packet_len = SCLDA_CHUNKSIZE + ptr->pid_cputime_len + 1;
	sending_msg = kmalloc(max_packet_len, GFP_KERNEL);
	if (!sending_msg)
		goto free_chunkbuf;

	// 分割して送信する
	size_t offset = 0;
	size_t len = 0;
	while (offset < ptr->syscall_msg_len) {
		// chunksizeごとに文字列を分割
		len = min(SCLDA_CHUNKSIZE,
			  (size_t)(ptr->syscall_msg_len - offset));
		memcpy(chunkbuf, ptr->syscall_msg + offset, len);
		chunkbuf[len] = '\0';

		// 送信する文字列を段取り
		sending_len = snprintf(sending_msg, max_packet_len, "%s%s",
				       ptr->pid_cputime_msg, chunkbuf);
		// 文字列を送信
		send_ret = sclda_send_mutex(sending_msg, sending_len,
					    sclda_to_send);
		if (send_ret < 0)
			goto free_sending_msg;
		offset += len;
	}
	retval = 0;

free_sending_msg:
	kfree(sending_msg);
free_chunkbuf:
	kfree(chunkbuf);
out:
	return retval;
}

int sclda_syscallinfo_init(struct sclda_syscallinfo_struct **ptr, char *msg,
			   int len)
{
	// メモリを割り当て、ポインタを初期化
	struct sclda_syscallinfo_struct *s;
	s = kmalloc(sizeof(struct sclda_syscallinfo_struct), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	// メモリ割り当てが成功したら、情報を初期化する
	s->pid_cputime_len = snprintf(s->pid_cputime_msg, SCLDA_PID_CLOCK_SIZE,
				      "%d%c%llu%c", sclda_get_current_pid(),
				      SCLDA_DELIMITER, sched_clock(),
				      SCLDA_DELIMITER);

	// msg, len
	s->syscall_msg = msg;
	s->syscall_msg_len = len;
	*ptr = s;
	return 0;
}

int sclda_add_syscallinfo(struct sclda_syscallinfo_struct *ptr)
{
	// 新しいリストを定義
	struct sclda_syscallinfo_ls *new_node;
	new_node = kmalloc(sizeof(struct sclda_syscallinfo_ls), GFP_KERNEL);
	if (!new_node)
		return -ENOMEM;
	new_node->s = ptr;
	new_node->next = (struct sclda_syscallinfo_ls *)NULL;

	// リストを末端に追加する
	mutex_lock(&syscall_mutex[sclda_sci_index]);
	// 末尾に追加する
	sclda_syscall_tails[sclda_sci_index]->next = new_node;
	sclda_syscall_tails[sclda_sci_index] =
		sclda_syscall_tails[sclda_sci_index]->next;
	// 一つ増やす
	sclda_syscallinfo_exist[sclda_sci_index]++;
	mutex_unlock(&syscall_mutex[sclda_sci_index]);
	return 0;
}

// SYSCALL_DEFINEマクロ内で使用する関数
// 送信し終えたときに、送信したものが、
// msg_buf, syscallinfoを解放する責任を負う
static DEFINE_MUTEX(send_by_kthread);
int sclda_send_syscall_info(char *msg_buf, int msg_len)
{
	int retval;
	struct sclda_syscallinfo_struct *sss;

	retval = sclda_syscallinfo_init(&sss, msg_buf, msg_len);
	if (retval < 0) {
		// こいつの初期化ができなかったときは、
		// もうmsgの中身を送信するチャンスはない。
		kfree(msg_buf);
		return retval;
	}
	// リストに追加する
	retval = sclda_add_syscallinfo(sss);

	// リストが溜まっていたら、送信する
	if (mutex_is_locked(&send_by_kthread))
		return retval;

	mutex_lock(&send_by_kthread);
	if (sclda_syscallinfo_exist[sclda_sci_index] >
	    SCLDA_NUM_TO_SEND_SINFO) {
		struct task_struct *task;
		int *arg;

		arg = kmalloc(sizeof(int), GFP_KERNEL);
		if (!arg) {
			mutex_unlock(&send_by_kthread);
			return -ENOMEM;
		}
		*arg = sclda_sci_index;

		// current_indexの更新
		sclda_sci_index = (sclda_sci_index + 1) % SCLDA_SCI_NUM;

		// 送信メカニズムを呼び出す
		struct task_struct *newkthread;
		newkthread = kthread_create(sclda_sendall_syscallinfo, arg,
					    "sclda_sendall");
		if (!IS_ERR(newkthread))
			wake_up_process(newkthread);
	}
	mutex_unlock(&send_by_kthread);
	return retval;
}

int sclda_sendall_syscallinfo(void *data)
{
	int target_index, cnt, send_ret, failed_cnt;
	// while文でイテレーションを回すためのポインタ
	struct sclda_syscallinfo_ls *curptr, *next;
	// 失敗したときに退避するための頭・尻
	struct sclda_syscallinfo_ls temp_head, *temp_tail;

	// ターゲットになるindexを特定
	target_index = *(int *)data;
	kfree(data);

	mutex_lock(&syscall_mutex[target_index]);

	// curptrを初期化し、全リストのデータを送信する
	curptr = sclda_syscall_heads[target_index].next;
	cnt = 0;
	failed_cnt = 0;
	// ダミ頭・尻の初期化
	temp_head.s = (struct sclda_syscallinfo_struct *)NULL;
	temp_head.next = (struct sclda_syscallinfo_ls *)NULL;
	temp_tail = &temp_head;
	while (curptr != NULL) {
		send_ret =
			__sclda_send_split(curptr->s, cnt % SCLDA_PORT_NUMBER);
		next = curptr->next;
		if (send_ret < 0) {
			// 送信できていないため、tempに退避する
			failed_cnt = failed_cnt + 1;
			temp_tail->next = curptr;
			temp_tail = temp_tail->next;
		} else {
			// 送信できたので解放する
			kfree(curptr->s->syscall_msg); // msg_bufの解放
			kfree(curptr->s); // sclda_syscallinfo_structの解放
			kfree(curptr); // sclda_syscallinfo_lsの解放
		}
		curptr = next;
		cnt = cnt + 1;
	}
	// 頭・尻の再初期化
	sclda_syscallinfo_exist[target_index] = failed_cnt;
	sclda_syscall_heads[target_index].s = temp_head.s;
	sclda_syscall_heads[target_index].next = temp_head.next;
	sclda_syscall_tails[target_index] = temp_tail;
	sclda_syscall_tails[target_index]->next = NULL;
	mutex_unlock(&syscall_mutex[target_index]);
	return 0;
}

struct sclda_client_struct *sclda_get_pidppid_struct(void)
{
	return &pidppid_sclda;
}

void sclda_add_pidinfo(const char *msg, int len)
{
	struct sclda_pidinfo_ls *new_node =
		kmalloc(sizeof(struct sclda_pidinfo_ls), GFP_KERNEL);
	if (!new_node)
		return;

	strlcpy(new_node->str, msg, SCLDA_PIDPPID_BUFSIZE);
	new_node->len = len;
	new_node->next = NULL;

	mutex_lock(&pidinfo_mutex);
	sclda_pidinfo_tail->next = new_node;
	sclda_pidinfo_tail = sclda_pidinfo_tail->next;
	mutex_unlock(&pidinfo_mutex);
}

void sclda_sendall_pidinfo(void)
{
	struct sclda_pidinfo_ls *curptr = sclda_pidinfo_head.next;
	struct sclda_pidinfo_ls *next;
	mutex_lock(&pidinfo_mutex);
	while (curptr != NULL) {
		sclda_send(curptr->str, curptr->len, &pidppid_sclda);
		next = curptr->next;
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