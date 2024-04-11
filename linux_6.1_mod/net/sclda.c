#include <net/sclda.h>

// PIDに関する情報を送るためのソケット
struct sclda_client_struct pidppid_sclda;
// システムコールに関連する情報を送信するためのソケット
// CPUのIDのに応じて送信するポートを変更する
struct sclda_client_struct syscall_sclda[SCLDA_PORT_NUMBER];
// PIDに関する情報を送信できないときのために
// PID情報のリンクリストのダミーヘッド
struct sclda_pidinfo_ls sclda_pidinfo_head = {
	"\0", 1, (struct sclda_pidinfo_ls *)NULL
};
// システムコール情報のダミーヘッド
struct sclda_syscallinfo_ls sclda_syscall_head = {
	(struct sclda_syscallinfo_struct *)NULL,
	(struct sclda_syscallinfo_ls *)NULL
};
// 末尾を持っておく
struct sclda_syscallinfo_ls *sclda_syscall_tail = NULL;
// ソケットなどの初期化が済んだかどうか
int sclda_init_fin = 0;
// PIDの情報を送信したかどうか
int sclda_allsend_fin = 0;
// 現在システムコールの情報が溜まっているかどうか
int sclda_syscallinfo_exist = 0;

int __sclda_create_socket(struct sclda_client_struct *sclda_cs_ptr)
{
	int ret = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP,
				   &(sclda_cs_ptr->sock));
	return ret;
}

int __sclda_connect_socket(struct sclda_client_struct *sclda_cs_ptr, int port)
{
	sclda_cs_ptr->addr.sin_family = PF_INET;
	sclda_cs_ptr->addr.sin_port = htons(port);
	sclda_cs_ptr->addr.sin_addr.s_addr = htonl(SCLDA_SERVER_IP);

	int ret = kernel_connect(sclda_cs_ptr->sock,
				 (struct sockaddr *)(&(sclda_cs_ptr->addr)),
				 sizeof(struct sockaddr_in), 0);
	return ret;
}

int __init_sclda_client(struct sclda_client_struct *sclda_cs_ptr, int port)
{
	if (__sclda_create_socket(sclda_cs_ptr) < 0) {
		printk(KERN_INFO "SCLDA_ERROR socket_create_error: %d", port);
		return -1;
	}
	if (__sclda_connect_socket(sclda_cs_ptr, port) < 0) {
		// 今回はUDP通信なので、ここがエラーはいても問題ない
		// UDP通信はコネクションレスな通信であるため
		printk(KERN_INFO "SCLDA_ERROR socket_connect_error: %d", port);
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

static DEFINE_MUTEX(sclda_sendmutex);
int sclda_send_mutex(char *buf, int len,
		     struct sclda_client_struct *sclda_struct_ptr)
{
	if (!sclda_init_fin)
		return -1;
	int ret;
	mutex_lock(&sclda_sendmutex);
	ret = sclda_send(buf, len, sclda_struct_ptr);
	mutex_unlock(&sclda_sendmutex);
	return ret;
}

int sclda_syscallinfo_init(struct sclda_syscallinfo_struct **ptr, char *msg,
			   int len)
{
	// メモリを割り当て、ポインタを初期化
	*ptr = kmalloc(sizeof(struct sclda_syscallinfo_struct), GFP_KERNEL);
	if (!*ptr) {
		printk(KERN_ERR "sclda_syscallinfo_init: kmalloc failed\n");
		return 0;
	}

	// メモリ割り当てが成功したら、情報を初期化
	struct sclda_syscallinfo_struct *s = *ptr;

	// stime, memory usage
	s->stime_memory_len = snprintf(
		s->stime_memory_msg, SCLDA_STIME_MEMORY_SIZE,
		"%llu%c%lu%c%lu%c%lu%c", current->stime, SCLDA_DELIMITER,
		sclda_get_current_spsize(), SCLDA_DELIMITER,
		sclda_get_current_heapsize(), SCLDA_DELIMITER,
		sclda_get_current_totalsize(), SCLDA_DELIMITER);

	// utime, pid
	s->pid_utime_len = snprintf(s->pid_utime_msg, SCLDA_UTIME_PID_SIZE,
				    "%d%c%llu%c", sclda_get_current_pid(),
				    SCLDA_DELIMITER, current->utime,
				    SCLDA_DELIMITER);

	// msg, len
	s->syscall_msg = msg;
	s->syscall_msg_len = len;
	return 1;
}

static DEFINE_MUTEX(sclda_add_syscallinfo_mutex);
void sclda_add_syscallinfo(struct sclda_syscallinfo_struct *ptr)
{
	mutex_lock(&sclda_add_syscallinfo_mutex);
	// 新しいリストを定義
	struct sclda_syscallinfo_ls *new_node =
		kmalloc(sizeof(struct sclda_syscallinfo_ls), GFP_KERNEL);
	if (!new_node) {
		mutex_unlock(&sclda_add_syscallinfo_mutex);
		return;
	}
	new_node->s = ptr;
	new_node->next = NULL;

	// ダミーヘッドの末尾に追加する
	if (sclda_syscall_tail == NULL) {
		sclda_syscall_head.next = new_node;
		sclda_syscall_tail = new_node;
	} else {
		sclda_syscall_tail = new_node;
	}

	// 溜まっている状態だから1に
	if (!sclda_syscallinfo_exist) {
		sclda_syscallinfo_exist = 1;
	}
	mutex_unlock(&sclda_add_syscallinfo_mutex);
}

int __sclda_send_split(struct sclda_syscallinfo_struct *ptr,
		       struct sclda_client_struct *sclda_to_send)
{
	// 大きいサイズの文字列を分割して送信する実装
	// ヘッダ情報としてPIDとutimeを最初にくっつける
	// system-call関連情報を送信するときのみ使用する
	if (!sclda_init_fin)
		return -1;

	// 送信する情報を確定する
	int all_msg_len = ptr->stime_memory_len + ptr->syscall_msg_len + 1;
	char *all_msg = kmalloc(all_msg_len, GFP_KERNEL);
	if (!all_msg) {
		printk(KERN_INFO "SCLDA_ERROR %s%s", ptr->pid_utime_msg,
		       ptr->syscall_msg);
		return -1;
	}
	all_msg_len = snprintf(all_msg, all_msg_len, "%s%s",
			       ptr->stime_memory_msg, ptr->syscall_msg);

	// chunksizeごとに分割して送信するパート
	// chunksizeのバッファを段取り
	char *chunkbuf = kmalloc(SCLDA_CHUNKSIZE + 1, GFP_KERNEL);
	if (!chunkbuf) {
		kfree(all_msg);
		printk(KERN_INFO "SCLDA_ERROR %s%s", ptr->pid_utime_msg,
		       ptr->syscall_msg);
		return -1;
	}
	// 一度に送信するパケットのバッファを段取り
	int max_packet_len = SCLDA_CHUNKSIZE + ptr->pid_utime_len + 1;
	char *sending_msg = kmalloc(max_packet_len, GFP_KERNEL);
	if (!sending_msg) {
		kfree(all_msg);
		kfree(chunkbuf);
		printk(KERN_INFO "SCLDA_ERROR %s%s", ptr->pid_utime_msg,
		       ptr->syscall_msg);
		return -1;
	}

	// 分割して送信する
	size_t offset = 0;
	size_t len = 0;
	int send_ret;
	int sending_len;
	while (offset < all_msg_len) {
		// chunksizeごとに文字列を分割
		len = min(SCLDA_CHUNKSIZE, (size_t)all_msg_len - offset);
		memcpy(chunkbuf, all_msg + offset, len);
		chunkbuf[len] = '\0';

		// 送信する文字列を段取り
		sending_len = snprintf(sending_msg, max_packet_len, "%s%s",
				       ptr->pid_utime_msg, chunkbuf);
		// 文字列を送信
		send_ret = sclda_send_mutex(sending_msg, sending_len,
					    sclda_to_send);
		if (send_ret < 0) {
			kfree(all_msg);
			kfree(chunkbuf);
			kfree(sending_msg);
			return send_ret;
		}

		offset += len;
	}

	kfree(all_msg);
	kfree(chunkbuf);
	kfree(sending_msg);
	return 1;
}

int sclda_send_syscall_info(struct sclda_syscallinfo_struct *ptr)
{
	int ret = __sclda_send_split(ptr, sclda_decide_struct());
	if (!ret)
		return ret;
	if (sclda_syscallinfo_exist) {
		struct task_struct *my_thread = kthread_run(
			sclda_sendall_syscall, NULL, "sclda_sendall_syscall");
		if (IS_ERR(my_thread)) {
			return PTR_ERR(my_thread);
		}
	}
	return ret;
}

int sclda_sendall_syscall(void *data)
{
	mutex_lock(&sclda_add_syscallinfo_mutex);
	struct sclda_syscallinfo_ls *curptr = sclda_syscall_head.next;
	struct sclda_syscallinfo_ls *next;
	int count = 0;
	while (curptr != NULL) {
		__sclda_send_split(curptr->s,
				   &(syscall_sclda[count % SCLDA_PORT_NUMBER]));
		next = curptr->next;
		kfree(curptr->s->syscall_msg);
		kfree(curptr);
		curptr = next;
	}
	sclda_syscallinfo_exist = 0;
	mutex_unlock(&sclda_add_syscallinfo_mutex);
	return 0;
}

int sclda_get_current_pid(void)
{
	return (int)pid_nr(get_task_pid(current, PIDTYPE_PID));
}

unsigned long sclda_get_current_spsize(void)
{
	return current->mm->stack_vm * PAGE_SIZE;
}

unsigned long sclda_get_current_heapsize(void)
{
	return current->mm->brk - current->mm->start_brk;
}

unsigned long sclda_get_current_totalsize(void)
{
	return current->mm->total_vm * PAGE_SIZE;
}

struct sclda_client_struct *sclda_decide_struct(void)
{
	unsigned int cpu_id = smp_processor_id();
	return &(syscall_sclda[cpu_id % SCLDA_PORT_NUMBER]);
}

struct sclda_client_struct *sclda_get_pidppid_struct(void)
{
	return &pidppid_sclda;
}

static DEFINE_MUTEX(sclda_addstr_mutex);
void sclda_add_string(const char *msg, int len)
{
	struct sclda_pidinfo_ls *new_node =
		kmalloc(sizeof(struct sclda_pidinfo_ls), GFP_KERNEL);
	if (!new_node)
		return;

	strlcpy(new_node->str, msg, SCLDA_PIDPPID_BUFSIZE);
	new_node->len = len;
	new_node->next = NULL;

	mutex_lock(&sclda_addstr_mutex);
	struct sclda_pidinfo_ls *current_ptr = &sclda_pidinfo_head;
	while (current_ptr->next != NULL) {
		current_ptr = current_ptr->next;
	}
	current_ptr->next = new_node;
	mutex_unlock(&sclda_addstr_mutex);
}

void sclda_all_send_strls(void)
{
	struct sclda_pidinfo_ls *curptr = sclda_pidinfo_head.next;
	struct sclda_pidinfo_ls *next;
	while (curptr != NULL) {
		sclda_send(curptr->str, curptr->len, &pidppid_sclda);
		next = curptr->next;
		kfree(curptr);
		curptr = next;
	}
	sclda_allsend_fin = 1;
}

struct sclda_pidinfo_ls *get_sclda_pidinfo_ls_head(void)
{
	return &sclda_pidinfo_head;
}

int is_sclda_init_fin(void)
{
	return sclda_init_fin;
}

int is_sclda_allsend_fin(void)
{
	return sclda_allsend_fin;
}
