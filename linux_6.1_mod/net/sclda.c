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
	(struct sclda_syscallinfo_ls *)NULL, (struct sclda_syscallinfo_ls *)NULL
};
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
	struct kvec iov;
	iov.iov_base = buf;
	iov.iov_len = len;
	return kernel_sendmsg(sclda_struct_ptr->sock, &(sclda_struct_ptr->msg),
			      &iov, 1, len);
}

static DEFINE_MUTEX(sclda_send_mutex);
int sclda_send_mutex(char *buf, int len,
		     struct sclda_client_struct *sclda_struct_ptr)
{
	int ret;
	mutex_lock(&sclda_send_mutex);
	ret = __sclda_send(buf, len, sclda_struct_ptr);
	mutex_unlock(&sclda_send_mutex);
	return ret;
}

void sclda_syscallinfo_init(struct sclda_syscallinfo_struct *ptr, char *msg,
			    int len)
{
	ptr = kmalloc(sizeof(struct sclda_syscallinfo_struct), GFP_KERNEL);
	// stime, memory usage
	ptr->stime_memory_len = snprintf(
		ptr->stime_memory_msg, SCLDA_STIME_MEMORY_SIZE,
		"%llu%c%lu%c%lu%c%lu%c", current->stime, SCLDA_DELIMITER,
		sclda_get_current_spsize(), SCLDA_DELIMITER,
		sclda_get_current_heapsize(), SCLDA_DELIMITER,
		sclda_get_current_totalsize(), SCLDA_DELIMITER);

	// utime, pid
	ptr->pid_utime_len = snprintf(ptr->pid_utime_msg, SCLDA_UTIME_PID_SIZE,
				      "%d%c%llu%c", sclda_get_current_pid(),
				      SCLDA_DELIMITER, current->utime,
				      SCLDA_DELIMITER);

	// msg, len
	ptr->syscall_msg = msg;
	ptr->syscall_msg_len = len;
}

static DEFINE_MUTEX(sclda_add_syscallinfo_mutex);
void sclda_add_syscallinfo(struct sclda_syscallinfo_struct *ptr)
{
	struct sclda_syscallinfo_ls *new_node =
		kmalloc(sizeof(struct sclda_syscallinfo_ls), GFP_KERNEL);
	if (!new_node)
		return;
	new_node->s = ptr;

	mutex_lock(&sclda_add_syscallinfo_mutex);
	struct sclda_syscallinfo_ls *current_ptr = &sclda_s_head;
	while (current_ptr->next != NULL) {
		current_ptr = current_ptr->next;
	}
	current_ptr->next = new_node;
	if (!sclda_syscallinfo_exist) {
		sclda_syscallinfo_exist = 1;
	}
	mutex_unlock(&sclda_add_syscallinfo_mutex);
}

int sclda_send_syscall_info(struct sclda_syscallinfo_struct *ptr)
{
	// 大きいサイズの文字列を分割して送信する実装
	// ヘッダ情報としてPIDとutimeを最初にくっつける
	// system-call関連情報を送信するときのみ使用する

	// 送信する情報を確定する
	int all_msg_len = ptr->stime_memory_len + ptr->syscall_msg_len + 1;
	char all_msg = kmalloc(all_msg_len, GFP_KERNEL);
	if (!all_msg) {
		printk(KERN_INFO "SCLDA_ERROR %s%s", pid_utime, msg);
		return -1;
	}
	all_msg_len = snprintf(all_msg, all_msg_len, "%s%s",
			       ptr->stime_memory_msg, ptr->syscall_msg);

	// chunksizeごとに分割して送信するパート
	// 一度に送信するパケットのバッファを段取り
	int max_packet_len = SCLDA_CHUNKSIZE + ptr->pid_utime_len + 1;
	char *sending_msg = kmalloc(max_packet_len, GFP_KERNEL);
	if (!sending_msg) {
		kfree(all_msg);
		printk(KERN_INFO "SCLDA_ERROR %s%s", pid_utime, msg);
		return -1;
	}

	// 送信に使用するソケットなどを決定
	struct sclda_client_struct *sclda_to_send = sclda_decide_struct();

	int packet_size;
	int ret;
	size_t sent_bytes = 0;
	size_t chunk_size;
	while (sent_bytes < all_msg_len) {
		if ((all_msg_len - sent_bytes) < SCLDA_CHUNKSIZE) {
			chunk_size = all_msg_len - sent_bytes;
		} else {
			chunk_size = SCLDA_CHUNKSIZE;
		}
		packet_size = snprintf(sending_msg, max_packet_len, "%s%.*s",
				       ptr->pid_utime_msg, (int)chunk_size,
				       all_msg + sent_bytes);
		ret = sclda_send_mutex(sending_msg, real_size, sclda_to_send);
		sent_bytes += chunk_size;
	}
	kfree(sending_msg);
	return ret;
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
