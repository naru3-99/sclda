#include <net/sclda.h>
#include <linux/init.h>

struct sclda_client_struct pidppid_sclda;
struct sclda_client_struct syscall_sclda[SCLDA_PORT_NUMBER];
struct sclda_str_list sclda_strls_head = { "\0", 1,
					   (struct sclda_str_list *)NULL };
int sclda_init_fin = 0;

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
	if (__sclda_create_socket(sclda_cs_ptr) < 0 ||
	    __sclda_connect_socket(sclda_cs_ptr, port) < 0) {
		printk(KERN_INFO "SCLDA_ERROR %d", port);
		return -1;
	}

	sclda_cs_ptr->msg.msg_name = &(sclda_cs_ptr->addr);
	sclda_cs_ptr->msg.msg_namelen = sizeof(struct sockaddr_in);
	sclda_cs_ptr->msg.msg_iter = sclda_cs_ptr->iov_it;
	sclda_cs_ptr->msg.msg_control = NULL;
	sclda_cs_ptr->msg.msg_controllen = 0;
	sclda_cs_ptr->msg.msg_flags = 0;
	return 0;
}

int init_all_sclda(void)
{
	// init all sclda_client_struct
	__init_sclda_client(&pidppid_sclda, SCLDA_PIDPPID_PORT);
	for (size_t i = 0; i < SCLDA_PORT_NUMBER; i++) {
		__init_sclda_client(&syscall_sclda[i],
				    SCLDA_SYSCALL_BASEPORT + i);
	}
	sclda_init_fin = 1;
	return 0;
}

static int __init sclda_init(void)
{
	init_all_sclda();
	sclda_all_send_strls();
	return 0;
}

late_initcall(sclda_init);

// 文字列を送信するための最もかんたんな実装
static DEFINE_MUTEX(sclda_send_mutex);
void __sclda_send(char *buf, int len,
		  struct sclda_client_struct *sclda_struct_ptr)
{
	struct kvec iov;
	iov.iov_base = buf;
	iov.iov_len = len;
	kernel_sendmsg(sclda_struct_ptr->sock, &(sclda_struct_ptr->msg), &iov,
		       1, len);
}

void sclda_send(char *buf, int len,
		struct sclda_client_struct *sclda_struct_ptr)
{
	mutex_lock(&sclda_send_mutex);
	__sclda_send(buf, len, sclda_struct_ptr);
	mutex_unlock(&sclda_send_mutex);
}

void __sclda_send_split(char *msg, int msg_len)
{
	// 大きいサイズの文字列を分割して送信する
	// system-call関連情報を送信するときのみ使用する
	size_t sent_bytes = 0;
	size_t chunk_size;
	struct sclda_client_struct *sclda_to_send = sclda_decide_struct();

	// pid utimeはどのプロセスのシステムコールかを特定するために使用する
	int pid = sclda_get_current_pid();
	u64 utime = current->utime;
	// 50あれば十分かな
	char *pid_utime = kmalloc(50, GFP_KERNEL);
	int header_len = snprintf(pid_utime, 50, "%d%c%llu%c", pid,
				  SCLDA_DELIMITER, utime, SCLDA_DELIMITER);

	int packet_len = SCLDA_CHUNKSIZE + header_len + 1;
	char *sending_msg = kmalloc(packet_len, GFP_KERNEL);

	while (sent_bytes < msg_len) {
		if ((msg_len - sent_bytes) < SCLDA_CHUNKSIZE) {
			chunk_size = msg_len - sent_bytes;
		} else {
			chunk_size = SCLDA_CHUNKSIZE;
		}
		snprintf(sending_msg, packet_len, "%s%s", pid_utime,
			 msg + sent_bytes);
		sclda_send(sending_msg, packet_len, sclda_to_send);
		sent_bytes += chunk_size;
	}
	kfree(sending_msg);
	kfree(pid_utime);
}

void sclda_send_split(char *msg, int msg_len)
{
	// pid utimeは__sclda_send_split関数で付加する
	// ここで付加する情報：
	// stime:kernel空間で消費した時間
	// スタック・ヒープ・メモリ全体の現在の消費量
	int add_bufsize = 200;
	char add_str[add_bufsize];
	add_bufsize = snprintf(add_str, add_bufsize, "%llu%c%lu%c%lu%c%lu%c",
			       current->stime, SCLDA_DELIMITER,
			       sclda_get_current_spsize(), SCLDA_DELIMITER,
			       sclda_get_current_heapsize(), SCLDA_DELIMITER,
			       sclda_get_current_totalsize(), SCLDA_DELIMITER);
	int new_len = msg_len + add_bufsize + 1;
	char *new_msg = kmalloc(new_len, GFP_KERNEL);
	new_len = snprintf(new_msg, new_len, "%s%s", add_str, msg);
	__sclda_send_split(new_msg, new_len);
	kfree(new_msg);
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

void sclda_add_string(const char *msg, int len)
{
	struct sclda_str_list *new_node =
		kmalloc(sizeof(struct sclda_str_list), GFP_KERNEL);
	if (!new_node)
		return;

	strlcpy(new_node->str, msg, SCLDA_PIDPPID_BUFSIZE);
	new_node->len = len;
	new_node->next = NULL;

	struct sclda_str_list *current_ptr = &sclda_strls_head;
	while (current_ptr->next != NULL) {
		current_ptr = current_ptr->next;
	}
	current_ptr->next = new_node;
}

void sclda_all_send_strls(void)
{
	struct sclda_str_list *curptr = sclda_strls_head.next;
	struct sclda_client_struct *pid_sclda = sclda_get_pidppid_struct();
	while (curptr != NULL) {
		if (curptr->len > 0) {
			__sclda_send(curptr->str, curptr->len, pid_sclda);
		}
		struct sclda_str_list *next = curptr->next;
		kfree(curptr);
		curptr = next;
	}
}

struct sclda_str_list *get_sclda_str_list_head(void)
{
	return &sclda_strls_head;
}

int is_sclda_init_fin(void)
{
	return sclda_init_fin;
}
