#include <net/sclda.h>

struct sclda_client_struct pidppid_sclda;
struct sclda_client_struct syscall_sclda[4];

// ソケットを作成する関数
// only used for init_sclda_client
static int sclda_create_socket(struct sclda_client_struct *sclda_cs_ptr)
{
	int ret = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP,
				   &(sclda_cs_ptr->sock));
	return ret;
}

// ソケットを接続するための関数
// only used for init_sclda_client
static int sclda_connect_socket(struct sclda_client_struct *sclda_cs_ptr,
				int port)
{
	sclda_cs_ptr->addr.sin_family = PF_INET;
	sclda_cs_ptr->addr.sin_port = htons(port);
	sclda_cs_ptr->addr.sin_addr.s_addr = htonl(SCLDA_SERVER_IP);

	int ret = kernel_connect(sclda_cs_ptr->sock,
				 (struct sockaddr *)(&(sclda_cs_ptr->addr)),
				 sizeof(struct sockaddr), 0);
	return ret;
}

// sclda_client_structを初期化するための関数
int init_sclda_client(struct sclda_client_struct *sclda_cs_ptr, int port)
{
	if (sclda_create_socket(sclda_cs_ptr) < 0 ||
	    sclda_connect_socket(sclda_cs_ptr, port) < 0) {
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

// 文字列を送信するための最もかんたんな実装
static DEFINE_MUTEX(sclda_send_mutex);
void sclda_send(char *buf, int len,
		struct sclda_client_struct *sclda_struct_ptr)
{
	static struct kvec iov;

	mutex_lock(&sclda_send_mutex);
	iov.iov_base = buf;
	iov.iov_len = len;
	kernel_sendmsg(sclda_struct_ptr->sock, &(sclda_struct_ptr->msg), &iov,
		       1, len);
	mutex_unlock(&sclda_send_mutex);
}

// 大きいサイズの文字列を分割して送信するための追加関数
// system-call関連情報を送信するときのみ使用する
void sclda_send_split(char *msg, int msg_len)
{
	size_t sent_bytes = 0;
	size_t chunk_size;
	struct sclda_client_struct *sclda_to_send = sclda_decide_struct();
	while (sent_bytes < msg_len) {
		if ((msg_len - sent_bytes) < SCLDA_BUFSIZE) {
			chunk_size = msg_len - sent_bytes;
		} else {
			chunk_size = SCLDA_BUFSIZE;
		}

		sclda_send(msg + sent_bytes, chunk_size, sclda_to_send);
		sent_bytes += chunk_size;
	}
}

//現在のPIDを返す関数
int sclda_get_current_pid(void)
{
	return (int)pid_nr(get_task_pid(current, PIDTYPE_PID));
}

struct sclda_client_struct *sclda_decide_struct()
{
	unsigned int cpu_id = smp_processor_id();
	return &(syscall_sclda[cpu_id % 4]);
}