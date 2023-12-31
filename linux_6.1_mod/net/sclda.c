#include <net/sclda.h>

struct sclda_client_struct syscall_sclda;
struct sclda_client_struct pidppid_sclda;
struct sclda_client_struct memory_sclda;
struct sclda_client_struct cputime_sclda;

static int sclda_create_socket(struct sclda_client_struct *sclda_cs_ptr)
{
	int ret = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP,
				   &(sclda_cs_ptr->sock));
	if (ret) {
		return -1;
	}
	return 0;
}

static int sclda_connect_socket(struct sclda_client_struct *sclda_cs_ptr,
				int port)
{
	sclda_cs_ptr->addr.sin_family = PF_INET;
	sclda_cs_ptr->addr.sin_port = htons(port);
	sclda_cs_ptr->addr.sin_addr.s_addr = htonl(SCLDA_SERVER_IP);

	int ret = kernel_connect(sclda_cs_ptr->sock,
				 (struct sockaddr *)(&(sclda_cs_ptr->addr)),
				 sizeof(struct sockaddr), 0);
	if (ret) {
		return -1;
	}
	return 0;
}

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

static DEFINE_MUTEX(sclda_send_mutex);
void sclda_send(char *buf, int len, struct sclda_client_struct *sclda_cs_ptr)
{
	static struct kvec iov;

	mutex_lock(&sclda_send_mutex);
	iov.iov_base = buf;
	iov.iov_len = len;
	kernel_sendmsg(sclda_cs_ptr->sock, &(sclda_cs_ptr->msg), &iov, 1, len);
	mutex_unlock(&sclda_send_mutex);
}

int sclda_get_current_pid()
{
	return (int)pid_nr(get_task_pid(current, PIDTYPE_PID));
}