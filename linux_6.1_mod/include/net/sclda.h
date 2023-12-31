#ifndef SCLDA_H
#define SCLDA_H

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/netpoll.h>

#include <linux/mutex.h>
#include <linux/spinlock.h>

// char for separating data
#define SCLDA_DELIMITER ((char)0x05)

// server IP address for recieving udp packet
// 192.168.10.4
#define SCLDA_SERVER_IP ((unsigned long int)0xc0a83801)

// server port for gathering SYSCALL INFO
#define SYSCALL_PORT ((int)15001)
// server port for gathering PID-PPID
#define PIDPPID_PORT ((int)15002)
// server port for gathering Memory Usage
#define MEMORY_PORT ((int)15003)
// server port for gathering CPUTIME for executed Process
#define CPUTIME_PORT ((int)15004)

// maximum buffer for syscall infomation
#define SYSCALL_BUFSIZE ((int)1024)

// struct for ip address, port, string to send
struct sclda_client_struct {
	struct socket *sock;
	struct sockaddr_in addr;
	struct msghdr msg;
	struct iov_iter iov_it;
};

// init method for sclda_client_struct
int init_sclda_client(struct sclda_client_struct *, int);
// send string for each sclda_cilent
void sclda_send(char *, int, struct sclda_client_struct *);
// returns PID of current context
int sclda_get_current_pid(void);

#endif // SCLDA_H
