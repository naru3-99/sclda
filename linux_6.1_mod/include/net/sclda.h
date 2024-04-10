#ifndef SCLDA_H
#define SCLDA_H

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/netpoll.h>

#include <linux/slab.h>
#include <linux/sched.h>

#include <linux/mutex.h>
#include <linux/spinlock.h>

#include <linux/smp.h>

#define SCLDA_DELIMITER ((char)0x05)
#define SCLDA_SERVER_IP ((unsigned long int)0xc0a83801)
// プロセス生成に関わる、PIDとPPIDのペアを取得するポート
#define SCLDA_PIDPPID_PORT ((int)15001)
// システムコールに関係する情報を取得する
// BASEPORT + (プロセッサID % PORTNUM)をPORTとして使用する
#define SCLDA_SYSCALL_BASEPORT ((int)15002)
#define SCLDA_PORT_NUMBER ((int)8)
// システムコールに関連する情報を送信する
// chunksizeごとに文字列を分割して送信する
#define SCLDA_CHUNKSIZE ((int)1000)
// 付加情報（stime、スタック・ヒープ・メモリ全体の消費量）
#define SCLDA_STIME_MEMORY_SIZE ((int)200)
// 付加情報（utime、PID）
#define SCLDA_UTIME_PID_SIZE ((int)50)
// プロセス生成に関連する情報を送信する
#define SCLDA_PIDPPID_BUFSIZE ((int)150)

// ソケットなどをひとまとめにする構造体
struct sclda_client_struct {
	struct socket *sock;
	struct sockaddr_in addr;
	struct msghdr msg;
	struct iov_iter iov_it;
};

// 文字列を保持するためのノードを定義
struct sclda_pidinfo_ls {
	char str[SCLDA_PIDPPID_BUFSIZE];
	int len;
	struct sclda_pidinfo_ls *next;
};

// システムコールを送信するための情報を保持するための実装
struct sclda_syscallinfo_struct {
	// PIDとutimeに関連する情報
	int pid_utime_len;
	char pid_utime_msg[SCLDA_UTIME_PID_SIZE];
	// stime, stack, heap, allmemoryに関連する情報
	int stime_memory_len;
	char stime_memory_msg[SCLDA_STIME_MEMORY_SIZE];
	// システムコールに関連する情報
	int syscall_msg_len;
	char *syscall_msg;
};

// システムコールの情報を保持しておくためのリスト
struct sclda_syscallinfo_ls {
	struct sclda_syscallinfo_struct *s;
	// 次の情報
	struct sclda_syscall_info_struct *next;
};

// socketの作成を行う
int __sclda_create_socket(struct sclda_client_struct *);
// socketの接続を行う
int __sclda_connect_socket(struct sclda_client_struct *, int);

// sclda_client_structを初期化する関数
int __init_sclda_client(struct sclda_client_struct *, int);

// sclda_client_structをすべて初期化する関数
int sclda_init(void);

// 文字列を送信する最も簡単な関数
int sclda_send(char *, int, struct sclda_client_struct *);
int sclda_send_mutex(char *, int, struct sclda_client_struct *);

// system callを送信するための構造体を初期化する
void sclda_syscallinfo_init(struct sclda_syscallinfo_ls *ptr, char *msg,int len);
void sclda_add_syscallinfo(struct sclda_syscallinfo_struct *ptr);

// システムコール情報が大きな文字列だった場合、分割して送信
int sclda_send_syscall_info(struct sclda_syscallinfo_struct *ptr);

// 現在のPIDを取得する関数
int sclda_get_current_pid(void);

// currentから、スタックの大きさを取得する(バイト単位)
unsigned long sclda_get_current_spsize(void);

// currentから、ヒープのサイズを取得する(バイト単位)
unsigned long sclda_get_current_heapsize(void);

// currentから、全体のメモリ使用量を取得する(バイト単位)
unsigned long sclda_get_current_totalsize(void);

// システムコール関連情報を送信する際の、
// sclda_client_structを決定する
struct sclda_client_struct *sclda_decide_struct(void);

struct sclda_client_struct *sclda_get_pidppid_struct(void);

void sclda_add_string(const char *, int);
void sclda_all_send_strls(void);
struct sclda_pidinfo_ls *get_sclda_pidinfo_ls_head(void);
int is_sclda_init_fin(void);
int is_sclda_allsend_fin(void);
#endif // SCLDA_H
