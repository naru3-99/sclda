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

// パケット内のデータを分割するための制御文字
#define SCLDA_DELIMITER ((char)0x05)

// サーバーのIPアドレス
#define SCLDA_SERVER_IP ((unsigned long int)0xc0a83801)

// サーバーのポート番号
// プロセス生成に関わる、PIDとPPIDのペアを取得するポート
#define SCLDA_PIDPPID_PORT ((int)15001)

// システムコールの情報を取得するポート
// プロセッサのID(smp_processor_id())により、
// 送るポートを分けることで負荷分散を図る
// BASEPORT + (プロセッサID % 4)をPORTとして使用する
#define SCLDA_SYSCALL_BASEPORT ((int)15002)
#define SCLDA_PORT_NUMBER ((int)4)

// maximum buffer for 1 packet
#define SCLDA_BUFSIZE ((int)1000)
// syscall_buffersize for additional info
#define SCLDA_ADD_BUFSIZE ((int)1500)
// pidppid関連のバフサイズ
#define SCLDA_PIDPPID_BUFSIZE ((int)50)

// ソケットなどをひとまとめにする構造体
struct sclda_client_struct {
	struct socket *sock;
	struct sockaddr_in addr;
	struct msghdr msg;
	struct iov_iter iov_it;
};

// 文字列を保持するためのノードを定義
struct sclda_str_list {
	char *str;
	int len;
	struct sclda_str_list *next;
};

// sclda_client_structを初期化する関数
int init_sclda_client(struct sclda_client_struct *, int);

// sclda_client_structをすべて初期化する関数
int init_all_sclda(void);

// 文字列を送信する最も簡単な関数
void sclda_send(char *, int, struct sclda_client_struct *);

// 大きな文字列だった場合、分けて送信するということを行う
// sclda_sendを用いて作成する
// 基本的にはこちらを使って、文字列を送信する
void sclda_send_split(char *, int);

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

struct sclda_str_list *sclda_add_string(const char *, int);
struct sclda_str_list *get_sclda_str_list_head(void);
void free_slcda_str_list(void);
void sclda_all_send_strls(void);
int is_sclda_init_fin(void);
#endif // SCLDA_H
