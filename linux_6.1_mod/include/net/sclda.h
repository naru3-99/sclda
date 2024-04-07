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
#define SCLDA_CHUNKSIZE ((int)1200)
// 付加情報（stime、スタック・ヒープ・メモリ全体の消費量）
// を付与するためのバッファサイズ
#define SCLDA_ADD_BUFSIZE ((int)200)
// プロセス生成に関連する情報を送信する
#define SCLDA_PIDPPID_BUFSIZE ((int)100)

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

// socketの作成を行う
int __sclda_create_socket(struct sclda_client_struct *);
// socketの接続を行う
int __sclda_connect_socket(struct sclda_client_struct *, int);

// sclda_client_structを初期化する関数
int __init_sclda_client(struct sclda_client_struct *, int);

// sclda_client_structをすべて初期化する関数
int sclda_init(void);

// 文字列を送信する最も簡単な関数
int __sclda_send(char *, int, struct sclda_client_struct *);
int sclda_send(char *, int, struct sclda_client_struct *);

// 下実装
void __sclda_send_split(char *, int);
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

void sclda_add_string(const char *, int);
void sclda_all_send_strls(void);
struct sclda_pidinfo_ls *get_sclda_pidinfo_ls_head(void);
int is_sclda_init_fin(void);
int is_sclda_allsend_fin(void);
#endif // SCLDA_H
