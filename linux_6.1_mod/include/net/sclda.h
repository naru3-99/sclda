#ifndef SCLDA_H
#define SCLDA_H

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/netpoll.h>

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
// プロセッサ数は8で固定する
#define SCLDA_SYSCALL_PORT_1 ((int)15002)
#define SCLDA_SYSCALL_PORT_2 ((int)15003)
#define SCLDA_SYSCALL_PORT_3 ((int)15004)
#define SCLDA_SYSCALL_PORT_4 ((int)15005)

// maximum buffer for 1 packet
#define SCLDA_BUFSIZE ((int)1000)

// ソケットなどをひとまとめにする構造体
struct sclda_client_struct {
	struct socket *sock;
	struct sockaddr_in addr;
	struct msghdr msg;
	struct iov_iter iov_it;
};

// sclda_client_structを初期化する関数
int init_sclda_client(struct sclda_client_struct *, int);

// 文字列を送信する最も簡単な関数
void sclda_send(char *, int, struct sclda_client_struct *);

// 大きな文字列だった場合、分けて送信するということを行う
// sclda_sendを用いて作成する
// 基本的にはこちらを使って、文字列を送信する
void sclda_send_split(char *, int);

// 現在のPIDを取得する関数
int sclda_get_current_pid(void);

// システムコール関連情報を送信する際の、
// sclda_client_structを決定する
struct sclda_client_struct *sclda_decide_struct(void);

#endif // SCLDA_H
