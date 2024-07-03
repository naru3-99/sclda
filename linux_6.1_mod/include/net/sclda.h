/*
 * sclda.c
 * Copyright (C) [2023] [Naru3 (Narumi Yoneda)
 * (7423530@ed.tus.ac.jp,naru99yoneda@gmail.com)]
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA.
 */

#ifndef SCLDA_H
#define SCLDA_H

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/netpoll.h>
#include <linux/uaccess.h>
#include <linux/types.h>

#include <linux/sched/clock.h>

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
#define SCLDA_PORT_NUMBER ((int)16)
// システムコールに関連する情報を送信する
// chunksizeごとに文字列を分割して送信する
#define SCLDA_CHUNKSIZE ((size_t)1000)
// 付加情報（utime、PID）
#define SCLDA_PID_CLOCK_SIZE ((int)50)
// syscall_info構造体がいくつ貯まると送信するか
#define SCLDA_NUM_TO_SEND_SINFO ((int)2000)
// syscall_info構造体の頭とmutexを用意する数
#define SCLDA_SCI_NUM ((int)8)

// ソケットなどをひとまとめにする構造体
typedef int (*sclda_send_f)(char *buf, int len, struct socket *sock,
			    struct msghdr msg);

struct sclda_client_struct {
	struct socket *sock;
	struct sockaddr_in addr;
	struct msghdr msg;
	struct iov_iter iov_it;
};

// 文字列の情報を保持するための構造体
struct sclda_iov {
	int len;
	char *str;
};

// PID情報を保持するためのノードを定義
struct sclda_pidinfo_ls {
	struct sclda_pidinfo_ls *next;
	struct sclda_iov pid_info;
};

// システムコール情報を保持するための構造体
struct sclda_syscallinfo_ls {
	// 次の構造体へのポインタ
	struct sclda_syscallinfo_ls *next;
	// PIDとcputimeに関連する情報
	struct sclda_iov pid_time;
	// システムコールに関連する情報
	// 大規模バッファに対応するため、配列として扱う
	int sc_iov_len;
	struct sclda_iov *syscall;
};

#define SCLDA_SEND_FUNC_NAME(n) sclda_send_func##n
#define DEFINE_SCLDA_SEND_FUNC(n)                                            \
	int SCLDA_SEND_FUNC_NAME(n)(char *buf, int len, struct socket *sock, \
				    struct msghdr msg)                       \
	{                                                                    \
		struct kvec iov;                                             \
		iov.iov_base = buf;                                          \
		iov.iov_len = len;                                           \
		return kernel_sendmsg(sock, &msg, &iov, 1, len);             \
	}

// sclda_client_structをすべて初期化する関数
int sclda_init(void);

// 文字列を送信する最も簡単な関数
int sclda_send(char *, int, struct sclda_client_struct *);
int sclda_send_mutex(char *, int, struct sclda_client_struct *);

// pidを取得する
int sclda_get_current_pid(void);

// システムコール情報が大きな文字列だった場合、分割して送信
int sclda_send_syscall_info(char *, int);
int sclda_send_syscall_info2(struct sclda_iov *, int);

// システムコール関連情報を送信する際の、
// sclda_client_structを決定する
struct sclda_client_struct *sclda_decide_struct(void);
struct sclda_client_struct *sclda_get_pidppid_struct(void);

// pid情報を送信するための機構
int sclda_add_pidinfo(char *, int);
void sclda_sendall_pidinfo(void);
// fork.cで初期化処理などが終わったかどうかを参照する
int is_sclda_init_fin(void);
int is_sclda_allsend_fin(void);
int kernel_timespec_to_str(const struct __kernel_timespec __user *, char *,
			   int);
#endif // SCLDA_H
