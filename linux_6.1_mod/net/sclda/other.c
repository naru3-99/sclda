/*
 * net/sclda/other.c
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

#include <net/sclda.h>

int sclda_get_current_pid(void) {
    return (int)pid_nr(get_task_pid(current, PIDTYPE_PID));
}

long copy_char_from_user_dinamic(char **dst, const char __user *src) {
    long length;
    char *buf;

    if (src == NULL) return -EFAULT;

    length = strnlen_user(src, PATH_MAX);
    if (length <= 0) return -EFAULT;

    buf = kmalloc(length + 1, GFP_KERNEL);
    if (!buf) return -ENOMEM;

    if (copy_from_user(buf, src, length)) {
        kfree(buf);
        return -EFAULT;
    }
    *dst = buf;
    return length;
};

static char *escape_control_chars(const char *data, size_t len,
                                  size_t *new_len) {
    size_t i, j;
    size_t estimated_len = len * 4;
    char *escaped_data;
    unsigned char ch;

    escaped_data = kmalloc(estimated_len + 1, GFP_KERNEL);
    if (!escaped_data) {
        *new_len = 0;
        return NULL;
    }

    for (i = 0, j = 0; i < len; i++) {
        ch = data[i];
        if (ch < 0x20 || ch == 0x7F) {
            j += snprintf(escaped_data + j, estimated_len - j, "\\x%02x", ch);
        } else {
            escaped_data[j++] = ch;
        }
    }

    escaped_data[j] = '\0';
    *new_len = j;
    return escaped_data;
}

struct sclda_iov *copy_userchar_to_siov(const char __user *src, size_t len, size_t *vlen) {
    long length;
    size_t copy_len, vec_len, copyable, i;
    struct sclda_iov *siov, data;

    if (src == NULL) return NULL;

    if (len == 0) {
        length = strnlen_user(src, PATH_MAX);
        if (length <= 0) return NULL;
        copy_len = (size_t)length;
    } else {
        copy_len = len;
    }

    vec_len = (copy_len + SCLDA_SCDATA_BUFMAX - 1) / SCLDA_SCDATA_BUFMAX;
    *vlen = vec_len;
    siov = kmalloc_array(vec_len + 1, sizeof(struct sclda_iov), GFP_KERNEL);
    if (!siov) return NULL;

    copyable = SCLDA_SCDATA_BUFMAX - 1;
    for (i = 0; i < vec_len; i++) {
        data.len = min(copy_len - copyable * i, copyable);
        data.str = kmalloc(data.len, GFP_KERNEL);
        if (!(data.str)) {
            while (i > 0) kfree(siov[--i].str);
            kfree(siov);
            return NULL;
        }

        if (copy_from_user(data.str, src + copyable * i, data.len)) {
            while (i > 0) kfree(siov[--i].str);
            kfree(siov);
            kfree(data.str);
            return NULL;
        }

        siov[i + 1].str =
            escape_control_chars(data.str, data.len, &(siov[i + 1].len));
        if (!(siov[i + 1].str)) {
            while (i > 0) kfree(siov[--i].str);
            kfree(siov);
            kfree(data.str);
            return NULL;
        }
        kfree(data.str);
        data.str = NULL;
    }

    return siov;
}

int kernel_timespec_to_str(const struct __kernel_timespec __user *uptr,
                           char *msg_buf, int msg_len) {
    struct __kernel_timespec kptr;

    if (!uptr) return -EFAULT;

    if (copy_from_user(&kptr, uptr, sizeof(struct __kernel_timespec)))
        return -EFAULT;

    return snprintf(msg_buf, msg_len, "%lld%c%lld", kptr.tv_sec,
                    SCLDA_DELIMITER, kptr.tv_nsec);
}

int sclda_sockaddr_to_str(struct sockaddr_storage *ss, struct sclda_iov *siov) {
    // sockaddr構造体から重要な情報(ホストIPやportなど)を
    // 抜き出し、文字列に変換する関数
    int i;
    size_t written = 0;

    if (!ss) return -EFAULT;

    // sa_familyごとに取得する情報を変更する
    if (ss->ss_family == AF_INET) {
        // IPv4 socket address
        uint32_t ip;
        struct sockaddr_in *addr_in;

        addr_in = (struct sockaddr_in *)ss;
        ip = ntohl(addr_in->sin_addr.s_addr);
        written +=
            snprintf(siov->str, siov->len,
                     "ipv4: address= %u:%u:%u:%u"
                     " port= %u",
                     (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF,
                     ip & 0xFF, (unsigned int)ntohs(addr_in->sin_port));

    } else if (ss->ss_family == AF_INET6) {
        // IPv6 socket address
        struct sockaddr_in6 *addr_in6;
        addr_in6 = (struct sockaddr_in6 *)ss;
        written += snprintf(siov->str, siov->len, "ipv6: address= %02x",
                            addr_in6->sin6_addr.in6_u.u6_addr8[0]);
        for (i = 1; i < 16; i++) {
            written += snprintf(siov->str + written, siov->len - written,
                                ":%02x", addr_in6->sin6_addr.in6_u.u6_addr8[i]);
        }

        written += snprintf(siov->str + written, siov->len - written,
                            "port= %u flowinfo= %u scopeid= %u",
                            (unsigned int)ntohs(addr_in6->sin6_port),
                            (unsigned int)addr_in6->sin6_flowinfo,
                            (unsigned int)addr_in6->sin6_scope_id);

    } else if (ss->ss_family == PF_UNSPEC) {
        // sa->sa_family == 0
        written += snprintf(siov->str, siov->len, "unspecified");

    } else if (ss->ss_family == PF_UNIX) {
        // sa->sa_family == 1
        struct sockaddr_un *addr_un = (struct sockaddr_un *)ss;
        written += snprintf(siov->str, siov->len, "unix_domain: %s",
                            addr_un->sun_path);

    } else if (ss->ss_family == PF_NETLINK) {
        struct sockaddr_nl *addr_nl = (struct sockaddr_nl *)ss;
        written +=
            snprintf(siov->str, siov->len, "netlink: port= %u groups= 0x%x",
                     addr_nl->nl_pid, addr_nl->nl_groups);

    } else if (ss->ss_family == PF_PACKET) {
        struct sockaddr_ll *ll = (struct sockaddr_ll *)ss;
        written += snprintf(siov->str, siov->len,
                            "packet: index= %d hatype= %u ptktype= %u"
                            " sll_halen= %u addr=%02x:%02x:%02x:%02x:%02x:%02x",
                            ll->sll_ifindex, ll->sll_hatype, ll->sll_pkttype,
                            ll->sll_halen, ll->sll_addr[0], ll->sll_addr[1],
                            ll->sll_addr[2], ll->sll_addr[3], ll->sll_addr[4],
                            ll->sll_addr[5]);
    } else {
        // unknown socket address
        written +=
            snprintf(siov->str, siov->len, "unknown: %d", (int)ss->ss_family);
    }

    return (int) written;
}

int _msgname_to_str(struct user_msghdr *kmsg, char *buf, int buf_size)
{
	// msghdrのsockaddrを見極め、重要な情報を抜き出す
	struct sockaddr_storage address;
	// プロトコルを特定する
	if (copy_from_user(&address, kmsg->msg_name, kmsg->msg_namelen))
		return -EFAULT;
	return sockaddr_to_str(&address, buf, buf_size);
}

int _control_to_str(struct user_msghdr *kmsg, char **buf)
{
	// control 文字列の取得
	// bufの解放は呼び出し元が責任を負う
	int control_len;
	char *control_buf;

	control_len = kmsg->msg_controllen;
	control_buf = kmalloc(control_len, GFP_KERNEL);
	if (!control_buf)
		return -EFAULT;

	if (copy_from_user(control_buf, kmsg->msg_control,
			   kmsg->msg_controllen)) {
		control_buf[0] = '\0';
		control_len = 1;
	}
	*buf = control_buf;
	return control_len;
}

int user_msghdr_to_str(const struct user_msghdr __user *umsg,
		       struct sclda_iov **iov_ls, char *msg_buf, int msg_len)
{
	// msgname, iov, controlを取得する
	int retval = -EFAULT;
	char *msgname_buf, *control_buf, *msg_ctrl_buf, *iov_buf;
	int msgname_len, control_len, msg_ctrl_len;
	size_t iov_len, iov_buf_len;
	int i, j, k;
	struct iovec *iov;
	struct sclda_iov *siov;
	struct user_msghdr kmsg;

	// カーネル空間にumsgをコピーする
	if (copy_from_user(&kmsg, umsg, sizeof(struct user_msghdr)))
		return -EFAULT;

	// msgnameの情報を取得
	msgname_len = 200;
	msgname_buf = kmalloc(msgname_len, GFP_KERNEL);
	if (!msgname_buf)
		return -ENOMEM;
	msgname_len = _msgname_to_str(&kmsg, msgname_buf, msgname_len);
	if (msgname_len < 0)
		goto free_msgname;

	// control文字列の取得
	control_len = _control_to_str(&kmsg, &control_buf);
	if (control_len <= 0)
		goto free_msgname;

	// msgnameとcontrol文字列をひとまとめにする
	msg_ctrl_len = msgname_len + control_len + 50;
	msg_ctrl_buf = kmalloc(msg_ctrl_len, GFP_KERNEL);
	if (!msg_ctrl_buf)
		goto free_control;
	msg_ctrl_len = snprintf(msg_ctrl_buf, msg_ctrl_len, "%u%c%s%c%s",
				kmsg.msg_flags, SCLDA_DELIMITER, control_buf,
				SCLDA_DELIMITER, msgname_buf);

	// sclda_iovの段取り
	siov = kmalloc_array((size_t)kmsg.msg_iovlen + 1,
			     sizeof(struct sclda_iov), GFP_KERNEL);
	if (!siov)
		goto free_msg_ctrl;

	// iovの取得
	// コピーするための配列を段取り
	iov = kmalloc_array((size_t)kmsg.msg_iovlen, sizeof(struct iovec),
			    GFP_KERNEL);
	if (!iov) {
		retval = -ENOMEM;
		goto free_msg_ctrl;
	}
	// カーネル空間にiovをコピー・最大サイズを計る
	iov_buf_len = 1;
	for (i = 0; i < kmsg.msg_iovlen; i++) {
		if (copy_from_user(&iov[i], &(kmsg.msg_iov[i]),
				   sizeof(struct iovec)))
			goto free_iov;
		iov_buf_len = (iov_buf_len < iov[i].iov_len) ? iov[i].iov_len :
							       iov_buf_len;
	}
	// 最大の大きさのiov分のバッファをコピーする
	// 大きすぎるとエラーになる(MAX_RW_COUNT)
	iov_len = (SCLDA_SCDATA_BUFMAX < iov_buf_len) ? SCLDA_SCDATA_BUFMAX :
						      iov_buf_len;
	iov_buf = kmalloc(iov_buf_len + 1, GFP_KERNEL);
	if (!iov_buf)
		goto free_iov;

	// siovにiovの情報をコピー
	for (i = 0; i < kmsg.msg_iovlen; i++) {
		k = i + 1;
		// strをmallocする
		iov_len = (SCLDA_SCDATA_BUFMAX < iov[i].iov_len) ?
				  SCLDA_SCDATA_BUFMAX :
				  iov[i].iov_len;
		siov[k].str = kmalloc(iov_len + 1, GFP_KERNEL);
		if (!siov[k].str) {
			for (j = 0; j < i; j++)
				kfree(siov[j + 1].str);
			goto free_iov_buf;
		}
		// iov_baseをカーネルにコピー
		memset(iov_buf, 0, iov_buf_len);
		if (copy_from_user(iov_buf, iov[i].iov_base, iov_len)) {
			// 失敗した場合は、エラーメッセージを入れとく
			iov_len = snprintf(iov_buf, iov_len, "ERROR");
		}
		// 文字列をコピーする
		siov[k].len = snprintf(siov[k].str, iov_len, "%s", iov_buf);
	}
	// siovの初期にmsg_ctrlの情報を追加
	siov[0].str = kmalloc(msg_ctrl_len + msg_len + 10, GFP_KERNEL);
	if (!siov[0].str) {
		for (i = 0; i < kmsg.msg_iovlen; i++)
			kfree(siov[i + 1].str);
		goto free_iov_buf;
	}
	siov[0].len = snprintf(siov[0].str, msg_ctrl_len + msg_len + 10,
			       "%s%c%s", msg_buf, SCLDA_DELIMITER,
			       msg_ctrl_buf);

	*iov_ls = siov;
	retval = (int)kmsg.msg_iovlen + 1;

free_iov_buf:
	kfree(iov_buf);
free_iov:
	kfree(iov);
free_msg_ctrl:
	kfree(msg_ctrl_buf);
free_control:
	kfree(control_buf);
free_msgname:
	kfree(msgname_buf);
	return retval;
}