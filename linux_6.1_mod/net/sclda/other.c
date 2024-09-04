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

#include <linux/un.h>
#include <net/sclda.h>

int sclda_get_current_pid(void) {
    return (int)pid_nr(get_task_pid(current, PIDTYPE_PID));
}

long copy_char_from_user_dinamic(char **dst, const char __user *src) {
    long length;
    char *buf;

    if (!src) return -EFAULT;

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

struct sclda_iov *copy_userchar_to_siov(const char __user *src, size_t len,
                                        size_t *vlen) {
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

    copyable = SCLDA_SCDATA_BUFMAX - 1;

    vec_len = copy_len / copyable + 1;
    *vlen = vec_len;
    siov = kmalloc_array(vec_len + 1, sizeof(struct sclda_iov), GFP_KERNEL);
    if (!siov) return NULL;

    for (i = 0; i < vec_len; i++) {
        data.len = min(copy_len - copyable * i, copyable);
        data.str = kmalloc(data.len, GFP_KERNEL);
        if (!(data.str)) goto out_err;

        if (copy_from_user(data.str, src + copyable * i, data.len))
            goto free_data;
        siov[i + 1].str =
            escape_control_chars(data.str, data.len, &(siov[i + 1].len));

        if (!(siov[i + 1].str)) goto free_data;
        kfree(data.str);
        data.str = NULL;
    }

    return siov;

free_data:
    kfree(data.str);
out_err:
    while (i > 0) kfree(siov[--i].str);
    kfree(siov);
    return NULL;
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

    return (int)written;
}

static char *_msgname_to_str(struct user_msghdr *kmsg, size_t *len) {
    struct sockaddr_storage ss;
    struct sclda_iov siov;
    int addrlen;

    siov.len = 200;
    siov.str = kmalloc(siov.len, GFP_KERNEL);
    if (!siov.str) return NULL;

    if (!kmsg->msg_name) goto failed;
    addrlen = kmsg->msg_namelen;
    if (!(0 < addrlen && addrlen < sizeof(struct sockaddr_storage)))
        goto failed;
    if (copy_from_user(&ss, kmsg->msg_name, addrlen)) goto failed;

    if (sclda_sockaddr_to_str(&ss, &siov) >= 0) goto out;

failed:
    siov.len = snprintf(siov.str, siov.len, "NULL");
out:
    *len = siov.len;
    return siov.str;
}

static struct sclda_iov *_msgiov_to_str(struct user_msghdr *kmsg,
                                        size_t *siov_vlen) {
    int failed = 1;
    size_t i, j, len, bufsize, written, copy, esclen;
    // buf for copy iovec
    struct iovec *iovec_ls;
    size_t vlen;
    // buf for returning siov
    struct sclda_iov *siov_ls, temp;
    size_t siovlen;

    if (!kmsg->msg_iov) return NULL;

    vlen = (size_t)kmsg->msg_iovlen;
    iovec_ls = kmalloc_array(vlen, sizeof(struct iovec), GFP_KERNEL);
    if (!iovec_ls) return NULL;

    if (copy_from_user(iovec_ls, kmsg->msg_iov, sizeof(struct iovec) * vlen))
        goto free_iovec_ls;

    bufsize = SCLDA_SCDATA_BUFMAX - 1;
    siovlen = 0;
    for (i = 0; i < vlen; i++)
        siovlen += (iovec_ls[i].iov_len - 1) / bufsize + 1;

    *siov_vlen = siovlen;
    siov_ls = kmalloc_array(siovlen, sizeof(struct sclda_iov), GFP_KERNEL);
    if (!siov_ls) goto free_iovec_ls;

    temp.len = 0;
    temp.str = kmalloc(SCLDA_SCDATA_BUFMAX, GFP_KERNEL);
    if (!temp.str) goto free_siov_ls;

    j = 0;
    for (i = 0; i < vlen; i++) {
        len = iovec_ls[i].iov_len;
        written = 0;
        while (len > written) {
            copy = min(bufsize, len - written);
            if (copy_from_user(temp.str, iovec_ls[i].iov_base + written,
                               copy)) {
                j -= 1;
                goto free;
            }
            written += copy;

            siov_ls[j].str = escape_control_chars(temp.str, copy, &esclen);
            if (!siov_ls[j].str) goto free;

            memset(temp.str, 0, SCLDA_SCDATA_BUFMAX);
            j += 1;
        }
    }
    failed = 0;

free:
    // kfree siov_ls[j].str, where 0 ~ current j, if failed
    if (failed) {
        while (j != -1) {
            kfree(siov_ls[j].str);
            j -= 1;
        }
    }
    // kfree temp.str
    kfree(temp.str);

free_siov_ls:
    // kfree siov_ls, if failed
    if (failed) kfree(siov_ls);

free_iovec_ls:
    // kfree iovec_ls
    kfree(iovec_ls);
    return failed ? NULL : siov_ls;
}

static char *_control_to_str(struct user_msghdr *umsg, size_t *len) {
    struct cmsghdr *cmsg;
    void *control_buf;
    size_t i, written = 0;
    struct sclda_iov siov;

    control_buf = kmalloc(umsg->msg_controllen,GFP_KERNEL);
    if (!control_buf) return NULL;

    if (copy_from_user(control_buf, umsg->msg_control, umsg->msg_controllen))
        goto out;

    siov.len = 500;
    siov.str = kmalloc(siov.len, GFP_KERNEL);
    if (!siov.str) goto out;

    // 最初の制御メッセージを取得
    for (cmsg = __CMSG_FIRSTHDR(control_buf, umsg->msg_controllen); cmsg;
         cmsg = __CMSG_NXTHDR(control_buf, umsg->msg_controllen, cmsg)) {
        // 制御メッセージが有効か確認
        if (!CMSG_OK(umsg, cmsg)) continue;
        if (siov.len <= written) goto out;

        // 制御メッセージのレベルとタイプで分岐処理
        if (cmsg->cmsg_level == SOL_SOCKET) {
            switch (cmsg->cmsg_type) {
                case SCM_RIGHTS: {
                    // ファイルディスクリプタを受信している場合
                    int *fd_array = (int *)CMSG_DATA(cmsg);
                    size_t fd_count =
                        (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);

                    written += snprintf(siov.str + written,
                                        siov.len - written, "fd:");
                    for (i = 0; i < fd_count; i++)
                        written +=
                            snprintf(siov.str + written, siov.len - written,
                                     "%d,", fd_array[i]);
                    break;
                }
                case SCM_CREDENTIALS: {
                    // ユーザ資格情報 (credentials) の場合
                    struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);
                    written +=
                        snprintf(siov.str + written, siov.len - written,
                                 "cred:pid=%d,uid=%d,gid=%d,", cred->pid,
                                 cred->uid, cred->gid);
                    break;
                }
                case SCM_SECURITY: {
                    char *security_label = (char *)CMSG_DATA(cmsg);
                    size_t label_len = cmsg->cmsg_len - sizeof(struct cmsghdr);

                    written +=
                        snprintf(siov.str + written, siov.len - written,
                                 "sl:%.*s", (int)label_len, security_label);
                    break;
                }
                // 他のソケットレベルの制御メッセージを処理
                default:
                    written +=
                        snprintf(siov.str + written, siov.len - written,
                                 "Utype:%d", cmsg->cmsg_type);
                    break;
            }
        } else {
            // 他のプロトコルレベルの制御メッセージの処理
            written += snprintf(siov.str + written, siov.len - written,
                                "Ulevel:%d", cmsg->cmsg_level);
        }
    }
out:
    kfree(control_buf);
    *len = siov.len;
    return siov.str;
}

struct sclda_iov *sclda_user_msghdr_to_str(
    const struct user_msghdr __user *umsg, size_t *vlen) {
    struct user_msghdr kmsg;
    size_t iov_vlen, i, written = 0;
    struct sclda_iov addr, *iov, control, *all;
    int addr_ok = 0, control_ok = 0;

    if (!umsg) return NULL;
    if (copy_from_user(&kmsg, umsg, sizeof(struct user_msghdr))) return NULL;

    // msg_iov
    iov = _msgiov_to_str(&kmsg, &iov_vlen);
    if (!iov) return NULL;
    // msgname
    addr.str = _msgname_to_str(&kmsg, &addr.len);
    if (addr.str) addr_ok = 1;
    // control
    control.str = _control_to_str(&kmsg, &control.len);
    if (control.str) control_ok = 1;

    *vlen = iov_vlen + 2;
    all = kmalloc_array(iov_vlen + 2, sizeof(struct sclda_iov), GFP_KERNEL);
    if (!all) goto free;
    all[1].len = addr.len + control.len + 100;
    all[1].str = kmalloc(all[1].len, GFP_KERNEL);
    if (!all[1].str) goto free1;

    written +=
        snprintf(all[1].str + written, all[1].len - written,
                 "[%s]%c%d%c"
                 "%zu%c[%s]"
                 "%c%zu%c"
                 "%u%c",
                 addr.str, SCLDA_DELIMITER, kmsg.msg_namelen, SCLDA_DELIMITER,
                 (size_t)kmsg.msg_iovlen, SCLDA_DELIMITER, control.str,
                 SCLDA_DELIMITER, (size_t)kmsg.msg_controllen, SCLDA_DELIMITER,
                 kmsg.msg_flags, SCLDA_DELIMITER);

    if (addr_ok) {
        written +=
            snprintf(all[1].str + written, all[1].len - written,
                     "[%s]%c%d%c"
                     "%zu%c",
                     addr.str, SCLDA_DELIMITER, kmsg.msg_namelen,
                     SCLDA_DELIMITER, (size_t)kmsg.msg_iovlen, SCLDA_DELIMITER);
        kfree(addr.str);
    } else {
        written += snprintf(all[1].str + written, all[1].len - written,
                            "NULL%c%d%c"
                            "%zu%c",
                            SCLDA_DELIMITER, kmsg.msg_namelen, SCLDA_DELIMITER,
                            (size_t)kmsg.msg_iovlen, SCLDA_DELIMITER);
    }

    if (control_ok) {
        written +=
            snprintf(all[1].str + written, all[1].len - written,
                     "[%s]%c%zu"
                     "%c%u%c",
                     control.str, SCLDA_DELIMITER, (size_t)kmsg.msg_controllen,
                     SCLDA_DELIMITER, kmsg.msg_flags, SCLDA_DELIMITER);
        kfree(control.str);
    } else {
        written += snprintf(all[1].str + written, all[1].len - written,
                            "NULL%c%zu"
                            "%c%u%c",
                            SCLDA_DELIMITER, (size_t)kmsg.msg_controllen,
                            SCLDA_DELIMITER, kmsg.msg_flags, SCLDA_DELIMITER);
    }
    all[1].len = written;

    for (i = 0; i < iov_vlen; i++) {
        all[i + 2].str = iov[i].str;
        all[i + 2].len = iov[i].len;
        kfree(iov[i].str);
    }
    kfree(iov);

    // for debug
    for (i = 0; i < iov_vlen + 2; i++) printk(KERN_ERR "%s", all[i].str);

    return all;

free1:
    kfree(all);
free:
    if (control_ok) kfree(control.str);
    if (addr_ok) kfree(addr.str);
    for (i = 0; i < iov_vlen; i++) kfree(iov[i].str);
    kfree(iov);
    return NULL;
}