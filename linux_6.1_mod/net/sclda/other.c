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
    if (!escaped_data) return NULL;

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
    // var
    int failed = 1;
    long length;
    size_t copy_len, vec_len, copyable, to_copy, i;
    struct sclda_iov *siov;
    char *buffer;

    // set
    if (src == NULL) goto out;

    if (len == 0) {
        length = strnlen_user(src, PATH_MAX);
        if (length <= 0) goto out;
        copy_len = (size_t)length;
    } else {
        if (len >= INT_MAX) len = INT_MAX - 1;
        copy_len = len;
    }

    copyable = SCLDA_SCDATA_BUFMAX - 1;
    buffer = kmalloc(copyable, GFP_KERNEL);
    if (!buffer) goto out;

    vec_len = (copy_len - 1) / copyable + 1;
    *vlen = vec_len;

    siov = kmalloc_array(vec_len + 1, sizeof(struct sclda_iov), GFP_KERNEL);
    if (!siov) goto free_buffer;

    for (i = 0; i < vec_len; i++) {
        to_copy = min(copy_len - copyable * i, copyable);
        if (copy_from_user(buffer, src + copyable * i, to_copy))
            goto free_siov_ls;

        siov[i + 1].str =
            escape_control_chars(buffer, to_copy, &(siov[i + 1].len));
        if (!(siov[i + 1].str)) goto free_siov_ls;
        memset(buffer, 0, copyable);
    }
    failed = 0;

free_siov_ls:
    if (failed) {
        while (i > 0) kfree(siov[--i].str);
        kfree(siov);
    }
free_buffer:
    kfree(buffer);
out:
    *vlen = failed ? 0 : vec_len + 1;
    return failed ? NULL : siov;
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

static char *_msgname_to_str(const struct user_msghdr *kmsg, size_t *len) {
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

static struct sclda_iov *_msgiov_to_str(const struct user_msghdr *kmsg,
                                        size_t *siov_vlen) {
    int failed = 1;
    size_t i, j, len, bufsize, written, copy, esclen;
    // buf for copy iovec
    struct iovec *iovec_ls;
    size_t vlen;
    // buffer for copying iovec.iobase
    char *temp;
    // buf for returning siov
    struct sclda_iov *siov_ls;
    size_t siovlen;

    if (!kmsg->msg_iov) return NULL;

    vlen = (size_t)kmsg->msg_iovlen;
    iovec_ls = kmalloc_array(vlen, sizeof(struct iovec), GFP_KERNEL);
    if (!iovec_ls) return NULL;

    if (copy_from_user(iovec_ls, kmsg->msg_iov, sizeof(struct iovec) * vlen))
        goto free_iovec_ls;

    bufsize = SCLDA_SCDATA_BUFMAX - 1;
    siovlen = 0;
    for (i = 0; i < vlen; i++) {
        if (iovec_ls[i].iov_len == 0) continue;
        siovlen += (iovec_ls[i].iov_len - 1) / bufsize + 1;
    }

    *siov_vlen = siovlen;
    if (siovlen == 0) goto free_iovec_ls;

    siov_ls = kmalloc_array(siovlen, sizeof(struct sclda_iov), GFP_KERNEL);
    if (!siov_ls) goto free_iovec_ls;

    temp = kmalloc(SCLDA_SCDATA_BUFMAX, GFP_KERNEL);
    if (!temp) goto free_siov_ls;

    j = 0;
    for (i = 0; i < vlen; i++) {
        len = iovec_ls[i].iov_len;
        written = 0;
        while (len > written) {
            copy = min(bufsize, len - written);
            if (copy_from_user(temp, iovec_ls[i].iov_base + written, copy)) {
                j -= 1;
                goto free;
            }
            written += copy;

            siov_ls[j].str = escape_control_chars(temp, copy, &esclen);
            if (!siov_ls[j].str) goto free;

            memset(temp, 0, SCLDA_SCDATA_BUFMAX);
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
    // kfree temp
    kfree(temp);

free_siov_ls:
    // kfree siov_ls, if failed
    if (failed) kfree(siov_ls);

free_iovec_ls:
    // kfree iovec_ls
    kfree(iovec_ls);
    return failed ? NULL : siov_ls;
}

static char *_control_to_str(struct user_msghdr *umsg, size_t *len) {
    // for copy_msghdr_from_user
    struct msghdr msg_sys;
    struct sockaddr_storage address;

    // other
    struct cmsghdr *cmsg;
    struct sclda_iov siov;
    size_t i, written = 0;

    // user_msghdr -> msghdr struct
    msg_sys.msg_name = &address;
    if (__copy_msghdr(&msg_sys, umsg, NULL)) return NULL;

    if (msg_sys.msg_controllen > INT_MAX) return NULL;

    // get data
    siov.len = 500;
    siov.str = kmalloc(siov.len, GFP_KERNEL);
    if (!siov.str) return NULL;

    // 最初の制御メッセージを取得
    for_each_cmsghdr(cmsg, &msg_sys) {
        // 制御メッセージが有効か確認
        if (!CMSG_OK(&msg_sys, cmsg)) goto out;
        if (siov.len <= written) goto out;

        // 制御メッセージのレベルとタイプで分岐処理
        if (cmsg->cmsg_level == SOL_SOCKET) {
            switch (cmsg->cmsg_type) {
                case SCM_RIGHTS: {
                    // ファイルディスクリプタを受信している場合
                    int *fd_array = (int *)CMSG_DATA(cmsg);
                    size_t fd_count =
                        (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);

                    written +=
                        snprintf(siov.str + written, siov.len - written, "fd:");
                    for (i = 0; i < fd_count; i++)
                        written +=
                            snprintf(siov.str + written, siov.len - written,
                                     "%d,", fd_array[i]);
                    break;
                }
                case SCM_CREDENTIALS: {
                    // ユーザ資格情報 (credentials) の場合
                    struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);
                    written += snprintf(siov.str + written, siov.len - written,
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
                    written += snprintf(siov.str + written, siov.len - written,
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
    *len = siov.len;
    return siov.str;
}

static struct sclda_iov *kernel_msghdr_to_str(struct user_msghdr *kmsg,
                                              size_t *vlen) {
    size_t iov_vlen, all_vlen, i, j, written = 0;
    struct sclda_iov addr, *iov, control, *all;
    int addr_ok = 0, iov_ok = 0, control_ok = 0;

    // msg_iov
    iov = _msgiov_to_str(kmsg, &iov_vlen);
    if (iov) iov_ok = 1;
    // msgname
    addr.str = _msgname_to_str(kmsg, &addr.len);
    if (addr.str) addr_ok = 1;
    // control
    control.str = _control_to_str(kmsg, &control.len);
    if (control.str) control_ok = 1;

    all_vlen = 2;  // controlなど+最初はscname,retvalなど
    if (iov_ok) {
        for (i = 0; i < iov_vlen; i++)
            if (!iov[i].str && iov[i].len != 0) all_vlen += 1;
    }

    *vlen = all_vlen;
    all = kmalloc_array(all_vlen, sizeof(struct sclda_iov), GFP_KERNEL);
    if (!all) goto free;
    all[1].len = addr.len + control.len + 100;
    all[1].str = kmalloc(all[1].len, GFP_KERNEL);
    if (!all[1].str) goto free1;

    if (addr_ok) {
        written += snprintf(all[1].str + written, all[1].len - written,
                            "[%s]%c%d%c"
                            "%zu%c",
                            addr.str, SCLDA_DELIMITER, kmsg->msg_namelen,
                            SCLDA_DELIMITER, (size_t)kmsg->msg_iovlen,
                            SCLDA_DELIMITER);
        kfree(addr.str);
    } else {
        written += snprintf(all[1].str + written, all[1].len - written,
                            "NULL%c%d%c"
                            "%zu%c",
                            SCLDA_DELIMITER, kmsg->msg_namelen, SCLDA_DELIMITER,
                            (size_t)kmsg->msg_iovlen, SCLDA_DELIMITER);
    }

    if (control_ok) {
        written +=
            snprintf(all[1].str + written, all[1].len - written,
                     "[%s]%c%zu"
                     "%c%u%c",
                     control.str, SCLDA_DELIMITER, (size_t)kmsg->msg_controllen,
                     SCLDA_DELIMITER, kmsg->msg_flags, SCLDA_DELIMITER);
        kfree(control.str);
    } else {
        written += snprintf(all[1].str + written, all[1].len - written,
                            "NULL%c%zu"
                            "%c%u%c",
                            SCLDA_DELIMITER, (size_t)kmsg->msg_controllen,
                            SCLDA_DELIMITER, kmsg->msg_flags, SCLDA_DELIMITER);
    }
    all[1].len = written;

    i = 0;
    j = 2;
    while (i < iov_vlen) {
        if (!(!iov[i].str && iov[i].len != 0)) {
            i += 1;
            continue;
        }
        all[j].str = iov[i].str;
        all[j].len = iov[i].len;
        kfree(iov[i].str);
        i += 1;
        j += 1;
    }
    kfree(iov);
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

struct sclda_iov *sclda_user_msghdr_to_str(
    const struct user_msghdr __user *umsg, size_t *vlen) {
    struct user_msghdr kmsg;

    if (!umsg) return NULL;
    if (copy_from_user(&kmsg, umsg, sizeof(struct user_msghdr))) return NULL;
    return kernel_msghdr_to_str(&kmsg, vlen);
}

struct sclda_iov *sclda_user_mmsghdr_to_str(const struct mmsghdr __user *umsg,
                                            unsigned int vlen,
                                            size_t *sclda_iov_len) {
    // var
    int failed = 1;
    struct mmsghdr kmsg;
    struct mmsghdr __user *entry;
    size_t i, j, written, veclen, alllen = 0;
    struct sclda_iov *siov_ls, siov;
    struct sclda_iov_ls head, *tail, *temp, *curptr;

    // set
    if (!umsg || vlen == 0) return NULL;
    head.next = NULL;
    tail = &head;
    if (vlen > UIO_MAXIOV) vlen = UIO_MAXIOV;

    siov.len = vlen * 11 + 20;
    siov.str = kmalloc(siov.len, GFP_KERNEL);
    if (!siov.str) return NULL;

    written = snprintf(siov.str, siov.len, "[");

    entry = umsg;
    for (i = 0; i < vlen; i++) {
        if (copy_from_user(&kmsg, entry, sizeof(struct mmsghdr)))
            goto free_spls;
        siov_ls = kernel_msghdr_to_str(&kmsg.msg_hdr, &veclen);

        if (siov.len > written)
            written += snprintf(siov.str + written, siov.len - written, "%u,",
                                kmsg.msg_len);

        for (j = 1; j < veclen; j++) {
            temp = kmalloc(sizeof(struct sclda_iov_ls), GFP_KERNEL);
            if (!temp) goto free_spls;

            temp->next = NULL;
            temp->data.len = siov_ls[j].len;
            temp->data.str = siov_ls[j].str;

            alllen += 1;
            tail->next = temp;
            tail = tail->next;
        }
        memset(&kmsg, 0, sizeof(struct mmsghdr));
        ++entry;
    }

    if (siov.len > written)
        written += snprintf(siov.str + written, siov.len - written, "]");

    return NULL;

    siov_ls = kmalloc_array(alllen + 2, sizeof(struct sclda_iov), GFP_KERNEL);
    if (!siov_ls) goto free_spls;

    siov_ls[1].len = written;
    siov_ls[1].str = siov.str;

    curptr = head.next;
    i = 2;
    while (curptr) {
        if (i >= alllen + 2) break;
        siov_ls[i].len = curptr->data.len;
        siov_ls[i].str = curptr->data.str;

        i += 1;
        curptr = curptr->next;
    }
    failed = 0;

free_spls:
    curptr = head.next;
    while (curptr) {
        temp = curptr->next;
        if (failed) kfree(curptr->data.str);
        kfree(curptr);
        curptr = temp;
    }

    if (failed) kfree(siov.str);
    *sclda_iov_len = failed ? 0 : alllen;
    return failed ? NULL : siov_ls;
}