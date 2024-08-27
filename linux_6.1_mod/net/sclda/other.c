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

struct sclda_iov *copy_userchar_to_siov(const char __user *src, size_t len) {
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