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

long copy_char_from_user_dinamic(char **dst, const char __user *src){
    long length;
    char *buf;

    if (src == NULL) return -EFAULT;

    length = strnlen_user(src, PATH_MAX);
    if (length <= 0) return -EFAULT;

    buf = kmalloc(length+1,GFP_KERNEL);
    if (!buf) return -ENOMEM;

    if (copy_from_user(buf, src, length)) {
        kfree(buf);
        return -EFAULT;
    }
    *dst = buf;
    return length;
};

int sclda_get_current_pid(void) {
    return (int)pid_nr(get_task_pid(current, PIDTYPE_PID));
}

char *escape_control_chars(const char *data, size_t len, size_t *new_len) {
    size_t i, j;
    char *escaped_data;
    size_t estimated_len = len * 4;  // 最悪の場合、各バイトがエスケープされると仮定
    escaped_data = kmalloc(estimated_len + 1, GFP_KERNEL);
    if (!escaped_data) {
        *new_len = 0;
        return NULL;
    }

    for (i = 0, j = 0; i < len; i++) {
        unsigned char ch = data[i];
        if (ch < 0x20 || ch == 0x7F) {  // 制御文字およびDEL
            j += snprintf(escaped_data + j, estimated_len - j, "\\x%02x", ch);
        } else {
            escaped_data[j++] = ch;
        }
    }

    escaped_data[j] = '\0';
    *new_len = j;
    return escaped_data;
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