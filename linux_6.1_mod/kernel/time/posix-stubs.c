// SPDX-License-Identifier: GPL-2.0
/*
 * Dummy stubs used when CONFIG_POSIX_TIMERS=n
 *
 * Created by:  Nicolas Pitre, July 2016
 * Copyright:   (C) 2016 Linaro Limited
 */

#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/posix-timers.h>
#include <linux/time_namespace.h>
#include <linux/compat.h>
#include <net/sclda.h>

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
/* Architectures may override SYS_NI and COMPAT_SYS_NI */
#include <asm/syscall_wrapper.h>
#endif

asmlinkage long sys_ni_posix_timers(void)
{
	pr_err_once("process %d (%s) attempted a POSIX timer syscall "
		    "while CONFIG_POSIX_TIMERS is not set\n",
		    current->pid, current->comm);
	return -ENOSYS;
}

#ifndef SYS_NI
#define SYS_NI(name) SYSCALL_ALIAS(sys_##name, sys_ni_posix_timers)
#endif

#ifndef COMPAT_SYS_NI
#define COMPAT_SYS_NI(name) \
	SYSCALL_ALIAS(compat_sys_##name, sys_ni_posix_timers)
#endif

SYS_NI(timer_create);
SYS_NI(timer_gettime);
SYS_NI(timer_getoverrun);
SYS_NI(timer_settime);
SYS_NI(timer_delete);
SYS_NI(clock_adjtime);
SYS_NI(getitimer);
SYS_NI(setitimer);
SYS_NI(clock_adjtime32);
#ifdef __ARCH_WANT_SYS_ALARM
SYS_NI(alarm);
#endif

/*
 * We preserve minimal support for CLOCK_REALTIME and CLOCK_MONOTONIC
 * as it is easy to remain compatible with little code. CLOCK_BOOTTIME
 * is also included for convenience as at least systemd uses it.
 */

SYSCALL_DEFINE2(clock_settime, const clockid_t, which_clock,
		const struct __kernel_timespec __user *, tp)
{
	struct timespec64 new_tp;

	if (which_clock != CLOCK_REALTIME)
		return -EINVAL;
	if (get_timespec64(&new_tp, tp))
		return -EFAULT;

	return do_sys_settimeofday64(&new_tp, NULL);
}

static int do_clock_gettime(clockid_t which_clock, struct timespec64 *tp)
{
	switch (which_clock) {
	case CLOCK_REALTIME:
		ktime_get_real_ts64(tp);
		break;
	case CLOCK_MONOTONIC:
		ktime_get_ts64(tp);
		timens_add_monotonic(tp);
		break;
	case CLOCK_BOOTTIME:
		ktime_get_boottime_ts64(tp);
		timens_add_boottime(tp);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

SYSCALL_DEFINE2(clock_gettime, const clockid_t, which_clock,
		struct __kernel_timespec __user *, tp)
{
	int ret;
	struct timespec64 kernel_tp;

	ret = do_clock_gettime(which_clock, &kernel_tp);
	if (ret)
		return ret;

	if (put_timespec64(&kernel_tp, tp))
		return -EFAULT;
	return 0;
}

int sclda_clock_getres(const clockid_t which_clock,
		       struct __kernel_timespec __user *tp)
{
	struct timespec64 rtn_tp = {
		.tv_sec = 0,
		.tv_nsec = hrtimer_resolution,
	};

	switch (which_clock) {
	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
	case CLOCK_BOOTTIME:
		if (put_timespec64(&rtn_tp, tp))
			return -EFAULT;
		return 0;
	default:
		return -EINVAL;
	}
}

SYSCALL_DEFINE2(clock_getres, const clockid_t, which_clock,
		struct __kernel_timespec __user *, tp)
{
	int retval;
	int msg_len, ts_len;
	char *msg_buf, *ts_buf;

	retval = sclda_clock_getres(which_clock, tp);
	if (!is_sclda_allsend_fin())
		return retval;

	// kernel_timespecを文字列に変換
	ts_len = 100;
	ts_buf = kmalloc(ts_len, GFP_KERNEL);
	if (!ts_buf)
		return retval;
	ts_len = kernel_timespec_to_str(tp, ts_buf, ts_len);
	if (ts_len < 0) {
		ts_buf[0] = '\0';
		ts_len = 1;
	}

	// 送信するパート
	msg_len = 200 + ts_len;
	msg_buf = kmalloc(msg_len, GFP_KERNEL);
	if (!msg_buf)
		goto free_ts_buf;

	msg_len = snprintf(msg_buf, msg_len,
			   "229%c%d%c"
			   "%d%c%s",
			   SCLDA_DELIMITER, retval, SCLDA_DELIMITER,
			   (int)which_clock, SCLDA_DELIMITER, ts_buf);
	sclda_send_syscall_info(msg_buf, msg_len);

free_ts_buf:
	kfree(ts_buf);
	return retval;
}

long _sclda_clock_nanosleep(const clockid_t which_clock, int flags,
			    const struct __kernel_timespec __user *rqtp,
			    struct __kernel_timespec __user *rmtp)
{
	struct timespec64 t;
	ktime_t texp;

	switch (which_clock) {
	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
	case CLOCK_BOOTTIME:
		break;
	default:
		return -EINVAL;
	}

	if (get_timespec64(&t, rqtp))
		return -EFAULT;
	if (!timespec64_valid(&t))
		return -EINVAL;
	if (flags & TIMER_ABSTIME)
		rmtp = NULL;
	current->restart_block.fn = do_no_restart_syscall;
	current->restart_block.nanosleep.type = rmtp ? TT_NATIVE : TT_NONE;
	current->restart_block.nanosleep.rmtp = rmtp;
	texp = timespec64_to_ktime(t);
	if (flags & TIMER_ABSTIME)
		texp = timens_ktime_to_host(which_clock, texp);
	return hrtimer_nanosleep(texp,
				 flags & TIMER_ABSTIME ? HRTIMER_MODE_ABS :
							 HRTIMER_MODE_REL,
				 which_clock);
}

SYSCALL_DEFINE4(clock_nanosleep, const clockid_t, which_clock, int, flags,
		const struct __kernel_timespec __user *, rqtp,
		struct __kernel_timespec __user *, rmtp)
{
	long retval;
	int msg_len, rqtp_len, rmtp_len;
	char *msg_buf, *rqtp_buf, *rmtp_buf;

	retval = _sclda_clock_nanosleep(which_clock, flags, rqtp, rmtp);
	if (!is_sclda_allsend_fin())
		return retval;

	// 第1引数を文字列に変換
	rqtp_len = 200;
	rqtp_buf = kmalloc(rqtp_len, GFP_KERNEL);
	if (!rqtp_buf)
		return retval;
	rqtp_len = kernel_timespec_to_str(rqtp, rqtp_buf, rqtp_len);
	if (rqtp_len < 0) {
		rqtp_len = 1;
		rqtp_buf[0] = '\0';
	}

	// 第2引数を文字列に変換
	rmtp_len = 200;
	rmtp_buf = kmalloc(rmtp_len, GFP_KERNEL);
	if (!rmtp_buf)
		goto free_rqtp_buf;
	rmtp_len = kernel_timespec_to_str(rqtp, rmtp_buf, rmtp_len);
	if (rmtp_len < 0) {
		rmtp_len = 1;
		rmtp_buf[0] = '\0';
	}

	// 送信するパート
	msg_len = 200 + rmtp_len + rqtp_len;
	msg_buf = kmalloc(msg_len, GFP_KERNEL);
	if (!msg_buf)
		goto free_rmtp_buf;

	msg_len = snprintf(msg_buf, msg_len,
			   "230%c%ld%c%d"
			   "%c%d%c%s%c%s",
			   SCLDA_DELIMITER, retval, SCLDA_DELIMITER,
			   (int)which_clock, SCLDA_DELIMITER, flags,
			   SCLDA_DELIMITER, rqtp_buf, SCLDA_DELIMITER,
			   rmtp_buf);
	sclda_send_syscall_info(msg_buf, msg_len);

free_rmtp_buf:
	kfree(rmtp_buf);
free_rqtp_buf:
	kfree(rqtp_buf);
	return retval;
}

#ifdef CONFIG_COMPAT
COMPAT_SYS_NI(timer_create);
#endif

#if defined(CONFIG_COMPAT) || defined(CONFIG_ALPHA)
COMPAT_SYS_NI(getitimer);
COMPAT_SYS_NI(setitimer);
#endif

#ifdef CONFIG_COMPAT_32BIT_TIME
SYS_NI(timer_settime32);
SYS_NI(timer_gettime32);

SYSCALL_DEFINE2(clock_settime32, const clockid_t, which_clock,
		struct old_timespec32 __user *, tp)
{
	struct timespec64 new_tp;

	if (which_clock != CLOCK_REALTIME)
		return -EINVAL;
	if (get_old_timespec32(&new_tp, tp))
		return -EFAULT;

	return do_sys_settimeofday64(&new_tp, NULL);
}

SYSCALL_DEFINE2(clock_gettime32, clockid_t, which_clock,
		struct old_timespec32 __user *, tp)
{
	int ret;
	struct timespec64 kernel_tp;

	ret = do_clock_gettime(which_clock, &kernel_tp);
	if (ret)
		return ret;

	if (put_old_timespec32(&kernel_tp, tp))
		return -EFAULT;
	return 0;
}

SYSCALL_DEFINE2(clock_getres_time32, clockid_t, which_clock,
		struct old_timespec32 __user *, tp)
{
	struct timespec64 rtn_tp = {
		.tv_sec = 0,
		.tv_nsec = hrtimer_resolution,
	};

	switch (which_clock) {
	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
	case CLOCK_BOOTTIME:
		if (put_old_timespec32(&rtn_tp, tp))
			return -EFAULT;
		return 0;
	default:
		return -EINVAL;
	}
}

SYSCALL_DEFINE4(clock_nanosleep_time32, clockid_t, which_clock, int, flags,
		struct old_timespec32 __user *, rqtp,
		struct old_timespec32 __user *, rmtp)
{
	struct timespec64 t;
	ktime_t texp;

	switch (which_clock) {
	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
	case CLOCK_BOOTTIME:
		break;
	default:
		return -EINVAL;
	}

	if (get_old_timespec32(&t, rqtp))
		return -EFAULT;
	if (!timespec64_valid(&t))
		return -EINVAL;
	if (flags & TIMER_ABSTIME)
		rmtp = NULL;
	current->restart_block.fn = do_no_restart_syscall;
	current->restart_block.nanosleep.type = rmtp ? TT_COMPAT : TT_NONE;
	current->restart_block.nanosleep.compat_rmtp = rmtp;
	texp = timespec64_to_ktime(t);
	if (flags & TIMER_ABSTIME)
		texp = timens_ktime_to_host(which_clock, texp);
	return hrtimer_nanosleep(texp,
				 flags & TIMER_ABSTIME ? HRTIMER_MODE_ABS :
							 HRTIMER_MODE_REL,
				 which_clock);
}
#endif
