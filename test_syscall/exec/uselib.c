#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>

int main() {
    const char *libpath = "/lib/x86_64-linux-gnu/libc.so.6";
    long result;

    // uselibシステムコールを呼び出す
    result = syscall(SYS_uselib, libpath);

    if (result == 0) {
        printf("uselib succeeded\n");
    } else {
        printf("uselib failed with error code: %ld\n", result);
    }

    return 0;
}
