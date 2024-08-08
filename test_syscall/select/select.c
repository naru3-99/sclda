#include <stdio.h>
#include <sys/select.h>
#include <unistd.h>

int main() {
    fd_set readfds;
    struct timeval tv;
    int retval;

    // ファイルディスクリプタセットをクリア
    FD_ZERO(&readfds);
    // 標準入力をファイルディスクリプタセットに追加
    FD_SET(STDIN_FILENO, &readfds);

    // タイムアウトを設定
    tv.tv_sec = 5;  // 5秒
    tv.tv_usec = 0;

    // selectシステムコールを呼び出す
    retval = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);

    if (retval == -1) {
        perror("select()");
    } else if (retval) {
        printf("データが入力されました。\n");
    } else {
        printf("タイムアウトしました。\n");
    }

    return 0;
}
