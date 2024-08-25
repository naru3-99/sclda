#include <stdio.h>
#include <sys/timex.h>

int main() {
    struct timex t;
    int ret;

    // 構造体をゼロで初期化
    t.modes = 0;

    // adjtimexシステムコールを呼び出して、現在の状態を取得
    ret = adjtimex(&t);

    // adjtimexの戻り値を確認
    if (ret < 0) {
        perror("adjtimex failed");
        return 1;
    }

    // 結果を表示
    printf("adjtimex return value: %d\n", ret);
    printf("offset: %ld\n", t.offset);
    printf("frequency: %ld\n", t.freq);
    printf("max error: %ld\n", t.maxerror);
    printf("est error: %ld\n", t.esterror);
    printf("status: %u\n", t.status);
    printf("time constant: %d\n", t.constant);
    printf("precision: %ld\n", t.precision);
    printf("tolerance: %ld\n", t.tolerance);
    printf("time: %ld.%06ld\n", t.time.tv_sec, t.time.tv_usec);

    return 0;
}
