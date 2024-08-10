#!/bin/bash

# server.c をコンパイル
gcc -o server server.c
if [ $? -ne 0 ]; then
    echo "Failed to compile server.c"
    exit 1
fi

# client.c をコンパイル
gcc -o client client.c
if [ $? -ne 0 ]; then
    echo "Failed to compile client.c"
    exit 1
fi

# サーバーをバックグラウンドで実行
./server &
SERVER_PID=$!

# サーバーが起動するのを少し待つ
sleep 1

# クライアントを実行
./client

# クライアントの実行が完了したらサーバーを終了
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null

echo "Server and client have finished execution."
