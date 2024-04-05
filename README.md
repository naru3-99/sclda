# sclda

System Call Level Dynamic Analysis

「任意のプログラムが実行した内容」を解析(データ化)するシステム

## 構成

仮想環境で走る OS 上の環境 → ゲスト環境と表記

URLがリンクしてあるので、クリックすると飛べます。
- sclda(本レポジトリ)：
  - debian linux のソースコードを改造して作成
  - virtual box による仮想環境でビルドし、使用
  - OSから必要な情報をUDP通信を用いて送信
- [sclda_host](https://github.com/naru3-99/sclda_host)：
  - ホスト環境で使用する、UDPパケットを受信するサーバ
  - 解析を自動化するため、SSHを用いてゲスト環境を操作
- [sclda_guest](https://github.com/naru3-99/sclda_guest):
  - ゲスト環境で、解析したいプログラムを別プロセスで実行
  - 現在、pythonとjavaを実行する基盤は構築済み

## 過去レポジトリとの関係
[ICAART(国際学会)に提出した論文](https://www.insticc.org/node/TechnicalProgram/ICAART/2024/presentationDetails/123729)に乗せるため、未完成の状態のシステムをpublicレポジトリとして公開しています。

過去のレポジトリ：対応する現在のレポジトリ
- [sct_debian](https://github.com/naru3-99/sct_debian)：sclda(本レポジトリ)
- [langMorphDA](https://github.com/naru3-99/langMorphDA)：[sclda_host](https://github.com/naru3-99/sclda_host) , [sclda_guest](https://github.com/naru3-99/sclda_guest)

langMorphDA配下のdynamic_analysis/hostがsclda_host、/guestがsclda_guestに対応しています。
## 取得する情報について

- システムコールに関連する情報
  - システムコールの ID
  - システムコールの引数・返り値に関連する情報
  - 呼び出されたタイミングについての情報
    - プロセスがユーザ空間で消費した CPU 時間
    - プロセスがカーネル空間で消費した CPU 時間
  - プロセスのメモリ消費量に関連する情報
    - スタック
    - ヒープ
    - メモリ全体
- プロセス生成に関連する情報
  - 生成されたプロセスの ID(PID)
  - 生成されたプロセスの親プロセスの ID(PPID)

## 進捗管理
- (DONE) ヘッダファイルを追加 (include/net/sclda.h)
- (DONE) UDP通信など一連の関数を実装 (net/sclda.c)
  - (DONE) ソケットの初期化処理に関する実装
  - (DONE) ソケットを用いたパケットの送信
  - (実装済み・未確認) 大きな文字列を分割して送信
  - (DONE) ソケットの初期化待ちのため、文字列をためておくための実装
  - (実装済み・未確認) CPUのIDごとに送信するポートを変えることで、並列化する
- (DONE) UDPソケットの初期化処理のエントリを追加 (init/main.c)
- (DONE) PIDとPPIDのペア、及びプロセスのもとになった実行可能ファイルの名前をUDP通信を用いて送信 (kernel/fork.c)
  - (未解決・パッチ済み)pid = 700くらいまで、なぜかパケットを送信できない
    - 送信できるようになるまで待つ