# sclda

System Call Level Dynamic Analysis

「任意のプログラムが実行した内容」を解析(データ化)するシステム

## 構成

仮想環境で走る OS 上の環境 → ゲスト環境と表記

URL がリンクしてあるので、クリックすると飛べます。

- sclda(本レポジトリ)：
  - debian linux のソースコードを改造して作成
  - virtual box による仮想環境でビルドし、使用
  - OS から必要な情報を UDP 通信を用いて送信
- [sclda_host](https://github.com/naru3-99/sclda_host)：
  - ホスト環境で使用する、UDP パケットを受信するサーバ
  - 解析を自動化するため、SSH を用いてゲスト環境を操作
- [sclda_guest](https://github.com/naru3-99/sclda_guest):
  - ゲスト環境で、解析したいプログラムを別プロセスで実行
  - 現在、python と java を実行する基盤は構築済み

## UDP パケットの中身

全ての情報は、\x05 区切りになっている。

- pid(システムコールを呼び出したプロセス ID)
- sched_clock(ナノ秒:カーネルの起動後から)
- syscall_msg(syscall_info.csv を参照。システムコールごとに異なる)

## 過去レポジトリとの関係

[ICAART(国際学会)に提出した論文](https://www.insticc.org/node/TechnicalProgram/ICAART/2024/presentationDetails/123729)に乗せるため、未完成の状態のシステムを public レポジトリとして公開しています。

過去のレポジトリ：対応する現在のレポジトリ

- [sct_debian](https://github.com/naru3-99/sct_debian)：sclda(本レポジトリ)
- [langMorphDA](https://github.com/naru3-99/langMorphDA)：[sclda_host](https://github.com/naru3-99/sclda_host) , [sclda_guest](https://github.com/naru3-99/sclda_guest)

langMorphDA 配下の dynamic_analysis/host が sclda_host、/guest が sclda_guest に対応しています。
