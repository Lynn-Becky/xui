# x-ui

支持多协议多用户的 xray 面板

# 功能介绍

- 系统状态监控
- 支持多用户多协议，网页可视化操作
- 支持的协议：vmess、vless、trojan、shadowsocks、http、mixed、tunnel、wireguard、hysteria2
- 支持配置更多传输配置
- 流量统计，限制流量，限制到期时间
- 可自定义 xray 配置模板
- 支持 https 访问面板（自备域名 + ssl 证书）
- 支持一键SSL证书申请且自动续签
- 更多高级配置项，详见面板

# 安装&升级

```
bash <(curl -fsSL https://raw.githubusercontent.com/Lynn-Becky/xui/main/install.sh)
```

## 手动安装&升级

1. 首先从 https://github.com/Lynn-Becky/xui/releases 下载最新的压缩包，一般选择 `amd64` 架构
2. 然后将这个压缩包上传到服务器的 `/root/`目录下，并使用 `root`用户登录服务器

> 如果你的服务器 cpu 架构不是 `amd64`，自行将命令中的 `amd64`替换为其他架构
>
> Alpine Linux 请使用 `x-ui-linux-amd64-alpine.tar.gz` 或 `x-ui-linux-arm64-alpine.tar.gz`。该产物使用 Go 1.26.5 在 Alpine 3.23 的 musl 环境中编译，不依赖 `glibc/gcompat`，并移除了调试符号以减小体积。

```
cd /root/
rm x-ui/ /usr/local/x-ui/ /usr/bin/x-ui -rf
tar --no-same-owner --no-same-permissions -zxvf x-ui-linux-amd64.tar.gz
chown -R root:root x-ui
chmod 0755 x-ui/x-ui x-ui/bin/xray-linux-* x-ui/x-ui.sh
cp x-ui/x-ui.sh /usr/bin/x-ui
cp -f x-ui/x-ui.service /etc/systemd/system/
mv x-ui/ /usr/local/
systemctl daemon-reload
systemctl enable x-ui
systemctl restart x-ui
```

> `--no-same-owner` 与 `chown` 是必要的：以 root 解包时 GNU tar 会沿用归档内记录的属主，而发布包是在 CI 上打的，否则 systemd 以 root 运行的面板二进制会归一个非 root 的 uid 所有。

> **首次启动会自动生成随机的管理员密码**（不再是 `admin/admin`），密码只在服务日志中打印一次。用 `journalctl -u x-ui | grep -A3 "initial administrator"` 查看，登录后请立即修改。

## 使用docker安装

> 此 docker 教程与 docker 镜像由[Chasing66](https://github.com/Chasing66)提供

1. 安装docker

```shell
curl -fsSL https://get.docker.com | sh
```

2. 安装x-ui

```shell
mkdir x-ui && cd x-ui
docker run -itd --network=host \
    -v $PWD/db/:/etc/x-ui/ \
    -v $PWD/cert/:/root/cert/ \
    --name x-ui --restart=unless-stopped \
    enwaiax/x-ui:latest
```

> **首次启动会自动生成随机的管理员密码**（不再是 `admin/admin`），只打印一次，用 `docker logs x-ui | grep -A3 "initial administrator"` 获取，登录后请立即修改。

> 这里保留 `--network=host` 是因为入站节点需要直接监听宿主机端口（例如 443），改用 `-p` 逐个发布端口会让代理不可用。代价是面板端口同样暴露在宿主机的所有网络接口上，因此建议：把面板端口设为一个随机高位端口、配置一个随机的面板访问路径，并用防火墙只放行你自己的来源 IP。

> Build 自己的镜像

```shell
docker build -t x-ui .
```

## SSL证书申请

> 此功能与教程由[FranzKafkaYu](https://github.com/FranzKafkaYu)提供

脚本内置SSL证书申请功能，使用该脚本申请证书，需满足以下条件:

- 知晓Cloudflare 注册邮箱
- 知晓Cloudflare Global API Key
- 域名已通过cloudflare进行解析到当前服务器

获取Cloudflare Global API Key的方法:
    ![](media/bda84fbc2ede834deaba1c173a932223.png)
    ![](media/d13ffd6a73f938d1037d0708e31433bf.png)

使用时只需输入 `域名`, `邮箱`, `API KEY`即可，示意图如下：
        ![](media/2022-04-04_141259.png)

注意事项:

- 该脚本使用DNS API进行证书申请
- 默认使用Let'sEncrypt作为CA方
- 证书安装目录为/root/cert目录
- 本脚本申请证书均为泛域名证书

## Tg机器人使用（开发中，暂不可使用）

> 此功能与教程由[FranzKafkaYu](https://github.com/FranzKafkaYu)提供

X-UI支持通过Tg机器人实现每日流量通知，面板登录提醒等功能，使用Tg机器人，需要自行申请
具体申请教程可以参考[博客链接](https://coderfan.net/how-to-use-telegram-bot-to-alarm-you-when-someone-login-into-your-vps.html)
使用说明:在面板后台设置机器人相关参数，具体包括

- Tg机器人Token
- Tg机器人ChatId
- Tg机器人周期运行时间，采用crontab语法  

参考语法：
- 30 * * * * * //每一分的第30s进行通知
- @hourly      //每小时通知
- @daily       //每天通知（凌晨零点整）
- @every 8h    //每8小时通知  

TG通知内容：
- 节点流量使用
- 面板登录提醒
- 节点到期提醒
- 流量预警提醒  

更多功能规划中...
## 建议系统

- CentOS 7+
- Ubuntu 16+
- Debian 8+
- Alpine 3.23+

# 常见问题

## issue 关闭

各种小白问题看得血压很高

## Stargazers over time

[![Stargazers over time](https://starchart.cc/vaxilu/x-ui.svg)](https://starchart.cc/vaxilu/x-ui)
