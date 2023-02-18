vmessc：vmess 代理协议客户端
============================

Features
--------

1. 接收并自动检测 SOCKS5/HTTP 协议的代理请求。
2. 自定义请求处理规则：丢弃、在本地处理或转发给 vmess 节点。
3. 支持 V2rayN 格式的订阅和管理多个 vmess 节点。
4. 基于动态调整的权重自动选择 vmess 节点。

Usage
-----

1. 规则

规则文件的默认路径是 `rule.txt`，格式如下：

```
# comment: baidu
block	ads.baidu.com
direct	baidu.com

# comment: github
forward	github.com
```

匹配域名 `1.www.baidu.com` 时依次匹配`1.www.baidu.com`、
`www.baidu.com`、`baidu.com`，最终匹配到 `direct`，即在本地处理请求；
匹配 `1.ads.baidu.com` 时依次匹配`1.ads.baidu.com`、`ads.baidu.com`，
最终匹配到 `block`，即丢弃请求；同理，`gist.github.com` 会匹配到
`forward`，即选择一个 vmess 节点转发请求；如果未匹配到任何规则，将使用
默认规则（称为 direction）。

相同的域名越靠前的优先级越高，可以在规则文件的前几行添加规则来覆盖后面
的规则。如果不需要规则匹配，那么可以将规则文件设置为空文件或不存在的文
件。

`scripts/dlc_merge.py` 将
[domain-list](https://github.com/v2fly/domain-list-community) 收录的域
名转化为 vmessc 的规则文件可能满足你的需求。

2. 配置

配置文件的默认路径是 `config.json`，格式如下：

```json
{
  "fetch_url": "https://example.net",
  "local_url": "http://localhost:1080",
  "direction": "direct",
  "rule_file": "rule.txt",
  "log_level": "INFO",
  "log_format": "%(asctime)s %(name)s %(levelname)s %(message)s",
  "log_datefmt": "%y-%m-%d %H:%M:%S",
  "nodes": [
    {
      "name": "peer1",
      "addr": "peer1.net",
      "port": "80",
      "uuid": "...",
      "delay": 0.4,
      "weight": 20.0
    },
    {
      "name": "peer2",
      "addr": "peer2.net",
      "port": "443",
      "uuid": "...",
      "delay": 0.5,
      "weight": 10.0
    },
  ]
}
```

`fetch_url` 是 V2rayN 格式的订阅链接，一般来说这是用户唯一需要关心的配
置项；后面的配置项：`local_url`、`direction`、`rule_file` `log_level`
`log_format`、`log_datefmt` 如字面意思；`nodes` 配置项包含所有 vmess
节点，其中 `delay` 是延迟，在 ping 之前或 ping 超时后为 -1.0；
`weight`是初始权重，在获取时为 10.0，ping 超时后为 -1.0，vmessc 根据权
重选取 vmess 节点，并在运行中根据请求是否处理成功动态地调整权重。

用户不需要手动编辑配置文件，vmessc 提供的命令行界面可以方便地生成和更
新配置文件。

3. 命令行界面

```
python -m vmessc
```

进入交互式的命令行界面，或者

```
python -m vmessc xxx
```

快速运行 vmessc 命令。

在交互式界面，`?` 可以显示帮助信息，`TAB` 可以补全命令。

- `set k v` 设置除 `nodes` 之外的配置项。
- `list` 列出所有节点。
- `run n...` 运行 vmess 客户端，可以指定或默认所有节点。
- `delete n...` 删除节点。
- `ping n...` ping 节点，默认 ping 所有节点。
- `fetch [proxy]` 获取订阅节点，可选地通过 proxy 代理。

TLDR.

```sh
# bootstrap
$ python -m vmessc
> set fetch_url https://example.net
> fetch
> ping
> run
server start at ...
...

# quick start
$ python -m vmessc run
server start at ...
...
```

Internal
--------

1. defaults.py：定义一些常量，例如默认的配置文件和规则文件路径、默认的监听端口等。
2. nodes.py：实现可序列化、反序列化的 vmess 节点类，和 V2rayN 格式的订阅节点的获取。
3. rule.py：实现规则文件的加载和规则匹配。
4. proxy.py：实现 SOCKS5/HTTP 代理协议接收器和原始连接器。
5. vmess.py：实现 vmess 代理协议连接器。
6. client.py：实现基于规则匹配和动态节点选择的 vmess 客户端。
7. config.py：实现配置文件管理和客户端启动。
8. cli.py：实现命令行界面。
