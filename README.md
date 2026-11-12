# ![Juice Shop Logo](https://raw.githubusercontent.com/juice-shop/juice-shop/master/frontend/src/assets/public/images/JuiceShop_Logo_100px.png) OWASP Juice Shop

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-48A646.svg)](https://owasp.org/projects/#sec-flagships)
[![GitHub release](https://img.shields.io/github/release/juice-shop/juice-shop.svg)](https://github.com/juice-shop/juice-shop/releases/latest)
[![Twitter Follow](https://img.shields.io/twitter/follow/owasp_juiceshop.svg?style=social&label=Follow)](https://twitter.com/owasp_juiceshop)
[![Subreddit subscribers](https://img.shields.io/reddit/subreddit-subscribers/owasp_juiceshop?style=social)](https://reddit.com/r/owasp_juiceshop)

[![CI/CD Pipeline](https://github.com/juice-shop/juice-shop/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/juice-shop/juice-shop/actions/workflows/ci.yml)
[![Release Pipeline](https://github.com/juice-shop/juice-shop/actions/workflows/release.yml/badge.svg)](https://github.com/juice-shop/juice-shop/actions/workflows/release.yml)
[![Coverage Status](https://coveralls.io/repos/github/juice-shop/juice-shop/badge.svg?branch=develop)](https://coveralls.io/github/juice-shop/juice-shop?branch=develop)
[![Cypress tests](https://img.shields.io/endpoint?url=https://dashboard.cypress.io/badge/simple/3hrkhu/develop&style=flat&logo=cypress)](https://dashboard.cypress.io/projects/3hrkhu/runs)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/223/badge)](https://www.bestpractices.dev/projects/223)
![GitHub stars](https://img.shields.io/github/stars/juice-shop/juice-shop.svg?label=GitHub%20%E2%98%85&style=flat)
[![Static Badge](https://img.shields.io/badge/OWASP-Code_of_Conduct-blue)](CODE_OF_CONDUCT.md)

> [市面上最值得信赖的在线商店。](https://twitter.com/dschadow/status/706781693504589824)
> ([@dschadow](https://github.com/dschadow)) —
> [全网最棒的果汁店！](https://twitter.com/shehackspurple/status/907335357775085568)
> ([@shehackspurple](https://twitter.com/shehackspurple)) —
> [世上最没有 Bug 的漏洞应用！](https://youtu.be/TXAztSpYpvE?t=26m35s)
> ([@vanderaj](https://twitter.com/vanderaj)) —
> [先让你 😂😂，再让你 😢](https://twitter.com/kramse/status/1073168529405472768)
> ([@kramse](https://twitter.com/kramse)) —
> [但这跟果汁压根没半点关系啊。](https://twitter.com/coderPatros/status/1199268774626488320)
> ([@coderPatros 的妻子](https://twitter.com/coderPatros))

OWASP Juice Shop 可能是目前最现代化、最精密的不安全 Web 应用程序！它可以用于安全培训、安全意识演示、CTF 夺旗赛，以及作为各类安全工具的测试靶场！Juice Shop 涵盖了整个 [OWASP Top Ten](https://owasp.org/www-project-top-ten) 中的所有漏洞类别，以及大量在真实世界应用程序中发现的其他安全缺陷！

![Juice Shop Screenshot Slideshow](screenshots/slideshow.gif)

如需详细了解项目介绍、完整功能列表及架构概览，请访问官方项目主页：
<https://owasp-juice.shop>

## 目录

- [安装与部署](#安装与部署)
    - [从源码安装](#从源码安装)
    - [预打包发行版](#预打包发行版)
    - [Docker 容器](#docker-容器)
    - [Vagrant](#vagrant)
- [在线演示](#在线演示)
- [文档](#文档)
    - [Node.js 版本兼容性](#nodejs-版本兼容性)
    - [故障排查](#故障排查)
    - [官方配套指南](#官方配套指南)
- [参与贡献](#参与贡献)
- [相关引用](#相关引用)
- [周边商品](#周边商品)
- [捐赠支持](#捐赠支持)
- [贡献者](#贡献者)
- [开源许可](#开源许可)

## 安装与部署

> 你可以在[_运行 OWASP Juice Shop_ 文档](https://pwning.owasp-juice.shop/companion-guide/latest/part1/running.html)中找到一些不太常见的安装方式，以及在各类云计算平台上运行 Juice Shop 的说明。

> 部分挑战需要配置 AI/LLM 服务提供商才能正常运行。请查阅[_设置外部依赖项_文档](https://pwning.owasp-juice.shop/companion-guide/snapshot/part1/running.html#_setting_up_external_dependencies)，了解如何配置本地或云端 AI 服务提供商。

### 从源码安装

![GitHub repo size](https://img.shields.io/github/repo-size/juice-shop/juice-shop.svg)

1. 安装 [node.js](#nodejs-版本兼容性)
2. 运行 `git clone https://github.com/juice-shop/juice-shop.git --depth 1`（或克隆该仓库[你自己的 Fork](https://github.com/juice-shop/juice-shop/fork)）
3. 使用 `cd juice-shop` 进入克隆后的目录
4. 运行 `npm install`（仅需在首次启动前或修改源代码后执行）
5. 运行 `npm start`
6. 在浏览器中访问 <http://localhost:3000>

### 预打包发行版

[![GitHub release](https://img.shields.io/github/downloads/juice-shop/juice-shop/total.svg)](https://github.com/juice-shop/juice-shop/releases/latest)
[![SourceForge](https://img.shields.io/sourceforge/dm/juice-shop?label=sourceforge%20downloads)](https://sourceforge.net/projects/juice-shop/)
[![SourceForge](https://img.shields.io/sourceforge/dt/juice-shop?label=sourceforge%20downloads)](https://sourceforge.net/projects/juice-shop/)

1. 在你的 Windows、MacOS 或 Linux 机器上安装 64 位 [node.js](#nodejs-版本兼容性)
2. 从[最新发行版](https://github.com/juice-shop/juice-shop/releases/latest)附件中下载 `juice-shop-<version>_<node-version>_<os>_x64.zip`（或 `.tgz`）
3. 解压并 `cd` 进入解压后的文件夹
4. 运行 `npm start`
5. 在浏览器中访问 <http://localhost:3000>

> 每个预打包发行版都包含与执行 `npm install` 时的操作系统和 node.js 版本绑定的 `sqlite3` 和 `libxmljs2` 二进制文件。

### Docker 容器

[![Docker Pulls](https://img.shields.io/docker/pulls/bkimminich/juice-shop.svg)](https://hub.docker.com/r/bkimminich/juice-shop)
![Docker Stars](https://img.shields.io/docker/stars/bkimminich/juice-shop.svg)
[![](https://images.microbadger.com/badges/image/bkimminich/juice-shop.svg)](https://microbadger.com/images/bkimminich/juice-shop
"Get your own image badge on microbadger.com")
[![](https://images.microbadger.com/badges/version/bkimminich/juice-shop.svg)](https://microbadger.com/images/bkimminich/juice-shop
"Get your own version badge on microbadger.com")

1. 安装 [Docker](https://www.docker.com)
2. 运行 `docker pull bkimminich/juice-shop`
3. 运行 `docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop`
4. 在浏览器中访问 <http://localhost:3000>（在 macOS 和 Windows 上，如果你使用的是 docker-machine 而非原生 Docker 安装，请访问 <http://192.168.99.100:3000>）

### Vagrant

1. 安装 [Vagrant](https://www.vagrantup.com/downloads.html) 和 [Virtualbox](https://www.virtualbox.org/wiki/Downloads)
2. 运行 `git clone https://github.com/juice-shop/juice-shop.git`（或克隆该仓库[你自己的 Fork](https://github.com/juice-shop/juice-shop/fork)）
3. 运行 `cd vagrant && vagrant up`
4. 在浏览器中访问 [192.168.56.110](http://192.168.56.110)

## 在线演示

欢迎随时体验最新版本的 OWASP Juice Shop：
<http://demo.owasp-juice.shop>

> 这仅是一个用于部署测试和抢先体验的实例！请__不要__将该实例用于你自己的渗透测试或解题尝试！不保证正常运行时间！如果你把它搞崩了，保证会收到严厉的注视！

## 文档

### Node.js 版本兼容性

![GitHub package.json dynamic](https://img.shields.io/github/package-json/cpu/juice-shop/juice-shop)
![GitHub package.json dynamic](https://img.shields.io/github/package-json/os/juice-shop/juice-shop)

OWASP Juice Shop 尽可能紧跟官方 [node.js LTS 发布计划](https://github.com/nodejs/LTS)，正式支持以下版本的 [node.js](http://nodejs.org)。Docker 镜像和预打包发行版也会据此提供。

| node.js | 支持情况               | 测试情况           | [预打包发行版](#预打包发行版)                     | 来自 `master` 的 [Docker 镜像](#docker-容器)     | 来自 `develop` 的 [Docker 镜像](#docker-容器)     |
|:--------|:-----------------------|:-------------------|:--------------------------------------------------|:-------------------------------------------------|:--------------------------------------------------|
| 26.x    | :x:                    | :x:                |                                                   |                                                  |                                                   |
| 25.x    | ( :heavy_check_mark: ) | :x:                |                                                   |                                                  |                                                   |
| 24.x    | :heavy_check_mark:     | :heavy_check_mark: | Windows (`x64`), MacOS (`x64`), Linux (`x64`)     | `latest` (`linux/amd64`, `linux/arm64`)          |                                                   |
| 23.x    | ( :heavy_check_mark: ) | :x:                |                                                   |                                                  |                                                   |
| 22.x    | :heavy_check_mark:     | :heavy_check_mark: | Windows (`x64`), MacOS (`x64`), Linux (`x64`)     |                                                  | `snapshot` (`linux/amd64`, `linux/arm64`)         |
| <22.x   | :x:                    | :x:                |                                                   |                                                  |                                                   |

Juice Shop 仅针对上述各个 node.js 版本的_最新 `.x` 次版本号_进行自动化测试！无法保证旧的 node.js 次版本始终能正常运行 Juice Shop！请确保将你所选用的版本保持在最新状态。

### 故障排查

[![Gitter](http://img.shields.io/badge/gitter-join%20chat-1dce73.svg)](https://gitter.im/bkimminich/juice-shop)

如果你在应用安装与配置过程中需要帮助，请先查阅[我们现有的_故障排查_指南](https://pwning.owasp-juice.shop/companion-guide/latest/part4/troubleshooting.html)。如果仍未能解决你的问题，请在 [Gitter 聊天室](https://gitter.im/bkimminich/juice-shop)中发布你的具体问题或疑问，社区成员会尽力为你提供帮助。

:stop_sign: **请勿在 GitHub Issues 中提交技术支持请求或一般性提问！**

### 官方配套指南

[![Write Goodreads Review](https://img.shields.io/badge/goodreads-write%20review-49557240.svg)](https://www.goodreads.com/review/edit/49557240)

OWASP Juice Shop 配有一本官方配套指南电子书。它将为你全面介绍应用中包含的所有漏洞，并提供如何发现与利用这些漏洞的提示。在附录中，你甚至可以找到每一个挑战的完整分步解题指南。书中还包含有关[自定义品牌化](https://pwning.owasp-juice.shop/companion-guide/latest/part4/customization.html)、[CTF 支持](https://pwning.owasp-juice.shop/companion-guide/latest/part4/ctf.html)、[讲师指南](https://pwning.owasp-juice.shop/companion-guide/latest/part4/trainers.html)等丰富内容的详细文档。

[Pwning OWASP Juice Shop](https://leanpub.com/juice-shop) 采用 [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/) 许可协议发布，可在 LeanPub 上**免费**获取 PDF、Kindle 和 ePub 格式版本。你也可以[在线浏览完整内容](https://pwning.owasp-juice.shop)！

[<img alt="Pwning OWASP Juice Shop cover" src="https://raw.githubusercontent.com/juice-shop/pwning-juice-shop/master/docs/modules/ROOT/assets/images/cover.jpg" width="200"/>](https://leanpub.com/juice-shop)
[<img alt="Pwning OWASP Juice Shop back cover" src="https://raw.githubusercontent.com/juice-shop/pwning-juice-shop/master/docs/modules/ROOT/assets/images/introduction/back.jpg" width="200"/>](https://leanpub.com/juice-shop)

## 参与贡献

[![GitHub contributors](https://img.shields.io/github/contributors/juice-shop/juice-shop.svg)](https://github.com/juice-shop/juice-shop/graphs/contributors)
[![JavaScript Style Guide](https://img.shields.io/badge/code%20style-standard-brightgreen.svg)](http://standardjs.com/)
[![Crowdin](https://d322cqt584bo4o.cloudfront.net/owasp-juice-shop/localized.svg)](https://crowdin.com/project/owasp-juice-shop)
![GitHub issues by-label](https://img.shields.io/github/issues/juice-shop/juice-shop/help%20wanted.svg)
![GitHub issues by-label](https://img.shields.io/github/issues/juice-shop/juice-shop/good%20first%20issue.svg)

我们非常欢迎新的贡献者加入！请查阅 [CONTRIBUTING.md](CONTRIBUTING.md)，了解如何[为代码库做出贡献](CONTRIBUTING.md#code-contributions)或参与[多语言翻译工作](CONTRIBUTING.md#i18n-contributions)！

## 相关引用

你是否撰写过关于或提及 OWASP Juice Shop 的博客文章、杂志文章，或者录制过相关播客？又或者你主持或参加过提及本项目的技术大会演讲、线下聚会（Meetup）、黑客工作坊或公开培训？

欢迎 Fork 本仓库并提交 Pull Request，将其添加到我们不断扩充的 [REFERENCES.md](REFERENCES.md) 列表中！

## 周边商品

* 在 [Spreadshirt.com](http://shop.spreadshirt.com/juiceshop) 和 [Spreadshirt.de](http://shop.spreadshirt.de/juiceshop) 上，你可以购买印有官方 OWASP Juice Shop 标志的周边商品（T 恤、连帽衫、马克杯）
* 在 [StickerYou.com](https://www.stickeryou.com/products/owasp-juice-shop/794) 上，你可以购买不同款式的 OWASP Juice Shop 标志单张贴纸来装饰你的笔记本电脑。他们还可以印制磁贴、烫印贴、整版贴纸和一次性纹身贴。

## 捐赠支持

[![](https://img.shields.io/badge/support-owasp%20juice%20shop-blue)](https://owasp.org/donate/?reponame=www-project-juice-shop&title=OWASP+Juice+Shop)

OWASP 基金会非常感谢通过 Stripe 进行的捐赠。像 Juice Shop 这样的项目随后可以向基金会申请费用报销。如果你希望表达对 Juice Shop 项目的支持，请务必在捐赠表单中勾选“Publicly list me as a supporter of OWASP Juice Shop”（将我公开列为 OWASP Juice Shop 的支持者）复选框。你可以在此处了解更多关于捐赠及其用途的信息：

<https://pwning.owasp-juice.shop/companion-guide/latest/part3/donations.html>

## 贡献者

OWASP Juice Shop 项目负责人为：

- [Björn Kimminich](https://github.com/bkimminich)（又名 `bkimminich`）[![Keybase PGP](https://img.shields.io/keybase/pgp/bkimminich)](https://keybase.io/bkimminich)
- [Jannik Hollenbach](https://github.com/J12934)（又名 `J12934`）

如需查看 OWASP Juice Shop 所有贡献者的名单，请访问我们的 [HALL_OF_FAME.md](HALL_OF_FAME.md)。

## 开源许可

[![license](https://img.shields.io/github/license/juice-shop/juice-shop.svg)](LICENSE)

本程序是自由软件：你可以根据 [MIT 许可证](LICENSE)的条款重新分发和/或修改它。
OWASP Juice Shop 及任何贡献内容的版权归 Bjoern Kimminich 与 OWASP Juice Shop 贡献者所有 © 2014-2026。

![Juice Shop Logo](https://raw.githubusercontent.com/juice-shop/juice-shop/master/frontend/src/assets/public/images/JuiceShop_Logo_400px.png)
