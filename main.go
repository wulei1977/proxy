package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"goproxy/internal/proxy"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("goproxy: %v", err)
	}
}

func run() error {
	cfg, err := parseConfig(os.Args[1:], os.Stderr, os.LookupEnv)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	cfg.Logger = log.New(os.Stderr, "", log.LstdFlags)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server, err := proxy.New(cfg)
	if err != nil {
		return err
	}
	return server.ListenAndServe(ctx)
}

func parseConfig(args []string, output io.Writer, lookupEnv func(string) (string, bool)) (proxy.Config, error) {
	cfg := proxy.Config{
		ListenAddr:  "127.0.0.1:8080",
		DialTimeout: 10 * time.Second,
	}

	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "监听地址；HTTP、HTTPS、SOCKS5 共用该端口")
	flags.IntVar(&cfg.MaxConnections, "max-connections", proxy.DefaultMaxConnections, "三种协议共用的客户端并发连接上限")
	flags.StringVar(&cfg.Username, "user", "", "代理用户名；需与密码一起设置")
	flags.StringVar(&cfg.Password, "pass", "", "代理密码；可通过 GOPROXY_PASS 设置")
	flags.StringVar(&cfg.CertFile, "cert", "", "HTTPS 代理使用的 PEM 证书文件；不填则自动生成自签名证书")
	flags.StringVar(&cfg.KeyFile, "key", "", "HTTPS 代理使用的 PEM 私钥文件；需与证书一起设置")
	flags.DurationVar(&cfg.DialTimeout, "dial-timeout", cfg.DialTimeout, "连接目标地址的超时时间")
	flags.DurationVar(&cfg.RequestReadTimeout, "request-read-timeout", proxy.DefaultRequestReadTimeout, "读取 HTTP 请求头和请求体的总时限")
	flags.DurationVar(&cfg.ResponseHeaderTimeout, "response-header-timeout", proxy.DefaultResponseHeaderTimeout, "HTTP 请求发送完毕后等待上游响应头的时限")
	flags.DurationVar(&cfg.UpstreamWriteTimeout, "upstream-write-timeout", proxy.DefaultUpstreamWriteTimeout, "上游连接就绪后发送 HTTP 请求的时限")
	flags.DurationVar(&cfg.ClientWriteTimeout, "client-write-timeout", proxy.DefaultClientWriteTimeout, "向客户端写入或刷新 HTTP 响应的单次时限")
	flags.DurationVar(&cfg.ResponseBodyIdleTimeout, "response-body-idle-timeout", proxy.DefaultResponseBodyIdleTimeout, "等待上游响应正文继续到达的时限")
	flags.DurationVar(&cfg.TunnelHalfCloseTimeout, "tunnel-half-close-timeout", proxy.DefaultTunnelHalfCloseTimeout, "隧道一侧半关闭后的空闲时限")
	flags.DurationVar(&cfg.TunnelWriteTimeout, "tunnel-write-timeout", proxy.DefaultTunnelWriteTimeout, "SOCKS5 和 CONNECT 隧道单次写入的时限")
	flags.BoolVar(&cfg.Verbose, "v", false, "输出每个请求的日志")
	flags.Usage = func() {
		fmt.Fprintf(output, `goproxy - HTTP/HTTPS/SOCKS5 代理

用法:
  %s [参数]

配置优先级从高到低为命令行、环境变量、当前目录的 .env、默认值。
环境变量使用 GOPROXY_ 前缀，参数名转为大写，连字符改为下划线。

参数:
`, flags.Name())
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return proxy.Config{}, err
	}

	if flags.NArg() != 0 {
		return proxy.Config{}, fmt.Errorf("多余的参数: %v", flags.Args())
	}
	if err := applyEnvironment(flags, lookupEnv); err != nil {
		return proxy.Config{}, err
	}
	if cfg.MaxConnections <= 0 {
		return proxy.Config{}, fmt.Errorf("-max-connections / GOPROXY_MAX_CONNECTIONS 必须为正整数")
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return proxy.Config{}, fmt.Errorf("证书和私钥必须同时提供（-cert / GOPROXY_CERT，-key / GOPROXY_KEY）")
	}
	if (cfg.Username == "") != (cfg.Password == "") {
		return proxy.Config{}, fmt.Errorf("用户名和密码必须同时提供（-user / GOPROXY_USER，-pass / GOPROXY_PASS）")
	}
	return cfg, nil
}

func applyEnvironment(flags *flag.FlagSet, lookupEnv func(string) (string, bool)) error {
	fileValues, err := readDotEnv(".env")
	if err != nil {
		return err
	}
	commandLine := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { commandLine[f.Name] = true })
	flags.VisitAll(func(f *flag.Flag) {
		if err != nil || commandLine[f.Name] {
			return
		}
		key := "GOPROXY_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		value, ok := lookupEnv(key)
		source := "环境变量"
		if !ok {
			value, ok = fileValues[key]
			source = ".env"
		}
		if ok && f.Value.Set(value) != nil {
			// Flag parsers may include the original input in their errors.
			err = fmt.Errorf("%s 中的 %s 无效（对应 -%s）", source, key, f.Name)
		}
	})
	return err
}
