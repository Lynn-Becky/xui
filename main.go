package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	_ "unsafe"
	"x-ui/config"
	"x-ui/database"
	"x-ui/logger"
	"x-ui/v2ui"
	"x-ui/web"
	"x-ui/web/global"
	"x-ui/web/service"

	"github.com/op/go-logging"
)

func runWebServer() {
	log.Printf("%v %v", config.GetName(), config.GetVersion())

	switch config.GetLogLevel() {
	case config.Debug:
		logger.InitLogger(logging.DEBUG)
	case config.Info:
		logger.InitLogger(logging.INFO)
	case config.Warn:
		logger.InitLogger(logging.WARNING)
	case config.Error:
		logger.InitLogger(logging.ERROR)
	default:
		log.Fatal("unknown log level:", config.GetLogLevel())
	}

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		log.Fatal(err)
	}

	var server *web.Server

	server = web.NewServer()
	global.SetWebServer(server)
	err = server.Start()
	if err != nil {
		log.Println(err)
		return
	}

	sigCh := make(chan os.Signal, 1)
	//信号量捕获处理
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGKILL)
	for {
		sig := <-sigCh

		switch sig {
		case syscall.SIGHUP:
			err := server.Stop()
			if err != nil {
				logger.Warning("stop server err:", err)
			}
			server = web.NewServer()
			global.SetWebServer(server)
			err = server.Start()
			if err != nil {
				log.Println(err)
				return
			}
		default:
			server.Stop()
			return
		}
	}
}

func resetSetting() {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	settingService := service.SettingService{}
	err = settingService.ResetSettings()
	if err != nil {
		fmt.Println("reset setting failed:", err)
	} else {
		fmt.Println("reset setting success")
	}
}

func showSetting(show bool) {
	if show {
		settingService := service.SettingService{}
		port, err := settingService.GetPort()
		if err != nil {
			fmt.Println("get current port fialed,error info:", err)
		}
		webBasePath, err := settingService.GetBasePath()
		if err != nil {
			fmt.Println("get current webBasePath failed,error info:", err)
		}
		webCertFile, certErr := settingService.GetCertFile()
		webKeyFile, keyErr := settingService.GetKeyFile()
		if certErr != nil || keyErr != nil {
			fmt.Println("get current web certificate paths failed:", certErr, keyErr)
		}
		userService := service.UserService{}
		userModel, err := userService.GetFirstUser()
		if err != nil {
			fmt.Println("get current user info failed,error info:", err)
		}
		username := userModel.Username
		userpasswd := userModel.Password
		if (username == "") || (userpasswd == "") {
			fmt.Println("current username or password is empty")
		}
		fmt.Println("current pannel settings as follows:")
		fmt.Println("username:", username)
		fmt.Println("userpasswd:", userpasswd)
		fmt.Println("port:", port)
		fmt.Println("webBasePath:", webBasePath)
		fmt.Println("webCertFile:", webCertFile)
		fmt.Println("webKeyFile:", webKeyFile)
	}
}

func updateCert(certFile, keyFile string) error {
	if (certFile == "") != (keyFile == "") {
		return fmt.Errorf("web certificate and key must be configured together")
	}
	if certFile != "" {
		if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			return fmt.Errorf("invalid web certificate or key: %w", err)
		}
	}
	if err := database.InitDB(config.GetDBPath()); err != nil {
		return err
	}
	settingService := service.SettingService{}
	if err := settingService.SetCertFile(certFile); err != nil {
		return err
	}
	if err := settingService.SetKeyFile(keyFile); err != nil {
		return err
	}
	fmt.Println("set web certificate paths success")
	return nil
}

func showCert() error {
	if err := database.InitDB(config.GetDBPath()); err != nil {
		return err
	}
	settingService := service.SettingService{}
	certFile, err := settingService.GetCertFile()
	if err != nil {
		return err
	}
	keyFile, err := settingService.GetKeyFile()
	if err != nil {
		return err
	}
	fmt.Println("cert:", certFile)
	fmt.Println("key:", keyFile)
	return nil
}

func updateTgbotEnableSts(status bool) {
	settingService := service.SettingService{}
	currentTgSts, err := settingService.GetTgbotenabled()
	if err != nil {
		fmt.Println(err)
		return
	}
	logger.Infof("current enabletgbot status[%v],need update to status[%v]", currentTgSts, status)
	if currentTgSts != status {
		err := settingService.SetTgbotenabled(status)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Infof("SetTgbotenabled[%v] success", status)
		}
	}
	return
}

func updateTgbotSetting(tgBotToken string, tgBotChatid int, tgBotRuntime string) {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	settingService := service.SettingService{}

	if tgBotToken != "" {
		err := settingService.SetTgBotToken(tgBotToken)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Info("updateTgbotSetting tgBotToken success")
		}
	}

	if tgBotRuntime != "" {
		err := settingService.SetTgbotRuntime(tgBotRuntime)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Infof("updateTgbotSetting tgBotRuntime[%s] success", tgBotRuntime)
		}
	}

	if tgBotChatid != 0 {
		err := settingService.SetTgBotChatId(tgBotChatid)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Info("updateTgbotSetting tgBotChatid success")
		}
	}
}

func updateSetting(port int, username string, password string, webBasePath string) error {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return err
	}

	settingService := service.SettingService{}

	if port > 0 {
		err := settingService.SetPort(port)
		if err != nil {
			fmt.Println("set port failed:", err)
			return err
		} else {
			fmt.Printf("set port %v success", port)
		}
	}
	if username != "" || password != "" {
		userService := service.UserService{}
		err := userService.UpdateFirstUser(username, password)
		if err != nil {
			fmt.Println("set username and password failed:", err)
			return err
		} else {
			fmt.Println("set username and password success")
		}
	}
	if webBasePath != "" {
		err := settingService.SetBasePath(webBasePath)
		if err != nil {
			fmt.Println("set web base path failed:", err)
			return err
		} else {
			fmt.Println("set web base path success")
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		runWebServer()
		return
	}

	var showVersion bool
	flag.BoolVar(&showVersion, "v", false, "show version")

	runCmd := flag.NewFlagSet("run", flag.ExitOnError)

	v2uiCmd := flag.NewFlagSet("v2-ui", flag.ExitOnError)
	var dbPath string
	v2uiCmd.StringVar(&dbPath, "db", "/etc/v2-ui/v2-ui.db", "set v2-ui db file path")

	settingCmd := flag.NewFlagSet("setting", flag.ExitOnError)
	var port int
	var username string
	var password string
	var webBasePath string
	var tgbottoken string
	var tgbotchatid int
	var enabletgbot bool
	var tgbotRuntime string
	var reset bool
	var show bool
	settingCmd.BoolVar(&reset, "reset", false, "reset all settings")
	settingCmd.BoolVar(&show, "show", false, "show current settings")
	settingCmd.IntVar(&port, "port", 0, "set panel port")
	settingCmd.StringVar(&username, "username", "", "set login username")
	settingCmd.StringVar(&password, "password", "", "set login password")
	settingCmd.StringVar(&webBasePath, "webBasePath", "", "set panel base path")
	settingCmd.StringVar(&tgbottoken, "tgbottoken", "", "set telegrame bot token")
	settingCmd.StringVar(&tgbotRuntime, "tgbotRuntime", "", "set telegrame bot cron time")
	settingCmd.IntVar(&tgbotchatid, "tgbotchatid", 0, "set telegrame bot chat id")
	settingCmd.BoolVar(&enabletgbot, "enabletgbot", false, "enable telegram bot notify")

	certCmd := flag.NewFlagSet("cert", flag.ExitOnError)
	var webCertFile string
	var webKeyFile string
	var getCert bool
	var resetCert bool
	certCmd.StringVar(&webCertFile, "webCert", "", "set panel certificate file")
	certCmd.StringVar(&webKeyFile, "webCertKey", "", "set panel certificate key file")
	certCmd.BoolVar(&getCert, "getCert", false, "show panel certificate paths")
	certCmd.BoolVar(&resetCert, "reset", false, "clear panel certificate paths")

	oldUsage := flag.Usage
	flag.Usage = func() {
		oldUsage()
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("    run            run web panel")
		fmt.Println("    v2-ui          migrate form v2-ui")
		fmt.Println("    setting        set settings")
		fmt.Println("    cert           set or show panel certificate paths")
	}

	flag.Parse()
	if showVersion {
		fmt.Println(config.GetVersion())
		return
	}

	switch os.Args[1] {
	case "run":
		err := runCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		runWebServer()
	case "v2-ui":
		err := v2uiCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		err = v2ui.MigrateFromV2UI(dbPath)
		if err != nil {
			fmt.Println("migrate from v2-ui failed:", err)
		}
	case "setting":
		err := settingCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		if reset {
			resetSetting()
		} else {
			if err := updateSetting(port, username, password, webBasePath); err != nil {
				os.Exit(1)
			}
		}
		if show {
			showSetting(show)
		}
		if (tgbottoken != "") || (tgbotchatid != 0) || (tgbotRuntime != "") {
			updateTgbotSetting(tgbottoken, tgbotchatid, tgbotRuntime)
		}
	case "cert":
		if err := certCmd.Parse(os.Args[2:]); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if getCert {
			if err := showCert(); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			return
		}
		if resetCert {
			webCertFile, webKeyFile = "", ""
		} else if webCertFile == "" && webKeyFile == "" {
			certCmd.Usage()
			os.Exit(1)
		}
		if err := updateCert(webCertFile, webKeyFile); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	default:
		fmt.Println("except 'run', 'v2-ui', 'setting' or 'cert' subcommands")
		fmt.Println()
		runCmd.Usage()
		fmt.Println()
		v2uiCmd.Usage()
		fmt.Println()
		settingCmd.Usage()
		fmt.Println()
		certCmd.Usage()
	}
}
