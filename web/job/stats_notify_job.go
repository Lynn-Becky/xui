package job

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"x-ui/logger"
	"x-ui/util/common"
	"x-ui/web/service"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type LoginStatus byte

const (
	LoginSuccess LoginStatus = 1
	LoginFail    LoginStatus = 0
)

// maxNotifyFieldLen caps untrusted values embedded in notifications so a long
// submitted username cannot flood the administrator's chat.
const maxNotifyFieldLen = 64

// The Telegram client performs a getMe round trip when it is constructed, so it
// is built once and reused rather than per message.
var (
	botMu     sync.Mutex
	botClient *tgbotapi.BotAPI
	botToken  string
)

type StatsNotifyJob struct {
	enable         bool
	xrayService    service.XrayService
	inboundService service.InboundService
	settingService service.SettingService
}

func NewStatsNotifyJob() *StatsNotifyJob {
	return new(StatsNotifyJob)
}

// sanitizeNotifyField makes an untrusted value safe to embed in a notification.
//
// The username on a failed login is entirely attacker-chosen. Without this,
// carriage returns and newlines let an attacker forge additional lines inside
// the administrator's Telegram message — for example a fabricated "login
// success" entry to bury a real alert.
func sanitizeNotifyField(value string) string {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	// Collapse the resulting runs of whitespace so a padded value cannot be used
	// to push content off the visible part of a message.
	out := strings.Join(strings.Fields(b.String()), " ")
	runes := []rune(out)
	if len(runes) > maxNotifyFieldLen {
		return string(runes[:maxNotifyFieldLen]) + "..."
	}
	return out
}

// telegramBot returns the shared client and target chat, or an error when
// Telegram notifications are not usable.
func (j *StatsNotifyJob) telegramBot() (*tgbotapi.BotAPI, int64, error) {
	enabled, err := j.settingService.GetTgbotenabled()
	if err != nil {
		return nil, 0, err
	}
	if !enabled {
		return nil, 0, errTelegramDisabled
	}
	token, err := j.settingService.GetTgBotToken()
	if err != nil {
		return nil, 0, err
	}
	if strings.TrimSpace(token) == "" {
		return nil, 0, errors.New("telegram bot token is not configured")
	}
	chatId, err := j.settingService.GetTgBotChatId()
	if err != nil {
		return nil, 0, err
	}
	if chatId == 0 {
		return nil, 0, errors.New("telegram chat id is not configured")
	}

	botMu.Lock()
	defer botMu.Unlock()
	if botClient != nil && botToken == token {
		return botClient, int64(chatId), nil
	}
	client, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		return nil, 0, err
	}
	// Never enable client debug logging: it writes the full API request,
	// including the bot token in the URL, to the service log.
	client.Debug = false
	botClient = client
	botToken = token
	return client, int64(chatId), nil
}

var errTelegramDisabled = errors.New("telegram notifications are disabled")

func (j *StatsNotifyJob) SendMsgToTgbot(msg string) {
	bot, chatId, err := j.telegramBot()
	if err != nil {
		if errors.Is(err, errTelegramDisabled) {
			// Return before constructing a client. This path used to fall
			// through and call NewBotAPI even with an empty token, and that
			// constructor performs a synchronous getMe request — so on a default
			// install every failed login triggered an outbound HTTPS call that an
			// unauthenticated attacker could amplify by hammering /login.
			return
		}
		logger.Warning("sendMsgToTgbot failed:", err)
		return
	}
	if _, err := bot.Send(tgbotapi.NewMessage(chatId, msg)); err != nil {
		logger.Warning("sendMsgToTgbot: send failed:", err)
	}
}

// Here run is a interface method of Job interface
func (j *StatsNotifyJob) Run() {
	if !j.xrayService.IsXrayRunning() {
		return
	}
	var info string
	//get hostname
	name, err := os.Hostname()
	if err != nil {
		logger.Warning("get hostname error:", err)
		return
	}
	info = fmt.Sprintf("主机名称:%s\r\n", name)
	//get ip address
	var ip string
	netInterfaces, err := net.Interfaces()
	if err != nil {
		logger.Warning("net.Interfaces failed, err:", err)
		return
	}

	for i := 0; i < len(netInterfaces); i++ {
		if (netInterfaces[i].Flags & net.FlagUp) != 0 {
			addrs, _ := netInterfaces[i].Addrs()

			for _, address := range addrs {
				if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						ip = ipnet.IP.String()
						break
					} else {
						ip = ipnet.IP.String()
						break
					}
				}
			}
		}
	}
	info += fmt.Sprintf("IP地址:%s\r\n \r\n", ip)

	//get traffic
	inbouds, err := j.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("StatsNotifyJob run failed:", err)
		return
	}
	//NOTE:If there no any sessions here,need to notify here
	//TODO:分节点推送,自动转化格式
	for _, inbound := range inbouds {
		info += fmt.Sprintf("节点名称:%s\r\n端口:%d\r\n上行流量↑:%s\r\n下行流量↓:%s\r\n总流量:%s\r\n", sanitizeNotifyField(inbound.Remark), inbound.Port, common.FormatTraffic(inbound.Up), common.FormatTraffic(inbound.Down), common.FormatTraffic((inbound.Up + inbound.Down)))
		if inbound.ExpiryTime == 0 {
			info += "到期时间:无限期\r\n \r\n"
		} else {
			info += fmt.Sprintf("到期时间:%s\r\n \r\n", time.Unix((inbound.ExpiryTime/1000), 0).Format("2006-01-02 15:04:05"))
		}
	}
	j.SendMsgToTgbot(info)
}

func (j *StatsNotifyJob) UserLoginNotify(username string, ip string, timeStr string, status LoginStatus) {
	if username == "" || ip == "" || timeStr == "" {
		logger.Warning("UserLoginNotify failed, invalid info")
		return
	}
	// Check before doing any other work: a failed login is an unauthenticated
	// request, so everything on this path is attacker-triggerable.
	if enabled, err := j.settingService.GetTgbotenabled(); err != nil || !enabled {
		return
	}

	var msg string
	name, err := os.Hostname()
	if err != nil {
		logger.Warning("get hostname error:", err)
		return
	}
	if status == LoginSuccess {
		msg = fmt.Sprintf("面板登录成功提醒\r\n主机名称:%s\r\n", name)
	} else if status == LoginFail {
		msg = fmt.Sprintf("面板登录失败提醒\r\n主机名称:%s\r\n", name)
	}
	msg += fmt.Sprintf("时间:%s\r\n", timeStr)
	msg += fmt.Sprintf("用户:%s\r\n", sanitizeNotifyField(username))
	msg += fmt.Sprintf("IP:%s\r\n", sanitizeNotifyField(ip))
	j.SendMsgToTgbot(msg)
}
