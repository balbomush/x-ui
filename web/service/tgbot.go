package service

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alireza0/x-ui/config"
	"github.com/alireza0/x-ui/database"
	"github.com/alireza0/x-ui/database/model"
	"github.com/alireza0/x-ui/logger"
	"github.com/alireza0/x-ui/util/common"
	"github.com/alireza0/x-ui/util/random"
	"github.com/alireza0/x-ui/web/locale"
	"github.com/alireza0/x-ui/xray"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/skip2/go-qrcode"
)

var (
	bot       *tgbotapi.BotAPI
	adminIds  []int64
	isRunning bool
	hostname  string
)

type LoginStatus byte

const (
	LoginSuccess LoginStatus = 1
	LoginFail    LoginStatus = 0
)

type Tgbot struct {
	inboundService InboundService
	settingService SettingService
	serverService  ServerService
	lastStatus     *Status
}

func (t *Tgbot) NewTgbot() *Tgbot {
	return new(Tgbot)
}

func (t *Tgbot) I18nBot(name string, params ...string) string {
	return locale.I18n(locale.Bot, name, params...)
}

func (t *Tgbot) Start(i18nFS embed.FS) error {
	err := locale.InitLocalizer(i18nFS, &t.settingService)
	if err != nil {
		return err
	}

	t.SetHostname()
	tgBottoken, err := t.settingService.GetTgBotToken()
	if err != nil || tgBottoken == "" {
		logger.Warning("Get TgBotToken failed:", err)
		return err
	}

	tgBotid, err := t.settingService.GetTgBotChatId()
	if err != nil {
		logger.Warning("Get GetTgBotChatId failed:", err)
		return err
	}

	if tgBotid != "" {
		for _, adminId := range strings.Split(tgBotid, ",") {
			id, err := strconv.Atoi(adminId)
			if err != nil {
				logger.Warning("Failed to get IDs from GetTgBotChatId:", err)
				return err
			}
			adminIds = append(adminIds, int64(id))
		}
	}

	for {
		bot, err = tgbotapi.NewBotAPI(tgBottoken)
		if err != nil {
			fmt.Println("Get tgbot's api error:", err)
			fmt.Println("Retrying after 10 secound...")
			time.Sleep(10 * time.Second)
		} else {
			fmt.Println("Tgbot connected!")
			break
		}
	}
	bot.Debug = false

	// listen for TG bot income messages
	if !isRunning {
		logger.Info("Starting Telegram receiver ...")
		go t.OnReceive()
		isRunning = true
	}

	return nil
}

func (t *Tgbot) IsRunning() bool {
	return isRunning
}

func (t *Tgbot) SetHostname() {
	host, err := os.Hostname()
	if err != nil {
		logger.Error("get hostname error:", err)
		hostname = ""
		return
	}
	hostname = host
}

func (t *Tgbot) Stop() {
	bot.StopReceivingUpdates()
	logger.Info("Stop Telegram receiver ...")
	isRunning = false
	adminIds = nil
}

func (t *Tgbot) OnReceive() {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 10

	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		tgId := update.FromChat().ID
		chatId := update.FromChat().ChatConfig().ChatID
		isAdmin := checkAdmin(tgId)
		if update.Message == nil {
			if update.CallbackQuery != nil {
				t.answerCallback(update.CallbackQuery)
			}
		} else {
			if update.Message.IsCommand() {
				t.answerCommand(update.Message, chatId, isAdmin)
			}
		}
	}
}

func (t *Tgbot) answerCommand(message *tgbotapi.Message, chatId int64, isAdmin bool) {
	msg, onlyMessage := "", false

	command, commandArgs := message.Command(), message.CommandArguments()

	// Extract the command from the Message.
	switch command {
	case "help":
		msg += t.I18nBot("tgbot.commands.help")
		msg += t.I18nBot("tgbot.commands.pleaseChoose")
	case "start":
		msg += t.I18nBot("tgbot.commands.start", "Firstname=="+message.From.FirstName)
		if isAdmin {
			msg += t.I18nBot("tgbot.commands.welcome", "Hostname=="+hostname)
		}
		msg += "\n\n" + t.I18nBot("tgbot.commands.pleaseChoose")
	case "status":
		onlyMessage = true
		msg += t.I18nBot("tgbot.commands.status")
	case "id":
		onlyMessage = true
		msg += t.I18nBot("tgbot.commands.getID", "ID=="+strconv.FormatInt(message.From.ID, 10))
	case "usage":
		onlyMessage = true
		if len(commandArgs) > 1 {
			if isAdmin {
				t.searchClient(chatId, commandArgs)
			} else {
				t.searchForClient(chatId, commandArgs)
			}
		} else {
			msg += t.I18nBot("tgbot.commands.usage")
		}
	case "inbound":
		onlyMessage = true
		if isAdmin {
			t.searchInbound(chatId, commandArgs)
		} else {
			msg += t.I18nBot("tgbot.commands.unknown")
		}
	case "configs":
		onlyMessage = true
		t.sendClientConfigs(chatId, message.From.ID, message.From.UserName)
	default:
		msg += t.I18nBot("tgbot.commands.unknown")
	}

	if onlyMessage {
		t.SendMsgToTgbot(chatId, msg)
		return
	}
	t.SendAnswer(chatId, msg, isAdmin)
}

func (t *Tgbot) answerCallback(callbackQuery *tgbotapi.CallbackQuery) {
	// Respond to the callback query, telling Telegram to show the user
	// a message with the data received.
	callback := tgbotapi.NewCallback(callbackQuery.ID, callbackQuery.Data)
	if _, err := bot.Request(callback); err != nil {
		logger.Warning(err)
	}

	switch callbackQuery.Data {
	case "get_usage":
		t.SendMsgToTgbot(callbackQuery.From.ID, t.getServerUsage())
	case "inbounds":
		t.SendMsgToTgbot(callbackQuery.From.ID, t.getInboundUsages())
	case "deplete_soon":
		t.SendMsgToTgbot(callbackQuery.From.ID, t.getExhausted())
	case "get_backup":
		t.sendBackup(callbackQuery.From.ID)
	case "client_traffic":
		t.getClientUsage(callbackQuery.From.ID, callbackQuery.From.UserName)
	case "configs":
		t.sendClientConfigs(callbackQuery.From.ID, callbackQuery.From.ID, callbackQuery.From.UserName)
	case "client_commands":
		t.SendMsgToTgbot(callbackQuery.From.ID, t.I18nBot("tgbot.commands.helpClientCommands"))
	case "onlines":
		t.onlineClients(callbackQuery.From.ID)
	case "commands":
		t.SendMsgToTgbot(callbackQuery.From.ID, t.I18nBot("tgbot.commands.helpAdminCommands"))
	default:
		if callbackQuery.Data[:7] == "client_" {
			t.searchClient(callbackQuery.From.ID, callbackQuery.Data[7:])
		}
	}
}

func checkAdmin(tgId int64) bool {
	for _, adminId := range adminIds {
		if adminId == tgId {
			return true
		}
	}
	return false
}

func (t *Tgbot) SendAnswer(chatId int64, msg string, isAdmin bool) {
	numericKeyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(t.I18nBot("tgbot.buttons.serverUsage"), "get_usage"),
			tgbotapi.NewInlineKeyboardButtonData(t.I18nBot("tgbot.buttons.dbBackup"), "get_backup"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(t.I18nBot("tgbot.buttons.getInbounds"), "inbounds"),
			tgbotapi.NewInlineKeyboardButtonData(t.I18nBot("tgbot.buttons.depleteSoon"), "deplete_soon"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(t.I18nBot("tgbot.buttons.commands"), "commands"),
			tgbotapi.NewInlineKeyboardButtonData(t.I18nBot("tgbot.buttons.onlines"), "onlines"),
		),
	)
	numericKeyboardClient := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(t.I18nBot("tgbot.buttons.configs"), "configs"),
			tgbotapi.NewInlineKeyboardButtonData(t.I18nBot("tgbot.buttons.clientUsage"), "client_traffic"),
		),
	)

	var keyboardMarkup tgbotapi.InlineKeyboardMarkup
	if isAdmin {
		keyboardMarkup = numericKeyboard
	} else {
		keyboardMarkup = numericKeyboardClient
	}
	t.SendMsgToTgbot(chatId, msg, keyboardMarkup)
}

func (t *Tgbot) SendMsgToTgbot(tgid int64, msg string, replyMarkup ...tgbotapi.InlineKeyboardMarkup) {
	if !isRunning {
		return
	}

	if msg == "" {
		logger.Info("[tgbot] message is empty!")
		return
	}

	var allMessages []string
	limit := 2000

	// paging message if it is big
	if len(msg) > limit {
		messages := strings.Split(msg, "\r\n \r\n")
		lastIndex := -1

		for _, message := range messages {
			if (len(allMessages) == 0) || (len(allMessages[lastIndex])+len(message) > limit) {
				allMessages = append(allMessages, message)
				lastIndex++
			} else {
				allMessages[lastIndex] += "\r\n \r\n" + message
			}
		}
	} else {
		allMessages = append(allMessages, msg)
	}
	for _, message := range allMessages {
		info := tgbotapi.NewMessage(tgid, message)
		info.ParseMode = "HTML"
		if len(replyMarkup) > 0 {
			info.ReplyMarkup = replyMarkup[0]
		}
		_, err := bot.Send(info)
		if err != nil {
			logger.Warning("Error sending telegram message :", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (t *Tgbot) SendMsgToTgbotAdmins(msg string) {
	for _, adminId := range adminIds {
		t.SendMsgToTgbot(adminId, msg)
	}
}

func (t *Tgbot) SendReport() {
	runTime, err := t.settingService.GetTgbotRuntime()
	if err == nil && len(runTime) > 0 {
		msg := ""
		msg += t.I18nBot("tgbot.messages.report", "RunTime=="+runTime)
		msg += t.I18nBot("tgbot.messages.datetime", "DateTime=="+time.Now().Format("2006-01-02 15:04:05"))
		t.SendMsgToTgbotAdmins(msg)
	}

	info := t.getServerUsage()
	t.SendMsgToTgbotAdmins(info)

	exhausted := t.getExhausted()
	t.SendMsgToTgbotAdmins(exhausted)

	backupEnable, err := t.settingService.GetTgBotBackup()
	if err == nil && backupEnable {
		t.SendBackupToAdmins()
	}
}

func (t *Tgbot) SendBackupToAdmins() {
	if !t.IsRunning() {
		return
	}
	for _, adminId := range adminIds {
		t.sendBackup(int64(adminId))
	}
}

func (t *Tgbot) getServerUsage() string {
	info, ipv4, ipv6 := "", "", ""
	info += t.I18nBot("tgbot.messages.hostname", "Hostname=="+hostname)
	info += t.I18nBot("tgbot.messages.version", "Version=="+config.GetVersion())

	// get ip address
	netInterfaces, err := net.Interfaces()
	if err != nil {
		logger.Error("net.Interfaces failed, err: ", err.Error())
		info += t.I18nBot("tgbot.messages.ip", "IP=="+t.I18nBot("tgbot.unknown"))
		info += " \r\n"
	} else {
		for i := 0; i < len(netInterfaces); i++ {
			if (netInterfaces[i].Flags & net.FlagUp) != 0 {
				addrs, _ := netInterfaces[i].Addrs()

				for _, address := range addrs {
					if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
						if ipnet.IP.To4() != nil {
							ipv4 += ipnet.IP.String() + " "
						} else if ipnet.IP.To16() != nil && !ipnet.IP.IsLinkLocalUnicast() {
							ipv6 += ipnet.IP.String() + " "
						}
					}
				}
			}
		}

		info += t.I18nBot("tgbot.messages.ipv4", "IPv4=="+ipv4)
		info += t.I18nBot("tgbot.messages.ipv6", "IPv6=="+ipv6)
	}

	// get latest status of server
	t.lastStatus = t.serverService.GetStatus(t.lastStatus)
	info += t.I18nBot("tgbot.messages.serverUpTime", "UpTime=="+strconv.FormatUint(t.lastStatus.Uptime/86400, 10), "Unit=="+t.I18nBot("tgbot.days"))
	info += t.I18nBot("tgbot.messages.serverLoad", "Load1=="+strconv.FormatFloat(t.lastStatus.Loads[0], 'f', 2, 64), "Load2=="+strconv.FormatFloat(t.lastStatus.Loads[1], 'f', 2, 64), "Load3=="+strconv.FormatFloat(t.lastStatus.Loads[2], 'f', 2, 64))
	info += t.I18nBot("tgbot.messages.serverMemory", "Current=="+common.FormatTraffic(int64(t.lastStatus.Mem.Current)), "Total=="+common.FormatTraffic(int64(t.lastStatus.Mem.Total)))
	info += t.I18nBot("tgbot.messages.tcpCount", "Count=="+strconv.Itoa(t.lastStatus.TcpCount))
	info += t.I18nBot("tgbot.messages.udpCount", "Count=="+strconv.Itoa(t.lastStatus.UdpCount))
	info += t.I18nBot("tgbot.messages.traffic", "Total=="+common.FormatTraffic(int64(t.lastStatus.NetTraffic.Sent+t.lastStatus.NetTraffic.Recv)), "Upload=="+common.FormatTraffic(int64(t.lastStatus.NetTraffic.Sent)), "Download=="+common.FormatTraffic(int64(t.lastStatus.NetTraffic.Recv)))
	info += t.I18nBot("tgbot.messages.xrayStatus", "State=="+fmt.Sprint(t.lastStatus.Xray.State))

	return info
}

func (t *Tgbot) UserLoginNotify(username string, ip string, time string, status LoginStatus) {
	if !t.IsRunning() {
		return
	}

	if username == "" || ip == "" || time == "" {
		logger.Warning("UserLoginNotify failed,invalid info")
		return
	}

	loginNotifyEnabled, err := t.settingService.GetTgBotLoginNotify()
	if err != nil || !loginNotifyEnabled {
		return
	}

	msg := ""
	if status == LoginSuccess {
		msg += t.I18nBot("tgbot.messages.loginSuccess")
	} else if status == LoginFail {
		msg += t.I18nBot("tgbot.messages.loginFailed")
	}
	msg += t.I18nBot("tgbot.messages.hostname", "Hostname=="+hostname)
	msg += t.I18nBot("tgbot.messages.username", "Username=="+username)
	msg += t.I18nBot("tgbot.messages.ip", "IP=="+ip)
	msg += t.I18nBot("tgbot.messages.time", "Time=="+time)

	t.SendMsgToTgbotAdmins(msg)
}

func (t *Tgbot) getInboundUsages() string {
	info := ""
	// get traffic
	inbounds, err := t.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("GetAllInbounds run failed:", err)
		info += t.I18nBot("tgbot.answers.getInboundsFailed")
	} else {
		// NOTE:If there no any sessions here,need to notify here
		// TODO:Sub-node push, automatic conversion format
		for _, inbound := range inbounds {
			info += t.I18nBot("tgbot.messages.inbound", "Remark=="+inbound.Remark)
			info += t.I18nBot("tgbot.messages.port", "Port=="+strconv.Itoa(inbound.Port))
			info += t.I18nBot("tgbot.messages.traffic", "Total=="+common.FormatTraffic((inbound.Up+inbound.Down)), "Upload=="+common.FormatTraffic(inbound.Up), "Download=="+common.FormatTraffic(inbound.Down))

			if inbound.ExpiryTime == 0 {
				info += t.I18nBot("tgbot.messages.expire", "DateTime=="+t.I18nBot("tgbot.unlimited"))
			} else {
				info += t.I18nBot("tgbot.messages.expire", "DateTime=="+time.Unix((inbound.ExpiryTime/1000), 0).Format("2006-01-02 15:04:05"))
			}
		}
	}
	return info
}

func (t *Tgbot) clientInfoMsg(traffic *xray.ClientTraffic) string {
	expiryTime := ""
	if traffic.ExpiryTime == 0 {
		expiryTime = t.I18nBot("tgbot.unlimited")
	} else if traffic.ExpiryTime < 0 {
		expiryTime = fmt.Sprintf("%d %s", traffic.ExpiryTime/-86400000, t.I18nBot("tgbot.days"))
	} else {
		expiryTime = time.Unix((traffic.ExpiryTime / 1000), 0).Format("2006-01-02 15:04:05")
	}

	total := ""
	if traffic.Total == 0 {
		total = t.I18nBot("tgbot.unlimited")
	} else {
		total = common.FormatTraffic((traffic.Total))
	}

	active := ""
	if traffic.Enable {
		active = t.I18nBot("tgbot.messages.yes")
	} else {
		active = t.I18nBot("tgbot.messages.no")
	}

	status := "🔴 " + t.I18nBot("offline")
	if p.IsRunning() {
		for _, online := range p.GetOnlineClients() {
			if online == traffic.Email {
				status = "🟢 " + t.I18nBot("online")
				break
			}
		}
	}

	output := ""
	output += t.I18nBot("tgbot.messages.active", "Enable=="+active)
	output += t.I18nBot("tgbot.messages.online", "Status=="+status)
	output += t.I18nBot("tgbot.messages.email", "Email=="+traffic.Email)
	output += t.I18nBot("tgbot.messages.upload", "Upload=="+common.FormatTraffic(traffic.Up))
	output += t.I18nBot("tgbot.messages.download", "Download=="+common.FormatTraffic(traffic.Down))
	output += t.I18nBot("tgbot.messages.total", "UpDown=="+common.FormatTraffic((traffic.Up+traffic.Down)), "Total=="+total)
	output += t.I18nBot("tgbot.messages.expireIn", "Time=="+expiryTime)

	return output
}

func (t *Tgbot) getClientUsage(chatId int64, tgUserName string) {
	if len(tgUserName) == 0 {
		msg := t.I18nBot("tgbot.answers.askToAddUser")
		t.SendMsgToTgbot(chatId, msg)
		return
	}

	traffics, err := t.inboundService.GetClientTrafficTgBot(strconv.FormatInt(chatId, 10), tgUserName)
	if err != nil {
		logger.Warning(err)
		msg := t.I18nBot("tgbot.wentWrong")
		t.SendMsgToTgbot(chatId, msg)
		return
	}
	if len(traffics) == 0 {
		msg := t.I18nBot("tgbot.answers.askToAddUserName", "TgUserName=="+tgUserName)
		msg += "\r\n" + t.I18nBot("tgbot.commands.getID", "ID=="+strconv.FormatInt(chatId, 10))
		t.SendMsgToTgbot(chatId, msg)
		return
	}

	for _, traffic := range traffics {
		output := t.clientInfoMsg(traffic)
		t.SendMsgToTgbot(chatId, output)
	}
	t.SendAnswer(chatId, t.I18nBot("tgbot.commands.pleaseChoose"), false)
}

func (t *Tgbot) searchClient(chatId int64, email string) {
	traffic, err := t.inboundService.GetClientTrafficByEmail(email)
	if err != nil {
		logger.Warning(err)
		msg := t.I18nBot("tgbot.wentWrong")
		t.SendMsgToTgbot(chatId, msg)
		return
	}
	if traffic == nil {
		msg := t.I18nBot("tgbot.noResult")
		t.SendMsgToTgbot(chatId, msg)
		return
	}

	output := t.clientInfoMsg(traffic)
	t.SendMsgToTgbot(chatId, output)
}

func (t *Tgbot) searchInbound(chatId int64, remark string) {
	inbounds, err := t.inboundService.SearchInbounds(remark)
	if err != nil {
		logger.Warning(err)
		msg := t.I18nBot("tgbot.wentWrong")
		t.SendMsgToTgbot(chatId, msg)
		return
	}

	if len(inbounds) == 0 {
		msg := t.I18nBot("tgbot.noInbounds")
		t.SendMsgToTgbot(chatId, msg)
		return
	}

	for _, inbound := range inbounds {
		info := ""
		info += t.I18nBot("tgbot.messages.inbound", "Remark=="+inbound.Remark)
		info += t.I18nBot("tgbot.messages.port", "Port=="+strconv.Itoa(inbound.Port))
		info += t.I18nBot("tgbot.messages.traffic", "Total=="+common.FormatTraffic((inbound.Up+inbound.Down)), "Upload=="+common.FormatTraffic(inbound.Up), "Download=="+common.FormatTraffic(inbound.Down))

		if inbound.ExpiryTime == 0 {
			info += t.I18nBot("tgbot.messages.expire", "DateTime=="+t.I18nBot("tgbot.unlimited"))
		} else {
			info += t.I18nBot("tgbot.messages.expire", "DateTime=="+time.Unix((inbound.ExpiryTime/1000), 0).Format("2006-01-02 15:04:05"))
		}
		t.SendMsgToTgbot(chatId, info)

		for _, traffic := range inbound.ClientStats {
			output := t.clientInfoMsg(&traffic)
			t.SendMsgToTgbot(chatId, output)
		}
	}
}

func (t *Tgbot) searchForClient(chatId int64, query string) {
	traffic, err := t.inboundService.SearchClientTraffic(query)
	if err != nil {
		logger.Warning(err)
		msg := t.I18nBot("tgbot.wentWrong")
		t.SendMsgToTgbot(chatId, msg)
		return
	}
	if traffic == nil {
		msg := t.I18nBot("tgbot.noResult")
		t.SendMsgToTgbot(chatId, msg)
		return
	}

	output := t.clientInfoMsg(traffic)
	t.SendMsgToTgbot(chatId, output)
}

func (t *Tgbot) getExhausted() string {
	trDiff := int64(0)
	exDiff := int64(0)
	now := time.Now().Unix() * 1000
	var exhaustedInbounds []model.Inbound
	var exhaustedClients []xray.ClientTraffic
	var disabledInbounds []model.Inbound
	var disabledClients []xray.ClientTraffic

	TrafficThreshold, err := t.settingService.GetTrafficDiff()
	if err == nil && TrafficThreshold > 0 {
		trDiff = int64(TrafficThreshold) * 1073741824
	}
	ExpireThreshold, err := t.settingService.GetExpireDiff()
	if err == nil && ExpireThreshold > 0 {
		exDiff = int64(ExpireThreshold) * 86400000
	}
	inbounds, err := t.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("Unable to load Inbounds", err)
	}

	for _, inbound := range inbounds {
		if inbound.Enable {
			if (inbound.ExpiryTime > 0 && (inbound.ExpiryTime-now < exDiff)) ||
				(inbound.Total > 0 && (inbound.Total-(inbound.Up+inbound.Down) < trDiff)) {
				exhaustedInbounds = append(exhaustedInbounds, *inbound)
			}
			if len(inbound.ClientStats) > 0 {
				for _, client := range inbound.ClientStats {
					if client.Enable {
						if (client.ExpiryTime > 0 && (client.ExpiryTime-now < exDiff)) ||
							(client.Total > 0 && (client.Total-(client.Up+client.Down) < trDiff)) {
							exhaustedClients = append(exhaustedClients, client)
						}
					} else {
						disabledClients = append(disabledClients, client)
					}
				}
			}
		} else {
			disabledInbounds = append(disabledInbounds, *inbound)
		}
	}

	// Inbounds
	output := ""
	output += t.I18nBot("tgbot.messages.exhaustedCount", "Type=="+t.I18nBot("tgbot.inbounds"))
	output += t.I18nBot("tgbot.messages.disabled", "Disabled=="+strconv.Itoa(len(disabledInbounds)))
	output += t.I18nBot("tgbot.messages.depleteSoon", "Deplete=="+strconv.Itoa(len(exhaustedInbounds)))
	output += "\r\n \r\n"

	if len(exhaustedInbounds) > 0 {
		output += t.I18nBot("tgbot.messages.exhaustedMsg", "Type=="+t.I18nBot("tgbot.inbounds"))

		for _, inbound := range exhaustedInbounds {
			output += t.I18nBot("tgbot.messages.inbound", "Remark=="+inbound.Remark)
			output += t.I18nBot("tgbot.messages.port", "Port=="+strconv.Itoa(inbound.Port))
			output += t.I18nBot("tgbot.messages.traffic", "Total=="+common.FormatTraffic((inbound.Up+inbound.Down)), "Upload=="+common.FormatTraffic(inbound.Up), "Download=="+common.FormatTraffic(inbound.Down))
			if inbound.ExpiryTime == 0 {
				output += t.I18nBot("tgbot.messages.expire", "DateTime=="+t.I18nBot("tgbot.unlimited"))
			} else {
				output += t.I18nBot("tgbot.messages.expire", "DateTime=="+time.Unix((inbound.ExpiryTime/1000), 0).Format("2006-01-02 15:04:05"))
			}
			output += "\r\n \r\n"
		}
	}

	// Clients
	output += t.I18nBot("tgbot.messages.exhaustedCount", "Type=="+t.I18nBot("tgbot.clients"))
	output += t.I18nBot("tgbot.messages.disabled", "Disabled=="+strconv.Itoa(len(disabledClients)))
	output += t.I18nBot("tgbot.messages.depleteSoon", "Deplete=="+strconv.Itoa(len(exhaustedClients)))
	output += "\r\n \r\n"

	if len(exhaustedClients) > 0 {
		output += t.I18nBot("tgbot.messages.exhaustedMsg", "Type=="+t.I18nBot("tgbot.clients"))

		for _, traffic := range exhaustedClients {
			output += t.clientInfoMsg(&traffic)
			output += "\r\n \r\n"
		}
	}

	return output
}

func (t *Tgbot) onlineClients(chatId int64) {
	if !p.IsRunning() {
		return
	}

	onlines := p.GetOnlineClients()
	output := t.I18nBot("tgbot.messages.onlinesCount", "Count=="+fmt.Sprint(len(onlines)))
	if len(onlines) > 0 {
		keyboard := tgbotapi.NewInlineKeyboardMarkup()
		for index, online := range onlines {
			keyboard.InlineKeyboard = append(keyboard.InlineKeyboard, tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData(fmt.Sprintf("%d: %s\r\n", index+1, online), "client_"+online)))
		}
		t.SendMsgToTgbot(chatId, output, keyboard)
	} else {
		t.SendMsgToTgbot(chatId, output)
	}
}

func (t *Tgbot) sendBackup(chatId int64) {
	if !t.IsRunning() {
		return
	}

	// Update by manually trigger a checkpoint operation
	err := database.Checkpoint()
	if err != nil {
		logger.Warning("Error in trigger a checkpoint operation: ", err)
	}

	output := t.I18nBot("tgbot.messages.backupTime", "Time=="+time.Now().Format("2006-01-02 15:04:05"))
	t.SendMsgToTgbot(chatId, output)

	file := tgbotapi.FilePath(config.GetDBPath())
	msg := tgbotapi.NewDocument(chatId, file)
	_, err = bot.Send(msg)
	if err != nil {
		logger.Warning("Error in uploading backup: ", err)
	}

	file = tgbotapi.FilePath(xray.GetConfigPath())
	msg = tgbotapi.NewDocument(chatId, file)
	_, err = bot.Send(msg)
	if err != nil {
		logger.Warning("Error in uploading config.json: ", err)
	}
}

func (t *Tgbot) sendClientConfigs(chatId int64, tgId int64, tgUserName string) {
	if !t.IsRunning() {
		return
	}

	tgIdStr := strconv.FormatInt(tgId, 10)
	tgUserNameStr := ""
	if tgUserName != "" {
		tgUserNameStr = tgUserName
	}

	// Get all clients with matching tgID
	clientInbounds, err := t.inboundService.GetClientsByTgID(tgIdStr, tgUserNameStr)
	if err != nil {
		logger.Warning("Error getting clients by tgID:", err)
		msg := t.I18nBot("tgbot.wentWrong")
		t.SendMsgToTgbot(chatId, msg)
		return
	}

	if len(clientInbounds) == 0 {
		username := tgUserNameStr
		if username == "" {
			username = tgIdStr
		}
		msg := fmt.Sprintf("Пользователь с таким ником %s не найден. Обратитесь к администратору", username)
		t.SendMsgToTgbot(chatId, msg)
		return
	}

	// Get server address for generating links
	serverAddress := t.getServerAddress()

	// Send config for each client
	for _, clientInbound := range clientInbounds {
		if !clientInbound.Client.Enable {
			continue
		}

		// Generate configuration link
		configLink := t.generateConfigLink(clientInbound.Inbound, clientInbound.Email, serverAddress)
		if configLink == "" {
			logger.Warning("Failed to generate link for client:", clientInbound.Email)
			continue
		}

		// Generate QR code
		qrCode, err := qrcode.Encode(configLink, qrcode.Medium, 256)
		if err != nil {
			logger.Warning("Error generating QR code:", err)
			// Send text only if QR generation fails
			msg := fmt.Sprintf("📋 <b>%s</b>\n\n<code>%s</code>", clientInbound.Inbound.Remark, configLink)
			t.SendMsgToTgbot(chatId, msg)
			continue
		}

		// Prepare message text
		msgText := fmt.Sprintf("📋 <b>%s</b>\n\n<code>%s</code>", clientInbound.Inbound.Remark, configLink)

		// Send photo with QR code and text
		photo := tgbotapi.NewPhoto(chatId, tgbotapi.FileBytes{
			Name:  "qrcode.png",
			Bytes: qrCode,
		})
		photo.Caption = msgText
		photo.ParseMode = "HTML"

		_, err = bot.Send(photo)
		if err != nil {
			logger.Warning("Error sending QR code:", err)
			// Fallback to text only
			t.SendMsgToTgbot(chatId, msgText)
		}

		// Small delay between messages
		time.Sleep(500 * time.Millisecond)
	}
}

func (t *Tgbot) getServerAddress() string {
	// Try to get domain first
	domain, err := t.settingService.GetWebDomain()
	if err == nil && domain != "" && domain != "yourhostname" {
		return domain
	}

	// Try to get listen address
	listen, err := t.settingService.GetListen()
	if err == nil && listen != "" && listen != "0.0.0.0" && listen != "::" {
		return listen
	}

	// Try to get IP address from network interfaces (prefer non-loopback, non-link-local)
	var preferredIP string
	var fallbackIP string
	netInterfaces, err := net.Interfaces()
	if err == nil {
		for i := 0; i < len(netInterfaces); i++ {
			if (netInterfaces[i].Flags & net.FlagUp) != 0 {
				addrs, _ := netInterfaces[i].Addrs()
				for _, address := range addrs {
					if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
						if ipnet.IP.To4() != nil {
							// Prefer non-link-local addresses
							if !ipnet.IP.IsLinkLocalUnicast() {
								preferredIP = ipnet.IP.String()
								break
							} else if fallbackIP == "" {
								fallbackIP = ipnet.IP.String()
							}
						}
					}
				}
				if preferredIP != "" {
					break
				}
			}
		}
	}

	if preferredIP != "" {
		return preferredIP
	}
	if fallbackIP != "" {
		return fallbackIP
	}

	// Last resort: try hostname only if it's not "yourhostname"
	if hostname != "" && hostname != "yourhostname" {
		return hostname
	}

	return "127.0.0.1"
}

// generateConfigLink generates a configuration link for a client
// This is a simplified version to avoid circular import with sub package
func (t *Tgbot) generateConfigLink(inbound *model.Inbound, email string, address string) string {
	clients, err := t.inboundService.GetClients(inbound)
	if err != nil {
		return ""
	}

	var client *model.Client
	for i := range clients {
		if clients[i].Email == email {
			client = &clients[i]
			break
		}
	}
	if client == nil {
		return ""
	}

	switch inbound.Protocol {
	case model.VLESS:
		return t.generateVlessLink(inbound, client, address)
	case model.VMess:
		return t.generateVmessLink(inbound, client, address)
	case model.Trojan:
		return t.generateTrojanLink(inbound, client, address)
	case model.Shadowsocks:
		return t.generateShadowsocksLink(inbound, client, address)
	}
	return ""
}

// Helper functions for generating links (simplified versions)
func (t *Tgbot) generateVlessLink(inbound *model.Inbound, client *model.Client, address string) string {
	var vlessSettings model.VLESSSettings
	json.Unmarshal([]byte(inbound.Settings), &vlessSettings)

	var stream map[string]interface{}
	json.Unmarshal([]byte(inbound.StreamSettings), &stream)

	link := fmt.Sprintf("vless://%s@%s:%d", client.ID, address, inbound.Port)
	u, _ := url.Parse(link)
	q := u.Query()

	// Add encryption parameter
	if vlessSettings.Encryption != "" {
		q.Set("encryption", vlessSettings.Encryption)
	} else {
		q.Set("encryption", "none")
	}

	// Add type parameter (must be first)
	streamNetwork, _ := stream["network"].(string)
	q.Set("type", streamNetwork)

	// Add stream settings based on network type
	switch streamNetwork {
	case "tcp":
		if tcp, ok := stream["tcpSettings"].(map[string]interface{}); ok {
			if header, ok := tcp["header"].(map[string]interface{}); ok {
				if headerType, ok := header["type"].(string); ok && headerType == "http" {
					if request, ok := header["request"].(map[string]interface{}); ok {
						if path, ok := request["path"].([]interface{}); ok && len(path) > 0 {
							q.Set("path", path[0].(string))
						}
						if headers, ok := request["headers"].(map[string]interface{}); ok {
							if host, ok := headers["Host"].([]interface{}); ok && len(host) > 0 {
								q.Set("host", host[0].(string))
							}
						}
						q.Set("headerType", "http")
					}
				}
			}
		}
	case "ws":
		if ws, ok := stream["wsSettings"].(map[string]interface{}); ok {
			if path, ok := ws["path"].(string); ok {
				q.Set("path", path)
			}
			if host, ok := ws["host"].(string); ok && host != "" {
				q.Set("host", host)
			} else if headers, ok := ws["headers"].(map[string]interface{}); ok {
				if host, ok := headers["Host"].([]interface{}); ok && len(host) > 0 {
					q.Set("host", host[0].(string))
				}
			}
		}
	case "grpc":
		if grpc, ok := stream["grpcSettings"].(map[string]interface{}); ok {
			if serviceName, ok := grpc["serviceName"].(string); ok {
				q.Set("serviceName", serviceName)
			}
			if authority, ok := grpc["authority"].(string); ok && authority != "" {
				q.Set("authority", authority)
			}
			if multiMode, ok := grpc["multiMode"].(bool); ok && multiMode {
				q.Set("mode", "multi")
			}
		}
	case "httpupgrade":
		if httpupgrade, ok := stream["httpupgradeSettings"].(map[string]interface{}); ok {
			if path, ok := httpupgrade["path"].(string); ok {
				q.Set("path", path)
			}
			if host, ok := httpupgrade["host"].(string); ok && host != "" {
				q.Set("host", host)
			}
		}
	case "xhttp":
		if xhttp, ok := stream["xhttpSettings"].(map[string]interface{}); ok {
			if path, ok := xhttp["path"].(string); ok {
				q.Set("path", path)
			}
			if host, ok := xhttp["host"].(string); ok && host != "" {
				q.Set("host", host)
			}
			if mode, ok := xhttp["mode"].(string); ok {
				q.Set("mode", mode)
			}
		}
	}

	// Add security settings
	security, _ := stream["security"].(string)
	if security == "tls" {
		q.Set("security", "tls")
		if tls, ok := stream["tlsSettings"].(map[string]interface{}); ok {
			if sni, ok := t.searchKey(tls, "serverName"); ok {
				q.Set("sni", sni.(string))
			}
			if settings, ok := t.searchKey(tls, "settings"); ok {
				if fp, ok := t.searchKey(settings, "fingerprint"); ok {
					if fpStr, ok := fp.(string); ok && fpStr != "" {
						q.Set("fp", fpStr)
					}
				}
			}
		}
		if streamNetwork == "tcp" && client.Flow != "" {
			q.Set("flow", client.Flow)
		}
	} else if security == "reality" {
		q.Set("security", "reality")
		if reality, ok := stream["realitySettings"].(map[string]interface{}); ok {
			realitySettings, _ := t.searchKey(reality, "settings")
			if realitySettings != nil {
				if pbk, ok := t.searchKey(realitySettings, "publicKey"); ok {
					if pbkStr, ok := pbk.(string); ok && pbkStr != "" {
						q.Set("pbk", pbkStr)
					}
				}
				if fp, ok := t.searchKey(realitySettings, "fingerprint"); ok {
					if fpStr, ok := fp.(string); ok && fpStr != "" {
						q.Set("fp", fpStr)
					}
				}
				if pqv, ok := t.searchKey(realitySettings, "mldsa65Verify"); ok {
					if pqvStr, ok := pqv.(string); ok && pqvStr != "" {
						q.Set("pqv", pqvStr)
					}
				}
				if spx, ok := t.searchKey(realitySettings, "spiderX"); ok {
					if spxStr, ok := spx.(string); ok && spxStr != "" {
						q.Set("spx", spxStr)
					} else {
						// Generate random spx if not present
						q.Set("spx", "/"+random.Seq(15))
					}
				} else {
					// Generate random spx if not present
					q.Set("spx", "/"+random.Seq(15))
				}
			}
			if serverNames, ok := reality["serverNames"].([]interface{}); ok && len(serverNames) > 0 {
				q.Set("sni", serverNames[0].(string))
			}
			if shortIds, ok := reality["shortIds"].([]interface{}); ok && len(shortIds) > 0 {
				q.Set("sid", shortIds[0].(string))
			} else {
				q.Set("sid", "")
			}
		}
		if streamNetwork == "tcp" && client.Flow != "" {
			q.Set("flow", client.Flow)
		}
	} else {
		q.Set("security", "none")
	}

	u.RawQuery = q.Encode()
	// Use client email as fragment instead of remark
	u.Fragment = client.Email
	return u.String()
}

func (t *Tgbot) generateVmessLink(inbound *model.Inbound, client *model.Client, address string) string {
	var stream map[string]interface{}
	json.Unmarshal([]byte(inbound.StreamSettings), &stream)

	obj := map[string]interface{}{
		"v":    "2",
		"add":  address,
		"port": inbound.Port,
		"id":   client.ID,
		"type": "none",
	}

	network, _ := stream["network"].(string)
	obj["net"] = network

	// Add stream settings
	switch network {
	case "ws":
		if ws, ok := stream["wsSettings"].(map[string]interface{}); ok {
			if path, ok := ws["path"].(string); ok {
				obj["path"] = path
			}
			if host, ok := ws["host"].(string); ok && host != "" {
				obj["host"] = host
			}
		}
	}

	security, _ := stream["security"].(string)
	obj["tls"] = security

	obj["ps"] = inbound.Remark

	jsonStr, _ := json.Marshal(obj)
	return "vmess://" + base64.StdEncoding.EncodeToString(jsonStr)
}

func (t *Tgbot) generateTrojanLink(inbound *model.Inbound, client *model.Client, address string) string {
	var stream map[string]interface{}
	json.Unmarshal([]byte(inbound.StreamSettings), &stream)

	link := fmt.Sprintf("trojan://%s@%s:%d", client.Password, address, inbound.Port)
	u, _ := url.Parse(link)
	q := u.Query()

	// Add type parameter (must be first)
	streamNetwork, _ := stream["network"].(string)
	q.Set("type", streamNetwork)

	// Add stream settings based on network type
	switch streamNetwork {
	case "tcp":
		if tcp, ok := stream["tcpSettings"].(map[string]interface{}); ok {
			if header, ok := tcp["header"].(map[string]interface{}); ok {
				if headerType, ok := header["type"].(string); ok && headerType == "http" {
					if request, ok := header["request"].(map[string]interface{}); ok {
						if path, ok := request["path"].([]interface{}); ok && len(path) > 0 {
							q.Set("path", path[0].(string))
						}
						if headers, ok := request["headers"].(map[string]interface{}); ok {
							if host, ok := headers["Host"].([]interface{}); ok && len(host) > 0 {
								q.Set("host", host[0].(string))
							}
						}
						q.Set("headerType", "http")
					}
				}
			}
		}
	case "ws":
		if ws, ok := stream["wsSettings"].(map[string]interface{}); ok {
			if path, ok := ws["path"].(string); ok {
				q.Set("path", path)
			}
			if host, ok := ws["host"].(string); ok && host != "" {
				q.Set("host", host)
			} else if headers, ok := ws["headers"].(map[string]interface{}); ok {
				if host, ok := headers["Host"].([]interface{}); ok && len(host) > 0 {
					q.Set("host", host[0].(string))
				}
			}
		}
	case "grpc":
		if grpc, ok := stream["grpcSettings"].(map[string]interface{}); ok {
			if serviceName, ok := grpc["serviceName"].(string); ok {
				q.Set("serviceName", serviceName)
			}
			if authority, ok := grpc["authority"].(string); ok && authority != "" {
				q.Set("authority", authority)
			}
			if multiMode, ok := grpc["multiMode"].(bool); ok && multiMode {
				q.Set("mode", "multi")
			}
		}
	case "httpupgrade":
		if httpupgrade, ok := stream["httpupgradeSettings"].(map[string]interface{}); ok {
			if path, ok := httpupgrade["path"].(string); ok {
				q.Set("path", path)
			}
			if host, ok := httpupgrade["host"].(string); ok && host != "" {
				q.Set("host", host)
			}
		}
	case "xhttp":
		if xhttp, ok := stream["xhttpSettings"].(map[string]interface{}); ok {
			if path, ok := xhttp["path"].(string); ok {
				q.Set("path", path)
			}
			if host, ok := xhttp["host"].(string); ok && host != "" {
				q.Set("host", host)
			}
			if mode, ok := xhttp["mode"].(string); ok {
				q.Set("mode", mode)
			}
		}
	}

	// Add security settings
	security, _ := stream["security"].(string)
	if security == "tls" {
		q.Set("security", "tls")
		if tls, ok := stream["tlsSettings"].(map[string]interface{}); ok {
			if sni, ok := t.searchKey(tls, "serverName"); ok {
				q.Set("sni", sni.(string))
			}
			if settings, ok := t.searchKey(tls, "settings"); ok {
				if fp, ok := t.searchKey(settings, "fingerprint"); ok {
					if fpStr, ok := fp.(string); ok && fpStr != "" {
						q.Set("fp", fpStr)
					}
				}
			}
		}
	} else if security == "reality" {
		q.Set("security", "reality")
		if reality, ok := stream["realitySettings"].(map[string]interface{}); ok {
			realitySettings, _ := t.searchKey(reality, "settings")
			if realitySettings != nil {
				if pbk, ok := t.searchKey(realitySettings, "publicKey"); ok {
					if pbkStr, ok := pbk.(string); ok && pbkStr != "" {
						q.Set("pbk", pbkStr)
					}
				}
				if fp, ok := t.searchKey(realitySettings, "fingerprint"); ok {
					if fpStr, ok := fp.(string); ok && fpStr != "" {
						q.Set("fp", fpStr)
					}
				}
				if pqv, ok := t.searchKey(realitySettings, "mldsa65Verify"); ok {
					if pqvStr, ok := pqv.(string); ok && pqvStr != "" {
						q.Set("pqv", pqvStr)
					}
				}
				if spx, ok := t.searchKey(reality, "spiderX"); ok {
					if spxStr, ok := spx.(string); ok && spxStr != "" {
						q.Set("spx", spxStr)
					} else {
						// Generate random spx if not present
						q.Set("spx", "/"+random.Seq(15))
					}
				} else {
					// Generate random spx if not present
					q.Set("spx", "/"+random.Seq(15))
				}
			}
			if serverNames, ok := reality["serverNames"].([]interface{}); ok && len(serverNames) > 0 {
				q.Set("sni", serverNames[0].(string))
			}
			if shortIds, ok := reality["shortIds"].([]interface{}); ok && len(shortIds) > 0 {
				q.Set("sid", shortIds[0].(string))
			} else {
				q.Set("sid", "")
			}
		}
	} else {
		q.Set("security", "none")
	}

	u.RawQuery = q.Encode()
	// Use client email as fragment instead of remark
	u.Fragment = client.Email
	return u.String()
}

func (t *Tgbot) generateShadowsocksLink(inbound *model.Inbound, client *model.Client, address string) string {
	var settings map[string]interface{}
	json.Unmarshal([]byte(inbound.Settings), &settings)

	method, _ := settings["method"].(string)
	password := client.Password

	encPart := fmt.Sprintf("%s:%s", method, password)
	link := fmt.Sprintf("ss://%s@%s:%d", base64.StdEncoding.EncodeToString([]byte(encPart)), address, inbound.Port)
	u, _ := url.Parse(link)
	u.Fragment = inbound.Remark
	return u.String()
}

// Helper function to search for a key in nested map
func (t *Tgbot) searchKey(data interface{}, key string) (interface{}, bool) {
	switch val := data.(type) {
	case map[string]interface{}:
		for k, v := range val {
			if k == key {
				return v, true
			}
			if result, ok := t.searchKey(v, key); ok {
				return result, true
			}
		}
	case []interface{}:
		for _, v := range val {
			if result, ok := t.searchKey(v, key); ok {
				return result, true
			}
		}
	}
	return nil, false
}
