package telegram

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/apache/incubator-answer/plugin"
)

type TelegramConnector struct {
	plugin.Connector
	Config *TelegramConnectorConfig
}

type TelegramConnectorConfig struct {
	Name     string `json:"name"`
	BotID    string `json:"bot_id"`
	BotToken string `json:bot_token`
	Domain   string `json:domain`
	LogoSVG  string `json:"logo_svg"`
}

func init() {
	plugin.Register(&TelegramConnector{
		Config: &TelegramConnectorConfig{},
	})
}

func (g *TelegramConnector) Info() plugin.Info {
	return plugin.Info{
		Name:        plugin.MakeTranslator("Telegram"),
		SlugName:    "telegram_connector",
		Description: plugin.MakeTranslator("Telegram"),
		Author:      "answerdev",
		Version:     "0.1.2",
		Link:        "https://github.com/hbsciw/apache-answer-telgram-connector",
	}
}

func (g *TelegramConnector) ConnectorLogoSVG() string {
	return g.Config.LogoSVG
}

func (g *TelegramConnector) ConnectorName() plugin.Translator {
	// if len(g.Config.Name) > 0 {
	// 	g.Config.Name = "telegram connector"
	// 	return plugin.MakeTranslator(g.Config.Name)
	// }
	return plugin.MakeTranslator(g.Config.Name)
	//return plugin.MakeTranslator(i18n.ConnectorName)
}

func (g *TelegramConnector) ConnectorSlugName() string {
	return "telegram"
}

func (g *TelegramConnector) ConnectorSender(ctx *plugin.GinContext, receiverURL string) (redirectURL string) {

	return "https://oauth.telegram.org/auth?bot_id=" + g.Config.BotID + "&origin=" + g.Config.Domain + "&embed=1&request_access=write&return_to=https://balenj.com/balenj/telegramRedirect"

}

func (g *TelegramConnector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (userInfo plugin.ExternalLoginUserInfo, err error) {

	telegramData, res := ctx.GetQuery("tgAuthResult")
	paddedData := telegramData + strings.Repeat("=", 4-len(telegramData)%4)

	if !res {
		return userInfo, errors.New("invalid telegram authentication data")
	}

	// Decode the base64 string
	decodedBytes, err := base64.StdEncoding.DecodeString(paddedData)
	if err != nil {
		return userInfo, err
	}

	data, err := unmarshalJSON(decodedBytes)
	if err != nil {
		return userInfo, err
	}

	if !checkTelegramAuthorization(data, g.Config.BotToken) {
		return userInfo, errors.New("invalid telegram signature")
	}

	userInfo = plugin.ExternalLoginUserInfo{
		MetaInfo:    mapToString((data)),
		ExternalID:  "telegram-auth|" + data["id"],
		DisplayName: data["first_name"] + " " + data["last_name"],
		Username:    strings.ToLower(data["username"]),
		Avatar:      changeAvatarURL(data["photo_url"]),
		Email:       "telegram-auth|" + data["id"] + "@telegram.local",
	}

	return userInfo, nil
}

func (g *TelegramConnector) ConfigFields() []plugin.ConfigField {
	fields := make([]plugin.ConfigField, 0)
	fields = append(fields, createTextInput("name",
		"Name", "", g.Config.Name, true))
	fields = append(fields, createTextInput("bot_id", "BotID", "", g.Config.BotID, true))
	fields = append(fields, createTextInput("bot_token", "BotToken", "", g.Config.BotToken, true))
	fields = append(fields, createTextInput("domain", "Domain", "", g.Config.Domain, true))
	fields = append(fields, createTextInput("logo_svg",
		"Logo SVG", "", g.Config.LogoSVG, false))

	return fields
}

func createTextInput(name, title, desc, value string, require bool) plugin.ConfigField {
	return plugin.ConfigField{
		Name:        name,
		Type:        plugin.ConfigTypeInput,
		Title:       plugin.MakeTranslator(title),
		Description: plugin.MakeTranslator(desc),
		Required:    require,
		UIOptions: plugin.ConfigFieldUIOptions{
			InputType: plugin.InputTypeText,
		},
		Value: value,
	}
}

func (g *TelegramConnector) ConfigReceiver(config []byte) error {
	c := &TelegramConnectorConfig{}
	_ = json.Unmarshal(config, c)
	g.Config = c
	return nil
}

//helper functions

func changeAvatarURL(photoURL string) string {
	if photoURL == "" {
		return "https://balenj.com/uploads/avatar/59pH7TkF2mL.png?s=96"
	}

	return strings.Replace(photoURL, "https://t.me/", "https://balenj.com/timage/", 1)
}

func mapToString(m map[string]string) string {
	var sb strings.Builder

	sb.WriteString("{")
	for key, value := range m {
		sb.WriteString(fmt.Sprintf(`"%s":"%s", `, key, value))
	}
	sb.WriteString("}")

	return sb.String()
}

// id, first_name, last_name, username, photo_url, auth_date and hash
func checkTelegramAuthorization(params map[string]string, token string) bool {

	keyHash := sha256.New()
	keyHash.Write([]byte(token))
	secretkey := keyHash.Sum(nil)

	var checkparams []string
	for k, v := range params {
		if k != "hash" {
			checkparams = append(checkparams, fmt.Sprintf("%s=%s", k, v))
		}
	}
	sort.Strings(checkparams)
	checkString := strings.Join(checkparams, "\n")
	hash := hmac.New(sha256.New, secretkey)
	hash.Write([]byte(checkString))
	hashstr := hex.EncodeToString(hash.Sum(nil))

	authDateUnix := params["auth_date"] // Assuming this is your auth_date

	if !isAuthDateWithinLast5Minutes(authDateUnix) {
		return false
	}
	if hashstr == params["hash"] {
		return true
	}
	return false
}

func parseIntToString(value interface{}) (string, error) {
	switch v := value.(type) {
	case float64:
		intValue := int(v)
		return strconv.Itoa(intValue), nil
	case int:
		return strconv.Itoa(v), nil
	case json.Number:
		intValue, err := v.Int64()
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(intValue, 10), nil
	case string:
		return v, nil // Handle string values by returning them as is
	default:
		return "", fmt.Errorf("unsupported type: %T", value)
	}
}

func unmarshalJSON(data []byte) (map[string]string, error) {
	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for key, value := range rawMap {
		stringValue, err := parseIntToString(value)
		if err != nil {
			return nil, err
		}
		result[key] = stringValue
	}
	return result, nil
}

func isAuthDateWithinLast5Minutes(authDateUnix string) bool {
	authDateUnitInt, err := strconv.Atoi(authDateUnix)
	if err != nil {
		return false
	}
	authDate := time.Unix(int64(authDateUnitInt), 0)
	currentTime := time.Now()

	difference := currentTime.Sub(authDate)
	// Check if the difference is less than or equal to 5 minutes
	return difference <= 5*time.Minute
}
