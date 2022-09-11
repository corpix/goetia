package proxy

import (
	"io/ioutil"
	"time"

	"github.com/davecgh/go-spew/spew"
	lru "github.com/go-pkgz/expirable-cache/v2"
	tg "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/corpix/gdk/crypto"
	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/template"
)

type (
	ConnectorTelegramConfig struct {
		*ConnectorConfig     `yaml:",inline,omitempty"`
		BotToken             string              `yaml:"bot-token"`
		BotTokenFile         string              `yaml:"bot-token-file"`
		Token                *crypto.TokenConfig `yaml:"token"`
		Groups               []int64             `yaml:"groups"`
		ApproveTimeout       time.Duration       `yaml:"approve-timeout"`
		ApproveTransitionTTL time.Duration       `yaml:"approve-transition-ttl"`

		botToken string
	}
	ConnectorTelegramCache lru.Cache[string, *tg.User]
	ConnectorTelegram      struct {
		Config *ConnectorTelegramConfig
		Api    *tg.BotAPI
		Cache  ConnectorTelegramCache
	}
)

func (c *ConnectorTelegramConfig) Default() {
	if c.ConnectorConfig == nil {
		c.ConnectorConfig = &ConnectorConfig{}
	}

	if c.Name == "" {
		c.Name = string(ConnectorNameTelegram)
	}
	if c.Label == "" {
		c.Label = "Telegram"
	}
	if c.Description == "" {
		c.Description = "HTTP Telegram Auth"
	}

	if c.ApproveTimeout == 0 {
		c.ApproveTimeout = 5 * time.Minute
	}
	if c.ApproveTransitionTTL == 0 {
		c.ApproveTransitionTTL = 30 * time.Second
	}
}

func (c *ConnectorTelegramConfig) Validate() error {
	if len(c.Groups) == 0 {
		return errors.New("no groups defined")
	}
	if c.BotToken != "" && c.BotTokenFile != "" {
		return errors.New("either bot-token or bot-token-file should be defined, not both")
	}
	if c.BotToken == "" && c.BotTokenFile == "" {
		return errors.New("either bot-token or bot-token-file should be defined")
	}
	return nil
}

func (c *ConnectorTelegramConfig) Expand() error {
	if c.BotTokenFile != "" {
		token, err := ioutil.ReadFile(c.BotTokenFile)
		if err != nil {
			return err
		}
		c.botToken = string(token)
	} else {
		c.botToken = c.BotToken
	}
	return nil
}

//

func (c *ConnectorTelegram) Name() string        { return c.Config.Name }
func (c *ConnectorTelegram) Label() string       { return c.Config.Label }
func (c *ConnectorTelegram) Description() string { return c.Config.Description }

func (c *ConnectorTelegram) Worker() {
	config := tg.NewUpdate(0)
	config.Timeout = 30

	for update := range c.Api.GetUpdatesChan(config) {
	groupsLoop:
		for _, g := range c.Config.Groups {
			m, err := c.Api.GetChatMember(tg.GetChatMemberConfig{
				ChatConfigWithUser: tg.ChatConfigWithUser{
					ChatID: g,
					UserID: update.SentFrom().ID,
				},
			})
			if err == nil {
				c.Cache.Set("xxxx", m.User, c.Config.ApproveTransitionTTL)
				spew.Dump(c.Cache)
				break groupsLoop
			}
		}
	}
}

func (c *ConnectorTelegram) Mount(router *http.Router) {
	di.MustInvoke(di.Default, func(
		t *template.Template,
		profileRules UserProfileRules,
		paths Paths,
	) {
		var (
			bot tg.User
			err error
		)

		bot, err = c.Api.GetMe()
		if err != nil {
			panic(err)
		}

		go c.Worker()

		router.
			HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				TemplateResponse(
					t.Lookup(string(TemplateNameTelegram)),
					http.
						NewTemplateContext(r).
						With(TemplateContextKeyTelegram, map[string]interface{}{
							"bot":   bot,
							"token": "xxxx",
						}),
					w,
				)
			}).
			Methods(http.MethodPost)
	})
}

func NewConnectorTelegram(c *ConnectorTelegramConfig) *ConnectorTelegram {
	api, err := tg.NewBotAPI(c.botToken)
	if err != nil {
		panic(err)
	}

	connector := &ConnectorTelegram{
		Config: c,
		Api:    api,
		Cache:  lru.NewCache[string, *tg.User](),
	}
	return connector
}
