package proxy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/reflect"
)

type (
	RuleConfig struct {
		Type string `yaml:"type"`
		Key  string `yaml:"key"`
		Expr string `yaml:"expr"`
	}
	Rule interface {
		String() string
		Match(interface{}) bool
	}
	RuleType   string
	RuleRegexp struct {
		Config *RuleConfig
		Regexp *regexp.Regexp
	}
)

const (
	RuleTypeRegexp RuleType = "regexp"
)

var (
	RuleTypes = map[RuleType]struct{}{
		RuleTypeRegexp: {},
	}

	_ Rule = new(RuleRegexp)
)

func (c *RuleConfig) String() string {
	argsFmt := "%q"
	args := []interface{}{c.Type, c.Expr}
	if c.Key != "" {
		argsFmt = "%q, %s"
		args = append(args, c.Key)
	}
	return fmt.Sprintf("%s("+argsFmt+")", args...)
}

func (c *RuleConfig) Validate() error {
	if c.Type == "" {
		return errors.New("type should not be empty")
	}
	_, exists := RuleTypes[RuleType(strings.ToLower(c.Type))]
	if !exists {
		return errors.Errorf("unsupported rule type: %q", c.Type)
	}
	return nil
}

//

func (r *RuleRegexp) String() string {
	return r.Config.String()
}

func (r *RuleRegexp) Match(v interface{}) bool {
	if r.Config.Key != "" {
		v = RuleKey(r.Config.Key, v)
	}
	return r.Regexp.MatchString(fmt.Sprintf("%s", v))
}

func NewRuleRegexp(c *RuleConfig) *RuleRegexp {
	return &RuleRegexp{
		Config: c,
		Regexp: regexp.MustCompile(c.Expr),
	}
}

//

func RuleKey(key string, v interface{}) interface{} {
	rv := reflect.IndirectValue(reflect.ValueOf(v))
	switch rv.Kind() {
	case reflect.Struct:
		v = rv.FieldByName(key).Interface()
	case reflect.Map:
		v = rv.MapIndex(reflect.ValueOf(key)).Interface()
	case reflect.Slice:
		n, err := strconv.Atoi(key)
		if err != nil {
			panic(err)
		}
		v = rv.Index(n).Interface()
	default:
		panic(fmt.Sprintf(
			"can not index value of type %q with key %q",
			rv.Type(), key,
		))
	}
	return v
}

func RulesMatch(v interface{}, rules ...Rule) error {
	for _, rule := range rules {
		if !rule.Match(v) {
			return errors.Errorf("failed to match rule %s on value %+v", rule.String(), v)
		}
	}
	return nil
}

//

func NewRule(c *RuleConfig) Rule {
	switch RuleType(strings.ToLower(c.Type)) {
	case RuleTypeRegexp:
		return NewRuleRegexp(c)
	default:
		panic(fmt.Sprintf("unsupported rule type: %q", c.Type))
	}
}

func NewRules(c []*RuleConfig) []Rule {
	rs := make([]Rule, len(c))
	for n, rc := range c {
		rs[n] = NewRule(rc)
	}
	return rs
}
