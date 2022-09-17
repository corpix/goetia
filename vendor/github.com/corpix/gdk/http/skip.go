package http

type SkipConfig struct {
	SkipPaths map[string]struct{} `yaml:"skip-paths"`
}

func (c *SkipConfig) Default() {
	if c.SkipPaths == nil {
		c.SkipPaths = map[string]struct{}{}
	}
}

func Skip(c *SkipConfig, r *Request) bool {
	if c == nil {
		return false
	}

	if _, ok := c.SkipPaths[r.URL.Path]; ok {
		return true
	}

	return false
}
