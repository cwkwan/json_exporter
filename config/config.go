// Copyright 2020 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"errors"
	"os"
	"regexp"

	pconfig "github.com/prometheus/common/config"
	"gopkg.in/yaml.v2"
)

var (
	DefaultRegexpExtract = RegexpExtract{
		Value: "$1",
	}
)

// Metric contains values that define a metric
type Metric struct {
	Name           string
	Path           string
	Labels         map[string]string
	Transform      Transform
	Type           ScrapeType
	ValueType      ValueType
	RegexpExtracts []RegexpExtract `yaml:"regex_extracts,omitempty"`
	EpochTimestamp string
	Help           string
	Values         map[string][]Values
}

type Transform struct {
	Jq string
}

type RegexpExtract struct {
	Value string `yaml:"value"`
	Regex Regexp `yaml:"regex"`
}

type Values struct {
	Help           string
	Value          string
	RegexpExtracts []RegexpExtract `yaml:"regex_extracts,omitempty"`
}

// Regexp encapsulates a regexp.Regexp and makes it YAML marshalable.
type Regexp struct {
	*regexp.Regexp
}

type ScrapeType string

const (
	ValueScrape  ScrapeType = "value" // default
	ObjectScrape ScrapeType = "object"
)

type ValueType string

const (
	ValueTypeGauge   ValueType = "gauge"
	ValueTypeCounter ValueType = "counter"
	ValueTypeUntyped ValueType = "untyped"
)

// Config contains multiple modules.
type Config struct {
	Modules map[string]Module `yaml:"modules"`
}

// Module contains metrics and headers defining a configuration
type Module struct {
	Headers          map[string]string `yaml:"headers,omitempty"`
	Url              string
	Metrics          []Metric                 `yaml:"metrics"`
	HTTPClientConfig pconfig.HTTPClientConfig `yaml:"http_client_config,omitempty"`
	Body             Body                     `yaml:"body,omitempty"`
	ValidStatusCodes []int                    `yaml:"valid_status_codes,omitempty"`
}

type Body struct {
	Content    string `yaml:"content"`
	Templatize bool   `yaml:"templatize,omitempty"`
}

func (c *RegexpExtract) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultRegexpExtract
	type plain RegexpExtract
	return unmarshal((*plain)(c))
}

func (re *Regexp) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	regex, err := regexp.Compile("^(?:" + s + ")$")
	if err != nil {
		return err
	}
	re.Regexp = regex
	return nil
}

func LoadConfig(configPath string) (Config, error) {
	var config Config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, err
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, err
	}

	// Complete Defaults
	for _, module := range config.Modules {
		if module.Url == "" {
			return config, errors.New("module URL not set")
		}
		for i := 0; i < len(module.Metrics); i++ {
			if module.Metrics[i].Type == "" {
				module.Metrics[i].Type = ValueScrape
			}
			if module.Metrics[i].Help == "" {
				module.Metrics[i].Help = module.Metrics[i].Name
			}
			if module.Metrics[i].ValueType == "" {
				module.Metrics[i].ValueType = ValueTypeUntyped
			}
			for _, regexpextract := range module.Metrics[i].RegexpExtracts {
				if regexpextract.Value == "" {
					regexpextract.Value = "$1"
				}
			}
			for _, values := range module.Metrics[i].Values {
				for _, value := range values {
					for _, regexpextract := range value.RegexpExtracts {
						if regexpextract.Value == "" {
							regexpextract.Value = "$1"
						}
					}
				}
			}
		}
	}
	return config, nil
}

