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

package exporter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"cwkwan/json_exporter/config"
	"cwkwan/json_exporter/spnego_mixin"
)

func MakeMetricName(parts ...string) string {
	return strings.Join(parts, "_")
}

func SanitizeIntValue(s string) (int64, error) {
	var err error
	var value int64
	var resultErr string

	if value, err = strconv.ParseInt(s, 10, 64); err == nil {
		return value, nil
	}
	resultErr = fmt.Sprintf("%s", err)

	return value, fmt.Errorf(resultErr)
}

func SanitizeValue(s string) (float64, error) {
	var err error
	var value float64
	var resultErr string

	if value, err = strconv.ParseFloat(s, 64); err == nil {
		return value, nil
	}
	resultErr = fmt.Sprintf("%s", err)

	if boolValue, err := strconv.ParseBool(s); err == nil {
		if boolValue {
			return 1.0, nil
		}
		return 0.0, nil
	}
	resultErr = resultErr + "; " + fmt.Sprintf("%s", err)

	if s == "<nil>" {
		return math.NaN(), nil
	}
	return value, fmt.Errorf(resultErr)
}

func CreateMetricsList(c config.Module) ([]JSONMetric, error) {
	var (
		metrics   []JSONMetric
		valueType prometheus.ValueType
	)
	for _, metric := range c.Metrics {
		switch metric.ValueType {
		case config.ValueTypeGauge:
			valueType = prometheus.GaugeValue
		case config.ValueTypeCounter:
			valueType = prometheus.CounterValue
		default:
			valueType = prometheus.UntypedValue
		}
		switch metric.Type {
		case config.ValueScrape:
			var variableLabels, variableLabelsValues []string
			for k, v := range metric.Labels {
				variableLabels = append(variableLabels, k)
				variableLabelsValues = append(variableLabelsValues, v)
			}
			jsonMetric := JSONMetric{
				Type: config.ValueScrape,
				Desc: prometheus.NewDesc(
					metric.Name,
					metric.Help,
					variableLabels,
					nil,
				),
				KeyJSONPath:            metric.Path,
				LabelsJSONPaths:        variableLabelsValues,
				JqTransform:            metric.Transform.Jq,
				ValueType:              valueType,
				RegexpExtracts:         metric.RegexpExtracts,
				EpochTimestampJSONPath: metric.EpochTimestamp,
			}
			metrics = append(metrics, jsonMetric)
		case config.ObjectScrape:
			for subName, values := range metric.Values {
				name := MakeMetricName(metric.Name, subName)
				var variableLabels, variableLabelsValues []string
				for k, v := range metric.Labels {
					variableLabels = append(variableLabels, k)
					variableLabelsValues = append(variableLabelsValues, v)
				}
				for _, value := range values {
					jsonMetric := JSONMetric{
						Type: config.ObjectScrape,
						Desc: prometheus.NewDesc(
							name,
							value.Help,
							variableLabels,
							nil,
						),
						KeyJSONPath:            metric.Path,
						ValueJSONPath:          value.Value,
						LabelsJSONPaths:        variableLabelsValues,
						JqTransform:            metric.Transform.Jq,
						ValueType:              valueType,
						RegexpExtracts:         value.RegexpExtracts,
						EpochTimestampJSONPath: metric.EpochTimestamp,
					}
					metrics = append(metrics, jsonMetric)
				}
			}
		default:
			return nil, fmt.Errorf("Unknown metric type: '%s', for metric: '%s'", metric.Type, metric.Name)
		}
	}
	return metrics, nil
}

type JSONFetcher struct {
	module config.Module
	url    string
	ctx    context.Context
	logger log.Logger
	method string
	body   io.Reader
}

func NewJSONFetcher(ctx context.Context, logger log.Logger, m config.Module, tplValues url.Values) *JSONFetcher {
	method, body := renderBody(logger, m.Body, tplValues)
	url := renderUrl(logger, m.Url, tplValues)
	return &JSONFetcher{
		module: m,
		url:    url,
		ctx:    ctx,
		logger: logger,
		method: method,
		body:   body,
	}
}

func (f *JSONFetcher) FetchJSON(moduleMetric *spnego_mixin.ExporterMetric, endpoint string, clientip string) ([]byte, error) {
	httpClientConfig := f.module.HTTPClientConfig
	client, err := spnego_mixin.NewClient(httpClientConfig, "json_exporter", moduleMetric, f.logger)
	if err != nil {
		level.Error(f.logger).Log("msg", "Error generating HTTP client", "err", err)
		return nil, err
	}

	var req *http.Request
	req, err = http.NewRequest(f.method, f.url, f.body)
	req = req.WithContext(f.ctx)
	if err != nil {
		level.Error(f.logger).Log("msg", "Failed to create request", "err", err)
		return nil, err
	}
	req.Header.Add("User-Agent", "esp prometheus json exporter/1.0")
	req.Header.Add("X-Forwarded-For", GetOutboundIP().String())

	for key, value := range f.module.Headers {
		if strings.HasPrefix(key, "Authorization") && strings.HasPrefix(value, "`") {
			fields := strings.Fields(strings.Trim(value, "`"))
			out, err := exec.Command("/bin/bash", "-c", "/bin/vault tell "+fields[1]+" "+fields[2]).Output()
			if err != nil {
				level.Error(f.logger).Log("msg", "Failed getting secret from vault", "vault namespace", fields[1], "vault key", fields[2], "err", err)
				return nil, err
			}
			req.Header.Add(key, string(out))
		} else {
			req.Header.Add(key, value)
		}
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Add("Accept", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			level.Error(f.logger).Log("msg", "Failed to discard body", "err", err)
		}
		resp.Body.Close()
	}()

	if len(f.module.ValidStatusCodes) != 0 {
		success := false
		for _, code := range f.module.ValidStatusCodes {
			if resp.StatusCode == code {
				success = true
				break
			}
		}
		if !success {
			return nil, errors.New("http response: " + resp.Status)
		}
	} else if resp.StatusCode/100 != 2 {
		return nil, errors.New("http response: " + resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Use the configured template to render the body if enabled
// Do not treat template errors as fatal, on such errors just log them
// and continue with static body content
func renderBody(logger log.Logger, body config.Body, tplValues url.Values) (method string, br io.Reader) {
	method = "POST"
	if body.Content == "" {
		return "GET", nil
	}
	br = strings.NewReader(body.Content)
	if body.Templatize {
		tpl, err := template.New("base").Funcs(sprig.TxtFuncMap()).Parse(body.Content)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to create a new template from body content", "err", err, "content", body.Content)
			return
		}
		tpl = tpl.Option("missingkey=zero")
		var b strings.Builder
		if err := tpl.Execute(&b, tplValues); err != nil {
			level.Error(logger).Log("msg", "Failed to render template with values", "err", err, "tempalte", body.Content)

			// `tplValues` can contain sensitive values, so log it only when in debug mode
			level.Debug(logger).Log("msg", "Failed to render template with values", "err", err, "tempalte", body.Content, "values", tplValues, "rendered_body", b.String())
			return
		}
		br = strings.NewReader(b.String())
	}
	return
}

func renderUrl(logger log.Logger, url_template string, tplValues url.Values) (url string) {
	tpl, err := template.New("base").Funcs(sprig.TxtFuncMap()).Parse(url_template)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to parse target url", "err", err, "url", url_template)
		return
	}
	tpl = tpl.Option("missingkey=zero")
	var b strings.Builder
	if err := tpl.Execute(&b, tplValues); err != nil {
		level.Error(logger).Log("msg", "Failed to render url with values", "err", err, "url", url_template)

		// `tplValues` can contain sensitive values, so log it only when in debug mode
		level.Debug(logger).Log("msg", "Failed to render url with values", "err", err, "tempalte", url_template, "values", tplValues, "rendered_url", b.String())
		return
	}
	url = b.String()

	return url
}

// Get preferred outbound ip of this machine
func GetOutboundIP() net.IP {
	conn, _ := net.Dial("udp", "10.2.3.4:123")

	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

