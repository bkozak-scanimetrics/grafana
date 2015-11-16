package api

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
	"io/ioutil"
	"bytes"
	"encoding/json"
	"strings"
	"fmt"

	"github.com/grafana/grafana/pkg/log"
	"github.com/grafana/grafana/pkg/api/cloudwatch"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/metrics"
	"github.com/grafana/grafana/pkg/middleware"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
)

var dataProxyTransport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	Proxy:           http.ProxyFromEnvironment,
	Dial: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial,
	TLSHandshakeTimeout: 10 * time.Second,
}

func NewReverseProxy(ds *m.DataSource, proxyPath string, targetUrl *url.URL) *httputil.ReverseProxy {
	director := func(req *http.Request) {
		req.URL.Scheme = targetUrl.Scheme
		req.URL.Host = targetUrl.Host
		req.Host = targetUrl.Host

		reqQueryVals := req.URL.Query()

		if ds.Type == m.DS_INFLUXDB_08 {
			req.URL.Path = util.JoinUrlFragments(targetUrl.Path, "db/"+ds.Database+"/"+proxyPath)
			reqQueryVals.Add("u", ds.User)
			reqQueryVals.Add("p", ds.Password)
			req.URL.RawQuery = reqQueryVals.Encode()
		} else if ds.Type == m.DS_INFLUXDB {
			req.URL.Path = util.JoinUrlFragments(targetUrl.Path, proxyPath)
			req.URL.RawQuery = reqQueryVals.Encode()
			if !ds.BasicAuth {
				req.Header.Del("Authorization")
				req.Header.Add("Authorization", util.GetBasicAuthHeader(ds.User, ds.Password))
			}
		} else {
			req.URL.Path = util.JoinUrlFragments(targetUrl.Path, proxyPath)
		}

		if ds.BasicAuth {
			req.Header.Del("Authorization")
			req.Header.Add("Authorization", util.GetBasicAuthHeader(ds.BasicAuthUser, ds.BasicAuthPassword))
		}

		dsAuth := req.Header.Get("X-DS-Authorization")
		if len(dsAuth) > 0 {
			req.Header.Del("X-DS-Authorization")
			req.Header.Del("Authorization")
			req.Header.Add("Authorization", dsAuth)
		}

		// clear cookie headers
		req.Header.Del("Cookie")
		req.Header.Del("Set-Cookie")
	}

	return &httputil.ReverseProxy{Director: director, FlushInterval: time.Millisecond * 200}
}

func getDatasource(id int64, orgId int64) (*m.DataSource, error) {
	query := m.GetDataSourceByIdQuery{Id: id, OrgId: orgId}
	if err := bus.Dispatch(&query); err != nil {
		return nil, err
	}

	return &query.Result, nil
}

func ProxyDataSourceRequest(c *middleware.Context) {
	c.TimeRequest(metrics.M_DataSource_ProxyReq_Timer)

	ds, err := getDatasource(c.ParamsInt64(":id"), c.OrgId)

	if err != nil {
		c.JsonApiErr(500, "Unable to load datasource meta data", err)
		return
	}

	targetUrl, _ := url.Parse(ds.Url)
	if len(setting.DataProxyWhiteList) > 0 {
		if _, exists := setting.DataProxyWhiteList[targetUrl.Host]; !exists {
			c.JsonApiErr(403, "Data proxy hostname and ip are not included in whitelist", nil)
			return
		}
	}

	if ds.Type == m.DS_CLOUDWATCH {
		cloudwatch.HandleRequest(c, ds)
	} else {
		proxyPath := c.Params("*")
		proxy := NewReverseProxy(ds, proxyPath, targetUrl)
		proxy.Transport = dataProxyTransport

		contents, err := ioutil.ReadAll(c.Req.Request.Body)

		if err != nil || len(contents) == 0 {
			c.Req.Request.ParseForm()
			form_values := c.Req.Request.Form
			if contents, ok := form_values["q"]; ok {
				log.Info("Metadata Query: %#v",contents)
			}else{
				c.JsonApiErr(500, "Unable to verify authorization", err)
				return
			}
		}else{
			c.Req.Request.Body = ioutil.NopCloser(bytes.NewReader(contents))

			var v util.DynMap
			err = json.Unmarshal(contents, &v)
			if err != nil {
				log.Info("Body: %s",contents)
				c.JsonApiErr(500, "Unable to verify authorization", err)
				return
			}

			for _,element := range v["queries"].([]interface{}) {
				m := element.(map[string]interface {})
				org_matches := strings.HasPrefix(m["metric"].(string),fmt.Sprintf("P%d.",c.SignedInUser.OrgId))
				super_admin := c.SignedInUser.Login == setting.AdminUser
				if !org_matches && !super_admin {
					log.Info("Query: %+v",m)
					log.Info("metric: %+v",m["metric"])
					log.Info("org: %s",fmt.Sprintf("P%d.",c.SignedInUser.OrgId))
					log.Info("admin: %s",fmt.Sprintf("P%d.",setting.AdminUser))
					log.Info("login: %s",fmt.Sprintf("P%d.",c.SignedInUser.Login))
					c.JsonApiErr(403, "Unauthorized Query", err)
					return
				}
			}
		}

		proxy.ServeHTTP(c.Resp, c.Req.Request)
		c.Resp.Header().Del("Set-Cookie")
	}
}
