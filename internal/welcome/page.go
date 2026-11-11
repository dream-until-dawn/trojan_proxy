// Package welcome 生成不含内部服务信息的公共默认页面。
package welcome

import (
	"bytes"
	_ "embed"
	"html/template"
)

//go:embed page.html
var source string
var page = template.Must(template.New("welcome").Parse(source))

// Render 只接受显示名称和公共网页就绪状态；模板自动转义，绝不读取请求Host或内部指标。
func Render(domain string, ready bool) (string, error) {
	var output bytes.Buffer
	err := page.Execute(&output, struct {
		Domain string
		Ready  bool
	}{domain, ready})
	return output.String(), err
}
