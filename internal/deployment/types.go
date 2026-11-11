// Package deployment 准备专用卷与安全启动快照，不操作Docker socket或其他进程。
package deployment

// Paths 全部来自部署，不接受后台请求；公开目录始终由宿主机显式只读挂载。
type Paths struct{ Data, GatewayRun, VPNRun, Certificates, CaddyData string }

func Defaults(data string) Paths {
	return Paths{Data: data, GatewayRun: "/run/caddy", VPNRun: "/run/vpn", Certificates: "/certificates", CaddyData: "/caddy-data"}
}
