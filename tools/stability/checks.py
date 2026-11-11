"""长稳判定的纯逻辑；缺字段、错误正向或失效反向均不能视作通过。"""
SERVICE_ROLES = {'control': 'control', 'vpn-runner': 'runner', 'admin-gateway': 'gateway'}


class CheckFailure(RuntimeError):
    pass


def validate_containers(containers, images, baseline=None):
    """固定镜像及进程基线；主动替换或意外重启都使这一轮稳定窗口失效。"""
    current = {}
    for container in containers:
        service = container['Config'].get('Labels', {}).get('com.docker.compose.service')
        if service not in SERVICE_ROLES:
            continue
        if service in current:
            raise CheckFailure('duplicate_service')
        state = container['State']
        if not state.get('Running') or state.get('OOMKilled') or state.get('Error'):
            raise CheckFailure('container_not_healthy')
        if container['Image'] != images[SERVICE_ROLES[service]]['config_digest']:
            raise CheckFailure('unexpected_image')
        health = state.get('Health', {}).get('Status')
        if health and health != 'healthy' and not (baseline is None and health == 'starting'):
            raise CheckFailure('docker_health_not_ready')
        current[service] = {'id': container['Id'], 'started': state['StartedAt'], 'restarts': container['RestartCount']}
    if set(current) != set(SERVICE_ROLES):
        raise CheckFailure('missing_service')
    if baseline is not None and current != baseline:
        raise CheckFailure('unexpected_restart_or_recreation')
    return current


def validate_vpn(result):
    """必须同时证明可信HTTPS确实可达、错误口令确实不可用。"""
    checks = result.get('checks', {})
    positive = checks.get('trojan_google_https', {})
    negative = checks.get('wrong_password', {})
    if positive.get('status_line') != 'HTTP/1.1 204 No Content' or positive.get('inner_tls_verified') is not True:
        raise CheckFailure('vpn_positive_failed')
    if negative.get('rejected') is not True:
        raise CheckFailure('vpn_negative_failed')


def completed_pass(duration, elapsed, failures, deep_checks, completed):
    """真实时长、全部样本及逐小时正反向缺一不可，提前退出不能写成成功。"""
    required = max(2, int(duration // 3600) + 1)
    return bool(completed and elapsed >= duration and failures == 0 and deep_checks >= required)
