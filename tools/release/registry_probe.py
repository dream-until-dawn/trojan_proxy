"""不读取本机Docker凭据，匿名验证三个候选镜像及提交标签，输出固定清单。"""
import argparse
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--commit', required=True)
args = parser.parse_args()
if not re.fullmatch('[0-9a-f]{40}', args.commit):
    parser.error('必须提供完整提交SHA')
registry = 'https://ghcr.io'
report = {'passed': False, 'anonymous': True, 'commit': args.commit, 'images': {}}


def read(url, headers=None, limit=2 << 20):
    request = urllib.request.Request(url, headers=dict({'User-Agent': 'trojan-proxy-release-check'}, **(headers or {})))
    with urllib.request.urlopen(request, timeout=25) as response:
        body = response.read(limit + 1)
        if len(body) > limit:
            raise RuntimeError('镜像元数据超过预算')
        return body, response.headers


try:
    for role in ['control', 'runner', 'gateway']:
        repository = 'dream-until-dawn/trojan-proxy-' + role
        query = urllib.parse.urlencode({'service': 'ghcr.io', 'scope': 'repository:' + repository + ':pull'})
        body, _ = read(registry + '/token?' + query)
        # 匿名pull令牌仅存内存；绝不读取或打印所有者PAT/GITHUB_TOKEN。
        token = json.loads(body)['token']
        authorization = {'Authorization': 'Bearer ' + token}
        headers = dict(authorization, Accept='application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json')
        body, metadata = read(registry + '/v2/' + repository + '/manifests/sha-' + args.commit, headers)
        digest = 'sha256:' + hashlib.sha256(body).hexdigest()
        if metadata.get('Docker-Content-Digest') != digest:
            raise RuntimeError('镜像清单摘要不匹配')
        manifest = json.loads(body)
        config_digest = manifest['config']['digest']
        body, _ = read(registry + '/v2/' + repository + '/blobs/' + config_digest, authorization)
        if 'sha256:' + hashlib.sha256(body).hexdigest() != config_digest:
            raise RuntimeError('镜像配置摘要不匹配')
        config = json.loads(body)
        if config['config']['Labels']['org.opencontainers.image.revision'] != args.commit:
            raise RuntimeError('匿名镜像不属于指定源码提交')
        if config['os'] != 'linux' or config['architecture'] != 'amd64':
            raise RuntimeError('候选镜像平台不符合当前交付范围')
        report['images'][role] = {'reference': 'ghcr.io/' + repository + '@' + digest,
                                  'manifest_digest': digest, 'config_digest': config_digest,
                                  'platform': 'linux/amd64'}
    report['passed'] = True
except urllib.error.HTTPError as error:
    report['error'] = '匿名注册表请求失败，HTTP ' + str(error.code)
except Exception as error:
    report['error'] = type(error).__name__ + ': ' + str(error)[:180]
print(json.dumps(report, ensure_ascii=False, indent=2))
raise SystemExit(0 if report['passed'] else 1)
