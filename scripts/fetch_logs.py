#!/usr/bin/env python3
"""取 Actions job 的原始日志。

## 为什么要单独写

`GET /repos/{o}/{r}/actions/jobs/{id}/logs` 返回的是 **302 到 Azure Blob**
的临时签名地址。urllib 默认会把 `Authorization` 头一起带到重定向后的请求，
而 Azure 收到「GitHub token + 自己的 SAS 签名」会直接回 401：

```
HTTP Error 401: Server failed to authenticate the request.
```

所以必须用自定义的 RedirectHandler 在跳转时**剥掉 Authorization**。

用法：
    GITHUB_TOKEN=xxx python3 scripts/fetch_logs.py            # 最近一次
    GITHUB_TOKEN=xxx python3 scripts/fetch_logs.py <run_id>
    GITHUB_TOKEN=xxx python3 scripts/fetch_logs.py <run_id> --all

默认只打失败 job 的日志尾部；`--all` 打全部 job。
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error

API = 'https://api.github.com'
OWNER = '8686aa'
REPO = 'fffsdfd'


class StripAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """跨域跳转时去掉 Authorization（Azure SAS 地址不需要也不接受它）。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_request = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_request is None:
            return None
        # Request.remove_header 只清掉普通头；这里重建一个干净的
        clean = urllib.request.Request(newurl)
        clean.method = 'GET'
        return clean


def build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(StripAuthOnRedirect)


def api(path: str, opener) -> bytes:
    token = os.environ.get('GITHUB_TOKEN', '').strip()
    if not token:
        raise SystemExit('缺 GITHUB_TOKEN')
    request = urllib.request.Request(API + path)
    request.add_header('Authorization', 'Bearer ' + token)
    request.add_header('Accept', 'application/vnd.github+json')
    request.add_header('X-GitHub-Api-Version', '2022-11-28')
    with opener.open(request, timeout=90) as response:
        return response.read()


def main() -> int:
    opener = build_opener()
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    show_all = '--all' in sys.argv

    if args:
        run_id = args[0]
    else:
        runs = json.loads(api('/repos/%s/%s/actions/runs?per_page=1'
                              % (OWNER, REPO), opener))
        items = runs.get('workflow_runs') or []
        if not items:
            print('没有运行记录')
            return 1
        run_id = str(items[0]['id'])

    run = json.loads(api('/repos/%s/%s/actions/runs/%s' % (OWNER, REPO, run_id),
                         opener))
    print('run %s · %s · %s' % (run_id, run.get('status'), run.get('conclusion')))

    jobs = json.loads(api('/repos/%s/%s/actions/runs/%s/jobs'
                          % (OWNER, REPO, run_id), opener)).get('jobs') or []
    for job in jobs:
        print('\n=== job「%s」 %s / %s ==='
              % (job['name'], job['status'], job.get('conclusion') or '-'))
        for step in job.get('steps') or []:
            mark = 'ok  ' if step.get('conclusion') == 'success' else (
                'FAIL' if step.get('conclusion') == 'failure'
                else (step.get('conclusion') or 'skip'))
            print('  [%s] %s' % (mark, step['name']))

        if job.get('conclusion') != 'failure' and not show_all:
            continue
        try:
            raw = api('/repos/%s/%s/actions/jobs/%d/logs'
                      % (OWNER, REPO, job['id']), opener)
        except Exception as error:
            print('  取日志失败：%s' % error)
            continue
        text = raw.decode('utf-8', 'replace')
        lines = text.splitlines()
        if show_all:
            print('--- 完整日志（尾部 200 行）---')
            for line in lines[-200:]:
                print(line)
            continue
        # 只挑错误行，避免几千行噪音。
        # 日志行形如 `2026-10-24T10:20:11.1234567Z error: ...`，整行保留便于定位。
        keys = ('error:', 'error ', 'Error:', 'fatal', 'FAILED', 'failed',
                'undefined', 'cannot find', 'not found', '失败')
        picked = [line for line in lines if any(k in line for k in keys)]
        print('--- 错误行（最多 70 条）---')
        for line in (picked[-70:] if picked else lines[-50:]):
            print(line)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
