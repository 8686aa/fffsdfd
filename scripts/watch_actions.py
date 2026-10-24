#!/usr/bin/env python3
"""盯着 GitHub Actions 的一次运行，直到结束或超时。

    GITHUB_TOKEN=xxx python3 scripts/watch_actions.py [run_id]

结束（成功/失败/取消）后打印每个 job 的结论，失败时把出错日志尾部抓回来 ——
省得再去网页翻。本环境 github.com 不可达，但 api.github.com 正常，
所以全程走 REST。
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

API = 'https://api.github.com'
OWNER = '8686aa'
REPO = 'fffsdfd'
TIMEOUT_SECONDS = 40 * 60


def call(path: str, raw_text: bool = False):
    token = os.environ.get('GITHUB_TOKEN', '').strip()
    if not token:
        print('缺 GITHUB_TOKEN', file=sys.stderr)
        raise SystemExit(2)
    request = urllib.request.Request(API + path)
    request.add_header('Authorization', 'Bearer ' + token)
    request.add_header('Accept', 'application/vnd.github+json')
    request.add_header('X-GitHub-Api-Version', '2022-11-28')
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                body = response.read().decode('utf-8', 'replace')
                return body if raw_text else json.loads(body or '{}')
        except urllib.error.HTTPError as error:
            detail = error.read().decode('utf-8', 'replace')
            if error.code in (404, 403):
                return {'__status__': error.code, '__body__': detail}
            if attempt == 3:
                raise RuntimeError('HTTP %d %s' % (error.code, detail[:200]))
        except Exception as error:
            if attempt == 3:
                raise RuntimeError('%s: %s' % (type(error).__name__, error))
        time.sleep(2 * (attempt + 1))
    return {}


def latest_run_id() -> str:
    data = call('/repos/%s/%s/actions/runs?per_page=1' % (OWNER, REPO))
    runs = data.get('workflow_runs') or []
    if not runs:
        raise SystemExit('没有找到任何运行')
    return str(runs[0]['id'])


def jobs_of(run_id: str) -> list[dict]:
    data = call('/repos/%s/%s/actions/runs/%s/jobs' % (OWNER, REPO, run_id))
    return data.get('jobs') or []


def step_logs(run_id: str, job_id: int) -> str:
    """抓某个 job 的原始日志（重定向到 S3，需要跟随跳转）。"""
    token = os.environ['GITHUB_TOKEN']
    url = '%s/repos/%s/%s/actions/jobs/%d/logs' % (API, OWNER, REPO, job_id)
    request = urllib.request.Request(url)
    request.add_header('Authorization', 'Bearer ' + token)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read().decode('utf-8', 'replace')
    except Exception as error:
        return '(取日志失败: %s)' % error


def main() -> int:
    run_id = sys.argv[1] if len(sys.argv) > 1 else latest_run_id()
    print('监视 run %s' % run_id)
    print('https://github.com/%s/%s/actions/runs/%s' % (OWNER, REPO, run_id))

    started = time.time()
    last_line = ''
    while True:
        data = call('/repos/%s/%s/actions/runs/%s' % (OWNER, REPO, run_id))
        status = data.get('status', '?')
        conclusion = data.get('conclusion')
        line = '状态 %s%s' % (status, '' if not conclusion else ' / %s' % conclusion)
        if line != last_line:
            print('[%4ds] %s' % (time.time() - started, line), flush=True)
            last_line = line
        if status == 'completed':
            break
        if time.time() - started > TIMEOUT_SECONDS:
            print('超时（%d 秒）仍未结束' % TIMEOUT_SECONDS)
            return 3
        time.sleep(10)

    print()
    print('=== 各 job 结论 ===')
    failed: list[dict] = []
    for job in jobs_of(run_id):
        print('  %-22s %-10s %s' % (job['name'], job['status'],
                                    job.get('conclusion') or '-'))
        for step in job.get('steps') or []:
            mark = 'ok  ' if step.get('conclusion') == 'success' else (
                'FAIL' if step.get('conclusion') == 'failure' else
                step.get('conclusion') or 'skip')
            print('      [%s] %s' % (mark, step['name']))
        if job.get('conclusion') == 'failure':
            failed.append(job)

    for job in failed:
        print()
        print('=== 失败 job「%s」日志尾部 ===' % job['name'])
        text = step_logs(run_id, int(job['id']))
        lines = text.splitlines()
        # 只挑像错误的行，避免几千行日志。
        # ⚠️ 不能用 shell 的 grep 过滤：日志里有 `00:01:23 ##[error]...` 前缀，
        # 这里直接在 Python 里筛，整行输出便于定位。
        keys = ('error', 'Error', 'ERROR', 'fatal', 'Failed', 'failed',
                '失败', 'error:', 'cannot find', 'not found')
        picked = [line for line in lines if any(k in line for k in keys)]
        for line in (picked[-60:] if picked else lines[-40:]):
            print(line)

    print()
    verdict = data.get('conclusion')
    if verdict == 'success':
        print('=== 成功。产物：Actions 页面底部 Artifacts → StarRadar-unsigned-ipa ===')
        return 0
    print('=== 结束，结论：%s ===' % verdict)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
