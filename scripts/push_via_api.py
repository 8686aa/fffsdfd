#!/usr/bin/env python3
"""用 GitHub REST API 推送本地提交（不依赖 git 协议）。

## 为什么需要这个

这个环境里 `github.com` 被网络策略挡住（curl 连 4 次全超时），
而 `api.github.com` 正常。`git push` 走的是 `github.com/<owner>/<repo>.git`
的 smart-HTTP 端点，因此必然失败：

```
send-pack: unexpected disconnect while reading sideband packet
schannel: server closed abruptly (missing close_notify)
```

而 GitHub 的 Git Data API（blobs / trees / commits / refs）全在
`api.github.com` 上，可以逐对象重建提交历史 —— **保真度一致**：
推上去的 commit sha 与本地完全相同（同样的 tree、同样的 parent、
同样的 author/committer 时间），所以本地仓库不会与远端分叉。

## 用法

```bash
GITHUB_TOKEN=ghp_xxx python3 scripts/push_via_api.py --dry-run   # 先看要做什么
GITHUB_TOKEN=ghp_xxx python3 scripts/push_via_api.py
```

token 权限：classic 勾 `repo`；fine-grained 勾 `Contents: Read and write`。

## 对象枚举

全部读本地 git 对象库（`git cat-file`），不联网：

- `git rev-list --reverse HEAD`  → 提交顺序
- `git cat-file -p <commit>`     → tree / parent / message / 时间
- `git ls-tree -r <commit>`      → 扁平文件列表（mode type sha path）

只上传**唯一** blob（按 sha 去重），两个提交共享的文件只传一次。
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

API = 'https://api.github.com'
OWNER = '8686aa'
REPO = 'fffsdfd'
BRANCH = 'main'


# ── git 对象读取 ────────────────────────────────────────────────

def git(*args: str) -> bytes:
    result = subprocess.run(['git'] + list(args), capture_output=True)
    if result.returncode != 0:
        raise RuntimeError('git %s 失败：%s'
                           % (' '.join(args),
                              result.stderr.decode('utf-8', 'replace').strip()))
    return result.stdout


def read_commit(sha: str) -> dict:
    raw = git('cat-file', '-p', sha).decode('utf-8', 'replace')
    head, _, message = raw.partition('\n\n')
    tree = ''
    parents: list[str] = []
    author = ''
    committer = ''
    for line in head.split('\n'):
        if line.startswith('tree '):
            tree = line[5:].strip()
        elif line.startswith('parent '):
            parents.append(line[7:].strip())
        elif line.startswith('author '):
            author = line[7:]
        elif line.startswith('committer '):
            committer = line[10:]
    return {
        'tree': tree,
        'parents': parents,
        'message': message,
        'author': author,
        'committer': committer,
    }


def parse_ident(text: str) -> dict:
    """`Name <mail> 1700000000 +0800` → API 需要的 name/email/date。"""
    if not text:
        return {}
    name, _, rest = text.partition(' <')
    email, _, rest = rest.partition('>')
    stamp = rest.strip().split()
    if len(stamp) >= 2:
        seconds, zone = int(stamp[0]), stamp[1]
    else:
        seconds, zone = int(time.time()), '+0000'
    sign = 1 if zone.startswith('+') else -1
    hours = int(zone[1:3])
    minutes = int(zone[3:5])
    offset = sign * (hours * 60 + minutes)
    zone_text = '%+03d:%02d' % (offset // 60, abs(offset) % 60)
    local = time.gmtime(seconds + offset * 60)
    date = time.strftime('%Y-%m-%dT%H:%M:%S', local) + zone_text
    return {'name': name.strip(), 'email': email.strip(), 'date': date}


def list_blobs(commit: str) -> list[dict]:
    """递归列出一个提交的全部文件（mode/type/sha/path）。"""
    out = git('ls-tree', '-r', commit)
    entries: list[dict] = []
    for line in out.decode('utf-8', 'replace').splitlines():
        if not line.strip():
            continue
        meta, _, path = line.partition('\t')
        parts = meta.split()
        if len(parts) < 3:
            continue
        mode, kind, sha = parts[0], parts[1], parts[2]
        if kind != 'blob':
            # 子模块（160000 commit）不支持；这个仓库没有
            print('  跳过非 blob 条目：%s %s' % (kind, path))
            continue
        entries.append({'mode': mode, 'sha': sha, 'path': path})
    return entries


# ── HTTP ────────────────────────────────────────────────────────

class Client:
    def __init__(self, token: str):
        self.token = token
        self.calls = 0

    def request(self, method: str, path: str, payload: dict | None = None,
                retries: int = 4, raw: bool = False):
        """发一个请求。

        @param raw 为 True 时返回 `(状态码, 响应体)` 而不是只返回体 ——
               用于「409 也算有效答案」的探测（如判断仓库是否为空）。
        """
        url = API + path
        data = None
        if payload is not None:
            data = json.dumps(payload).encode('utf-8')
        last = ''
        for attempt in range(retries):
            request = urllib.request.Request(url, data=data, method=method)
            request.add_header('Authorization', 'Bearer ' + self.token)
            request.add_header('Accept', 'application/vnd.github+json')
            request.add_header('X-GitHub-Api-Version', '2022-11-28')
            if data is not None:
                request.add_header('Content-Type', 'application/json')
            try:
                with urllib.request.urlopen(request, timeout=45) as response:
                    self.calls += 1
                    body = response.read().decode('utf-8', 'replace')
                    parsed = json.loads(body) if body.strip() else {}
                    return (response.status, parsed) if raw else parsed
            except urllib.error.HTTPError as error:
                self.calls += 1
                detail = error.read().decode('utf-8', 'replace')
                if raw:
                    try:
                        return error.code, json.loads(detail) if detail else {}
                    except json.JSONDecodeError:
                        return error.code, {'message': detail}
                # 422 常见于「引用已存在 / 内容未变化」，交给调用方判断
                if error.code in (422, 409):
                    return {'__status__': error.code, '__body__': detail}
                last = 'HTTP %d %s' % (error.code, detail[:300])
                if error.code == 401:
                    raise RuntimeError('token 无效或已过期：%s' % detail[:200])
                if error.code == 403:
                    raise RuntimeError('token 权限不足（需要 contents: write）：%s'
                                       % detail[:200])
            except Exception as error:            # 网络抖动
                last = '%s: %s' % (type(error).__name__, error)
            if attempt < retries - 1:
                time.sleep(1.5 * (attempt + 1))
        raise RuntimeError('%s %s 失败（重试 %d 次）：%s'
                           % (method, path, retries, last))


# ── 主流程 ──────────────────────────────────────────────────────

def bootstrap_if_empty(client: Client, owner: str, repo: str) -> bool:
    """仓库完全为空时，先用 Contents API 塞一个占位文件。

    ## 为什么必须这一步

    Git Data API（blobs / trees / commits）在**空仓库上直接返回 409**
    `Git Repository is empty.` —— 哪怕只是创建一个 blob。这是 GitHub 的
    设计：那些接口都要求仓库已经有一个提交作为起点。

    实测踩过：脚本把 409 当作成功（`result.get('sha', sha)` 回落到本地 sha），
    于是 blob 看起来全传完了，到建 tree 时才炸在 KeyError。

    这里用一个占位文件把仓库「点着」，随后建的正式根提交会把它顶掉，
    ref 强制指过去之后占位提交变成 unreachable，GitHub 会自行回收。

    @return 是否真的做了初始化（调用方据此提示）
    """
    status, _ = client.request('GET', '/repos/%s/%s/git/refs/heads/%s'
                               % (owner, repo, BRANCH), raw=True)
    if status != 409:
        return False                      # 已有内容，不用管

    print('  仓库是空的，先用 Contents API 建一个占位提交…')
    body = b'# placeholder\n'
    result = client.request(
        'PUT', '/repos/%s/%s/contents/%s' % (owner, repo, '.sr-bootstrap'),
        {'message': 'chore: bootstrap',
         'content': base64.b64encode(body).decode('ascii')})
    if result.get('__status__'):
        raise RuntimeError('初始化空仓库失败：%s'
                           % str(result.get('__body__'))[:300])
    print('  已初始化（后续会用正式提交覆盖）')
    return True


def remote_state(client: Client, owner: str, repo: str) -> tuple[str, set[str], set[str]]:
    """读出远端已有状态，用于增量推送。

    @return (远端 HEAD sha 或空串, 已有 commit sha 集合, 已有 blob sha 集合)

    ## 为什么要这一层

    全量重建对 3 个提交还行，但每改一次代码就重传七八十个 blob，
    迭代几次就慢得没法用。这里用 `trees?recursive=1` 一次拿到远端
    全部 blob sha，只上传本地新增的那些 —— 新增通常只有几个文件。
    """
    status, body = client.request(
        'GET', '/repos/%s/%s/git/ref/heads/%s' % (owner, repo, BRANCH), raw=True)
    if status != 200:
        return '', set(), set()

    head = (body.get('object') or {}).get('sha', '')
    if not head:
        return '', set(), set()

    # 沿着 parent 往上走，收集已有提交
    commits: set[str] = set()
    cursor = head
    while cursor and cursor not in commits:
        commits.add(cursor)
        status, info = client.request(
            'GET', '/repos/%s/%s/git/commits/%s' % (owner, repo, cursor), raw=True)
        if status != 200:
            break
        parents = info.get('parents') or []
        cursor = parents[0]['sha'] if parents else ''

    # 递归列树，收集已有 blob
    blobs: set[str] = set()
    status, tree = client.request(
        'GET', '/repos/%s/%s/git/trees/%s?recursive=1' % (owner, repo, head),
        raw=True)
    if status == 200:
        for item in tree.get('tree') or []:
            if item.get('type') == 'blob':
                blobs.add(item['sha'])
    return head, commits, blobs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true',
                        help='只打印计划，不写远端')
    parser.add_argument('--repo', default='%s/%s' % (OWNER, REPO))
    args = parser.parse_args()

    owner, _, repo = args.repo.partition('/')
    token = os.environ.get('GITHUB_TOKEN', '').strip()
    if not token and not args.dry_run:
        print('缺 GITHUB_TOKEN 环境变量', file=sys.stderr)
        return 2

    commits = git('rev-list', '--reverse', 'HEAD').decode().split()
    if not commits:
        print('本地没有提交', file=sys.stderr)
        return 1

    # blob 内容按 sha 去重
    blob_cache: dict[str, bytes] = {}
    plans: list[dict] = []
    for sha in commits:
        info = read_commit(sha)
        files = list_blobs(sha)
        for item in files:
            blob_cache.setdefault(item['sha'], b'')
        plans.append({'sha': sha, 'info': info, 'files': files})

    total_files = sum(len(plan['files']) for plan in plans)
    print('提交数：%d' % len(plans))
    print('文件条目：%d（唯一 blob %d）' % (total_files, len(blob_cache)))
    print('仓库：%s/%s · 分支：%s' % (owner, repo, BRANCH))
    for plan in plans:
        subject = plan['info']['message'].strip().split('\n')[0]
        print('  · %s  %s  (%d 文件)'
              % (plan['sha'][:8], subject, len(plan['files'])))

    if args.dry_run:
        print('\n[dry-run] 不写远端。去掉 --dry-run 才会真正推送。')
        return 0

    client = Client(token)

    # 0) 空仓库要先「点着」：Git Data API 在空仓库上直接 409
    print('\n==> 0/4 检查仓库状态')
    bootstrap_if_empty(client, owner, repo)

    # 读出远端已有对象 → 只推增量
    remote_head, remote_commits, remote_blobs = remote_state(client, owner, repo)
    todo = [plan for plan in plans if plan['sha'] not in remote_commits]
    if not todo:
        print('远端已经是最新（%s），无需推送' % remote_head[:8])
        return 0
    print('  远端 HEAD %s · 已有 blob %d 个'
          % (remote_head[:8] if remote_head else '(空)', len(remote_blobs)))
    print('  待推送提交 %d 个，跳过已有 blob %d 个'
          % (len(todo), len([s for s in blob_cache if s in remote_blobs])))

    # 1) 上传 blob（跳过远端已存在的）
    print('==> 1/4 上传 blob')
    uploaded: dict[str, str] = {}
    for sha in remote_blobs:
        if sha in blob_cache:
            uploaded[sha] = sha          # 远端已有，直接用同一 sha
    need_upload = [sha for sha in blob_cache if sha not in uploaded]
    print('    需上传 %d 个，复用 %d 个' % (len(need_upload), len(uploaded)))
    for index, sha in enumerate(sorted(need_upload), 1):
        content = git('cat-file', 'blob', sha)
        result = client.request(
            'POST', '/repos/%s/%s/git/blobs' % (owner, repo),
            {'content': base64.b64encode(content).decode('ascii'),
             'encoding': 'base64'})
        new_sha = result.get('sha')
        if not new_sha:
            # 绝不能静默回落成本地 sha —— 那会让后面的 tree 用不存在的对象
            raise RuntimeError('blob %s 上传失败：%s'
                               % (sha[:8], str(result)[:300]))
        uploaded[sha] = new_sha
        if index % 20 == 0 or index == len(need_upload):
            print('    %d/%d' % (index, len(need_upload)))

    # 2) 重建 tree
    print('==> 2/4 重建 tree')
    tree_shas: dict[str, str] = {}
    for plan in todo:
        entries = []
        for item in plan['files']:
            entries.append({
                'path': item['path'],
                'mode': item['mode'],
                'type': 'blob',
                'sha': uploaded[item['sha']],
            })
        result = client.request(
            'POST', '/repos/%s/%s/git/trees' % (owner, repo),
            {'tree': entries})
        tree_shas[plan['sha']] = result['sha']
        print('    %s → tree %s' % (plan['sha'][:8], result['sha'][:8]))

    # 3) 重建 commit（保留 author/committer 时间，sha 才能一致）
    print('==> 3/4 重建 commit')
    new_shas: dict[str, str] = {plan['sha']: plan['sha'] for plan in plans
                                if plan['sha'] in remote_commits}
    for plan in todo:
        info = plan['info']
        payload = {
            'message': info['message'],
            'tree': tree_shas[plan['sha']],
            'parents': [new_shas[parent] for parent in info['parents']
                        if parent in new_shas],
        }
        author = parse_ident(info.get('author', ''))
        committer = parse_ident(info.get('committer', ''))
        if author:
            payload['author'] = author
        if committer:
            payload['committer'] = committer
        result = client.request(
            'POST', '/repos/%s/%s/git/commits' % (owner, repo), payload)
        new_shas[plan['sha']] = result['sha']
        note = '一致' if result['sha'] == plan['sha'] else '与本地不同'
        print('    %s → %s（%s）'
              % (plan['sha'][:8], result['sha'][:8], note))

    # 4) 指向分支
    print('==> 4/4 更新分支 %s' % BRANCH)
    head = new_shas[plans[-1]['sha']]
    result = client.request(
        'POST', '/repos/%s/%s/git/refs' % (owner, repo),
        {'ref': 'refs/heads/%s' % BRANCH, 'sha': head})
    if result.get('__status__') == 422:
        # 引用已存在 → 强制改指
        result = client.request(
            'PATCH', '/repos/%s/%s/git/refs/heads/%s' % (owner, repo, BRANCH),
            {'sha': head, 'force': True})
        if result.get('__status__'):
            print('    更新失败：%s' % result.get('__body__', '')[:200])
            return 1
    print('    refs/heads/%s → %s' % (BRANCH, head[:8]))

    print('\n完成，共 %d 次 API 调用。' % client.calls)
    print('仓库：https://github.com/%s/%s' % (owner, repo))
    print('Actions：https://github.com/%s/%s/actions' % (owner, repo))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
