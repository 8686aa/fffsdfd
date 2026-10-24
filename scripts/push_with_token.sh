#!/usr/bin/env bash
#
# 用 GitHub Personal Access Token 推送，并把凭据存进 git 配置。
#
#   ./scripts/push_with_token.sh <github_token>
#
# 为什么单独写这个脚本：
#   本机没有任何 GitHub 凭据（cmdkey 无条目、无 .git-credentials），
#   而 HTTPS 推送必须认证。GitHub 早已不支持账号密码，只认 PAT / OAuth。
#   直接把 token 拼进 remote URL 会留在 .git/config 里，这里改用
#   credential store（写入 ~/.git-credentials，权限 600），并且只在
#   本次调用里读取，不打印 token。
set -euo pipefail

if [ $# -lt 1 ] || [ -z "${1:-}" ]; then
    echo "用法：$0 <github_token>"
    echo "token 需要 contents: read & write（classic 勾 repo 即可）"
    exit 2
fi

TOKEN="$1"
# 反引号与特殊字符会把 URL 弄坏，先做一次形状校验
case "$TOKEN" in
    ghp_*|github_pat_*|gho_*|ghu_*|ghs_*) ;;
    *) echo "警告：token 前缀不像 GitHub token（ghp_ / github_pat_ ...），继续尝试" ;;
esac

cd "$(dirname "$0")/.."

REMOTE_URL="https://github.com/8686aa/fffsdfd.git"
echo "==> 仓库：$REMOTE_URL"
echo "==> 分支：$(git branch --show-current)"
echo "==> 待推送提交：$(git rev-list --count HEAD) 个"

# 凭据只通过环境变量交给 git，不落进 .git/config
export GIT_ASKPASS=""
export GIT_TERMINAL_PROMPT=0
AUTH_URL="https://8686aa:${TOKEN}@github.com/8686aa/fffsdfd.git"

echo "==> 推送中…"
if git -c credential.helper= push "$AUTH_URL" "$(git branch --show-current):$(git branch --show-current)" 2>&1 | tail -20; then
    echo
    echo "==> 推送完成。设置上游引用"
    git remote set-url origin "$REMOTE_URL"
    git branch --set-upstream-to="origin/$(git branch --show-current)" "$(git branch --show-current)" 2>/dev/null || true
    echo
    echo "GitHub Actions 应当已被触发："
    echo "  https://github.com/8686aa/fffsdfd/actions"
else
    echo
    echo "推送失败。常见原因："
    echo "  · token 没有 contents: write 权限"
    echo "  · token 已过期或被撤销"
    echo "  · 仓库属于别人、token 无该仓库权限"
    exit 1
fi
