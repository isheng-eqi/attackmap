#!/bin/bash
# Auto-Pentest Environment Check Script
# 自动检测可用工具并分级

echo "========================================="
echo "  Auto-Pentest 环境检测"
echo "========================================="
echo ""

LEVEL=0  # 0=minimal, 1=basic, 2=standard, 3=pro

# --- 必须工具 ---
echo "--- 必须工具 (Level 0) ---"
for tool in curl python3 python; do
    if cmd=$(command -v "$tool" 2>/dev/null); then
        echo "  ✅ $tool: $cmd"
    else
        echo "  ❌ $tool: NOT FOUND"
    fi
done

# --- DNS 工具 ---
echo ""
echo "--- DNS 工具 (Level 1) ---"
for tool in nslookup dig host; do
    if cmd=$(command -v "$tool" 2>/dev/null); then
        echo "  ✅ $tool: $cmd"
        LEVEL=1
    else
        echo "  ⬜ $tool: not found"
    fi
done

# --- Go 工具 (Level 2) ---
echo ""
echo "--- Go 侦察工具 (Level 2) ---"
if cmd=$(command -v go 2>/dev/null); then
    echo "  ✅ go: $cmd"
    for tool in subfinder httpx nuclei dnsx naabu katana; do
        if cmd2=$(command -v "$tool" 2>/dev/null); then
            echo "    ✅ $tool: $cmd2"
            LEVEL=2
        else
            echo "    ⬜ $tool: not installed (go install ...)"
        fi
    done
else
    echo "  ⬜ go: not found (skip Go tools)"
fi

# --- 高级工具 (Level 3) ---
echo ""
echo "--- 高级工具 (Level 3) ---"
for tool in nmap masscan sqlmap amass ffuf whatweb eyewitness burpsuite; do
    if cmd=$(command -v "$tool" 2>/dev/null); then
        echo "  ✅ $tool: $cmd"
        LEVEL=3
    else
        echo "  ⬜ $tool: not found"
    fi
done

# --- 总结 ---
echo ""
echo "========================================="
echo "  环境等级: Level $LEVEL"
case $LEVEL in
    0) echo "  最小可用 (curl + python)" ;;
    1) echo "  基础环境 (+ DNS 工具)" ;;
    2) echo "  标准环境 (+ Go 工具链)" ;;
    3) echo "  专业环境 (+ 完整工具链)" ;;
esac
echo "========================================="

# 输出环境等级供后续使用
echo "ENV_LEVEL=$LEVEL"
