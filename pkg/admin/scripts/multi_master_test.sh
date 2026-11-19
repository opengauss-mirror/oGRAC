#!/bin/bash
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

# 帮助信息函数
function show_help() {
    echo "用法:"
    echo "  $0 <SYS_PASSWORD> <TEST_USER> --prepare  准备测试环境并启动写测试"
    echo "  $0 <SYS_PASSWORD> <TEST_USER> --runtest  运行读测试"
    echo "  $0 --stop                                停止所有测试"
    echo "  $0 --status                              查看测试状态"
    echo "  $0 --help                                显示此帮助信息"
    echo ""
    echo "参数说明:"
    echo "  SYS_PASSWORD  - 数据库系统用户密码"
    echo "  TEST_USER     - 测试用户名"
    echo ""
    echo "示例:"
    echo "  $0 password testuser --prepare"
    echo "  $0 password testuser --runtest"
    echo "  $0 --stop"
    echo "  $0 --status"
    exit 0
}

# 检查是否需要密码和用户的命令
NEEDS_CREDS_COMMANDS=("--prepare" "--runtest")

# 检查第一个参数是否为不需要认证的命令
if [ $# -ge 1 ]; then
    FIRST_ARG="$1"

    # 如果第一个参数就是不需要认证的命令
    if [[ "$FIRST_ARG" == "--stop" || "$FIRST_ARG" == "--status" || "$FIRST_ARG" == "--help" || "$FIRST_ARG" == "-h" ]]; then
        COMMAND="$FIRST_ARG"

        # 直接处理不需要认证的命令
        case "$COMMAND" in
            --help|-h)
                show_help
                ;;

            --stop)
                # 停止测试函数（稍后定义）
                function stop_tests() {
                    LOG_DIR="/tmp/db_test_logs"
                    WRITE_PID_FILE="$LOG_DIR/write_test.pid"
                    READ_PID_FILE="$LOG_DIR/read_test.pid"

                    echo "停止所有测试..."

                    # 停止写测试
                    if [ -f "$WRITE_PID_FILE" ]; then
                        WRITE_PID=$(cat "$WRITE_PID_FILE")
                        if ps -p "$WRITE_PID" > /dev/null 2>&1; then
                            kill -9 "$WRITE_PID" 2>/dev/null
                            echo "✓ 已停止写测试 (PID: $WRITE_PID)"
                        else
                            echo "写测试进程不存在"
                        fi
                        rm -f "$WRITE_PID_FILE"
                    else
                        echo "写测试未运行"
                    fi

                    # 停止读测试
                    if [ -f "$READ_PID_FILE" ]; then
                        READ_PID=$(cat "$READ_PID_FILE")
                        if ps -p "$READ_PID" > /dev/null 2>&1; then
                            kill -9 "$READ_PID" 2>/dev/null
                            echo "✓ 已停止读测试 (PID: $READ_PID)"
                        else
                            echo "读测试进程不存在"
                        fi
                        rm -f "$READ_PID_FILE"
                    else
                        echo "读测试未运行"
                    fi

                    echo "清理完成"
                }

                stop_tests
                exit 0
                ;;

            --status)
                # 查看状态函数
                function show_status() {
                    LOG_DIR="/tmp/db_test_logs"
                    WRITE_PID_FILE="$LOG_DIR/write_test.pid"
                    READ_PID_FILE="$LOG_DIR/read_test.pid"

                    echo "测试进程状态:"

                    if [ -f "$WRITE_PID_FILE" ] && ps -p $(cat "$WRITE_PID_FILE") > /dev/null 2>&1; then
                        WRITE_PID=$(cat "$WRITE_PID_FILE")
                        echo "✓ 写测试正在运行 (PID: $WRITE_PID)"
                        echo "   日志文件: $LOG_DIR/write_test.log"
                        if [ -f "$LOG_DIR/write_test.log" ]; then
                            echo "   最近日志:"
                            tail -n 3 "$LOG_DIR/write_test.log"
                        fi
                    else
                        echo "✗ 写测试未运行"
                    fi

                    echo ""

                    if [ -f "$READ_PID_FILE" ] && ps -p $(cat "$READ_PID_FILE") > /dev/null 2>&1; then
                        READ_PID=$(cat "$READ_PID_FILE")
                        echo "✓ 读测试正在运行 (PID: $READ_PID)"
                        echo "   日志文件: $LOG_DIR/read_test.log"
                        if [ -f "$LOG_DIR/read_test.log" ]; then
                            echo "   最近日志:"
                            tail -n 3 "$LOG_DIR/read_test.log"
                        fi
                    else
                        echo "✗ 读测试未运行"
                    fi
                }

                show_status
                exit 0
                ;;
        esac
    fi
fi

# 处理需要密码和用户的命令
if [ $# -lt 3 ]; then
    echo "错误: 参数不足"
    echo ""
    show_help
fi

# 处理参数
SYS_PWD=$1
TEST_USER=$2
COMMAND=$3

# 参数验证
if [ -z "$SYS_PWD" ]; then
    echo "错误: 系统密码不能为空"
    exit 1
fi

if [ -z "$TEST_USER" ]; then
    echo "错误: 测试用户名不能为空"
    exit 1
fi

# 检查集群状态
echo "检查集群状态..."
cms stat -res db | awk 'NR>1 && $3 != "ONLINE" {exit 1}'

if [ $? -eq 0 ]; then
    echo "✓ 集群状态正常"
else
    echo "✗ 集群有 OFFLINE/UNKNOWN 节点!"
    exit 1
fi

# 获取节点IP信息
CONFIG_FILE="/mnt/dbdata/local/ograc/tmp/data/cfg/ogracd.ini"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "错误: 配置文件不存在: $CONFIG_FILE"
    exit 1
fi

LOCAL_IPS=$(grep "^LSNR_ADDR" "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 | tr -d ' ' | tr ',' '\n' | grep -v "^127\.")

if [ -z "$LOCAL_IPS" ]; then
    echo "错误: 无法从配置文件中获取本地IP"
    exit 1
fi

CMS_IPS=$(cms node -list 2>/dev/null | awk 'NR>1 && $3 {print $3}')

if [ -z "$CMS_IPS" ]; then
    echo "错误: 无法获取节点列表"
    exit 1
fi

# 确定当前IP（配置中定义且在cms列表中的IP）
CURRENT_IP=""
for ip in $LOCAL_IPS; do
    if echo "$CMS_IPS" | grep -q "^$ip$"; then
        CURRENT_IP="$ip"
        break
    fi
done

[ -z "$CURRENT_IP" ] && { echo "错误: 无法确定当前IP"; exit 1; }

# 获取对端IP（cms列表中的其他IP）
PEER_IP=$(echo "$CMS_IPS" | grep -v "^$CURRENT_IP$" | head -n1)

[ -z "$PEER_IP" ] && { echo "错误: 未找到对端IP"; exit 1; }

echo "当前节点IP: $CURRENT_IP"
echo "对端节点IP: $PEER_IP"

# 定义日志目录
LOG_DIR="/tmp/db_test_logs"
mkdir -p "$LOG_DIR"

# PID文件路径
WRITE_PID_FILE="$LOG_DIR/write_test.pid"
READ_PID_FILE="$LOG_DIR/read_test.pid"

# 测试准备函数
function prepare_test() {
    echo "开始准备测试环境..."

    # 删除并创建测试用户
    echo "创建测试用户 $TEST_USER..."
    ogsql SYS/${SYS_PWD}@${CURRENT_IP}:1611 -q -c "DROP USER IF EXISTS ${TEST_USER} CASCADE;" >/dev/null 2>&1
    ogsql SYS/${SYS_PWD}@${CURRENT_IP}:1611 -q -c "create user ${TEST_USER} identified by '${SYS_PWD}';" >/dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "错误: 创建用户失败"
        return 1
    fi

    # 授权
    echo "授权给测试用户..."
    ogsql SYS/${SYS_PWD}@${CURRENT_IP}:1611 -q -c "grant create session to ${TEST_USER};grant create table to ${TEST_USER};grant dba to ${TEST_USER};grant inherit privileges on user SYS to ${TEST_USER};" >/dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "错误: 授权失败"
        return 1
    fi

    # 创建测试表
    echo "创建测试表..."
    ogsql ${TEST_USER}/${SYS_PWD}@${CURRENT_IP}:1611 -q -c "CREATE TABLE dual (dummy VARCHAR2(1));INSERT INTO dual (dummy) VALUES ('X');CREATE TABLE test (a_time TIMESTAMP, b_data NUMBER(10));" >/dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "错误: 创建表失败"
        return 1
    fi

    echo "✓ 测试环境准备完成"
    return 0
}

# 写测试函数
function run_write_test() {
    echo "启动写测试 (后台运行)..."
    echo "写测试日志: $LOG_DIR/write_test.log"

    # 检查是否已经运行
    if [ -f "$WRITE_PID_FILE" ] && ps -p $(cat "$WRITE_PID_FILE") > /dev/null 2>&1; then
        echo "写测试已经在运行 (PID: $(cat $WRITE_PID_FILE))"
        return 0
    fi

    # 在后台运行写测试
    (
        echo "写测试启动时间: $(date)"
        while true; do
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] 插入数据..." >> "$LOG_DIR/write_test_debug.log"
            ogsql ${TEST_USER}/${SYS_PWD}@${CURRENT_IP}:1611 -q -c "INSERT INTO test (a_time, b_data) SELECT CURRENT_TIMESTAMP, LEVEL FROM dual CONNECT BY LEVEL <= 25;" 2>&1
            ogsql ${TEST_USER}/${SYS_PWD}@${PEER_IP}:1611 -q -c "INSERT INTO test (a_time, b_data) SELECT CURRENT_TIMESTAMP, LEVEL FROM dual CONNECT BY LEVEL <= 25;" 2>&1
            sleep 0.25
        done
    ) > "$LOG_DIR/write_test.log" 2>&1 &

    WRITE_PID=$!
    echo $WRITE_PID > "$WRITE_PID_FILE"
    echo "✓ 写测试已启动 (PID: $WRITE_PID)"

    # 保存测试信息到文件，以便--stop和--status使用
    echo "TEST_USER=$TEST_USER" > "$LOG_DIR/test_info.env"
    echo "CURRENT_IP=$CURRENT_IP" >> "$LOG_DIR/test_info.env"
    echo "PEER_IP=$PEER_IP" >> "$LOG_DIR/test_info.env"
}

# 读测试函数
function run_read_test() {
    echo "启动读测试..."
    echo "读测试日志: $LOG_DIR/read_test.log"

    # 检查是否已经运行
    if [ -f "$READ_PID_FILE" ] && ps -p $(cat "$READ_PID_FILE") > /dev/null 2>&1; then
        echo "读测试已经在运行 (PID: $(cat $READ_PID_FILE))"
        return 0
    fi

    # 在前台运行读测试（可以按Ctrl+C停止）
    trap 'echo -e "\n读测试已停止"; exit 0' SIGINT SIGTERM

    echo "按 Ctrl+C 停止读测试"
    echo "开始时间: $(date)"

    # 记录PID
    echo $$ > "$READ_PID_FILE"

    while true; do
        stop_time=$(date +%s)
        interval=4
        start_time=$(($stop_time - $interval))
        stop_time_str=$(date "+%Y-%m-%d %H:%M:%S" -d @${stop_time})
        start_time_str=$(date "+%Y-%m-%d %H:%M:%S" -d @${start_time})

        # 在当前节点查询
        A=$(ogsql ${TEST_USER}/${SYS_PWD}@${CURRENT_IP}:1611 -q -c "select count(*) from test where a_time >= '${start_time_str}' and a_time <= '${stop_time_str}';" | tail -n 4 | head -n 1 | tr -d ' ')

        # 在对端节点查询
        B=$(ogsql ${TEST_USER}/${SYS_PWD}@${PEER_IP}:1611 -q -c "select count(*) from test where a_time >= '${start_time_str}' and a_time <= '${stop_time_str}';" | tail -n 4 | head -n 1 | tr -d ' ')

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 当前节点: ${A:-0}, 对端节点: ${B:-0}, 时间范围: ${start_time_str} 到 ${stop_time_str}" | tee -a "$LOG_DIR/read_test.log"

        # 如果读数为0，可能有问题
        if [ "${A:-0}" -eq 0 ] && [ "${B:-0}" -eq 0 ]; then
            echo "警告: 两个节点都未读取到数据，写测试可能未运行或有问题" >&2
        fi

        sleep 1
    done
}

# 停止测试函数（用于需要认证的命令）
function stop_tests() {
    echo "停止所有测试..."

    # 停止写测试
    if [ -f "$WRITE_PID_FILE" ]; then
        WRITE_PID=$(cat "$WRITE_PID_FILE")
        if ps -p "$WRITE_PID" > /dev/null 2>&1; then
            kill -9 "$WRITE_PID" 2>/dev/null
            echo "✓ 已停止写测试 (PID: $WRITE_PID)"
        else
            echo "写测试进程不存在"
        fi
        rm -f "$WRITE_PID_FILE"
    else
        echo "写测试未运行"
    fi

    # 停止读测试
    if [ -f "$READ_PID_FILE" ]; then
        READ_PID=$(cat "$READ_PID_FILE")
        if ps -p "$READ_PID" > /dev/null 2>&1; then
            kill -9 "$READ_PID" 2>/dev/null
            echo "✓ 已停止读测试 (PID: $READ_PID)"
        else
            echo "读测试进程不存在"
        fi
        rm -f "$READ_PID_FILE"
    else
        echo "读测试未运行"
    fi

    echo "清理完成"
}

# 根据命令执行相应操作
case "$COMMAND" in
    --prepare)
        echo "执行准备测试模式..."
        prepare_test
        if [ $? -eq 0 ]; then
            run_write_test
            echo "准备完成，写测试已在后台运行"
            echo "使用以下命令查看写测试日志: tail -f $LOG_DIR/write_test.log"
            echo "使用以下命令查看测试状态: $0 --status"
            echo "使用以下命令运行读测试: $0 $SYS_PWD $TEST_USER --runtest"
        else
            echo "测试准备失败"
            exit 1
        fi
        ;;

    --runtest)
        echo "执行读测试模式..."
        # 检查写测试是否在运行
        if [ ! -f "$WRITE_PID_FILE" ] || ! ps -p $(cat "$WRITE_PID_FILE") > /dev/null 2>&1; then
            echo "警告: 写测试可能未运行，建议先运行: $0 $SYS_PWD $TEST_USER --prepare"
            read -p "是否继续? (y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 0
            fi
        fi
        run_read_test
        ;;

    *)
        echo "错误: 未知命令 '$COMMAND'"
        echo "可用命令: --prepare, --runtest, --stop, --status, --help"
        exit 1
        ;;
esac
