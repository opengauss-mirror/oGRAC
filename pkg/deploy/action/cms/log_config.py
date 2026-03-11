"""
CMS 日志配置模块

重构自原 log.py:
  - 路径从 config.py 读取，不再硬编码 /opt/ograc
  - 敏感信息过滤保留
  - 支持自定义日志目录
"""

import os
import logging
from logging import handlers, LogRecord
from pathlib import Path


LOG_MAX_SIZE = 6 * 1024 * 1024
LOG_BACKUP_COUNT = 5
LOG_DATE_FMT = "%Y-%m-%d %H:%M:%S"
LOG_FMT = (
    "%(asctime)s %(levelname)s [pid:%(process)d] [%(threadName)s] "
    "[tid:%(thread)d] [%(filename)s:%(lineno)d %(funcName)s] %(message)s"
)

SENSITIVE_KEYWORDS = [
    'Password', 'passWord', 'PASSWORD', 'password', 'Pswd',
    'PSWD', 'pwd', 'signature', 'HmacSHA256', 'newPasswd',
    'private', 'certfile', 'secret', 'token', 'Token', 'pswd',
    'passwd', 'session', 'cookie'
]


class SensitiveFilter(logging.Filter):
    """过滤包含敏感关键词的日志消息"""
    def filter(self, record: LogRecord) -> bool:
        msg_upper = record.getMessage().upper()
        return not any(kw.upper() in msg_upper for kw in SENSITIVE_KEYWORDS)


def setup_logger(log_file, name="cms_deploy", level=logging.INFO):
    """
    初始化日志器。

    Args:
        log_file: 日志文件完整路径
        name: 日志器名称
        level: 日志级别

    Returns:
        logging.Logger 实例
    """
    log_dir = os.path.dirname(log_file)

    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, mode=0o750, exist_ok=True)

    if not os.path.exists(log_file):
        Path(log_file).touch(mode=0o640)

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)

    file_handler = handlers.RotatingFileHandler(
        log_file,
        maxBytes=LOG_MAX_SIZE,
        backupCount=LOG_BACKUP_COUNT,
    )
    file_handler.setFormatter(logging.Formatter(fmt=LOG_FMT, datefmt=LOG_DATE_FMT))
    logger.addHandler(file_handler)

    logger.addFilter(SensitiveFilter())

    try:
        os.chmod(log_dir, 0o750)
        os.chmod(log_file, 0o640)
    except OSError:
        pass

    return logger


def get_logger(log_file=None):
    """
    获取 CMS 部署日志器。

    若未指定 log_file，则从 config 读取路径。
    """
    if log_file is None:
        try:
            from config import cfg
            log_file = cfg.paths.cms_deploy_log
        except Exception:
            log_file = "/opt/ograc/log/cms/cms_deploy.log"
    return setup_logger(log_file)


LOGGER = get_logger()
