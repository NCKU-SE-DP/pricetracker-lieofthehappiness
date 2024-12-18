# 這是一個 Python 日誌(logging)配置文件，主要設置了三種日誌處理器：
# 1. 創建一個名為"logger"的日誌記錄器，設置最低記錄級別為DEBUG
import logging
from logging.handlers import RotatingFileHandler

logger = logging.getLogger("logger")
logger.setLevel(logging.DEBUG)

# 設置日誌格式，包含時間、logger名稱、日誌級別和訊息
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# 設置控制台輸出處理器，級別為INFO
stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.INFO)
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

# 設置文件輸出處理器，將所有DEBUG及以上級別的日誌寫入app.log
file_handler = logging.FileHandler("app.log")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# 設置循環文件處理器，當文件達到5MB時會自動輪換，保留3個備份
# 只記錄ERROR及以上級別的日誌
rotating_file_handler = RotatingFileHandler(
    "app_rotating.log", maxBytes=5 * 1024 * 1024, backupCount=3
)
rotating_file_handler.setLevel(logging.ERROR)
rotating_file_handler.setFormatter(formatter)
logger.addHandler(rotating_file_handler)
