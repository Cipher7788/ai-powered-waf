"""Small rotating security logger."""
import logging
import os
from logging.handlers import RotatingFileHandler


class SecurityLogger:
    def __init__(self, log_file=None):
        self.log_file = log_file or os.getenv("LOG_FILE", "security.log")
        self.logger = logging.getLogger("ai_powered_waf.security")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        if not self.logger.handlers:
            formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
            stream = logging.StreamHandler()
            stream.setFormatter(formatter)
            self.logger.addHandler(stream)
            try:
                parent = os.path.dirname(os.path.abspath(self.log_file))
                os.makedirs(parent, exist_ok=True)
                handler = RotatingFileHandler(self.log_file, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
            except OSError:
                self.logger.warning("File logging unavailable; using stream logging only")

    def log(self, message):
        self.logger.info("%s", str(message)[:2000])
