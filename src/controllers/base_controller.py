"""Shared config/logger plumbing for the static-analysis engine controllers."""

from config import Settings, settings
from system import get_logger


class BaseController:
    """Gives every analysis controller a configured ``self.config``/``self.logger``."""

    def __init__(self, config: Settings = settings) -> None:
        self.config = config
        self.logger = get_logger(type(self).__module__)
