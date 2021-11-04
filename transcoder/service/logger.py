import logging
from config import config

logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s - %(message)s", level=config.logging_level.upper())

loggers = {}


def create_logger(name, context):
    logger = loggers.get(name, None)
    if not logger:
        logger = logging.getLogger(name)
        for handler in logger.handlers:
            fmt= logging.Formatter("%(asctime)s %(levelname)s %(name)s %(context)s - %(message)s")
            handler.setFormatter(fmt)

    return logging.LoggerAdapter(logger, {"context": context})
