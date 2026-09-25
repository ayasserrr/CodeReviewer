import logging

from system.logs import quiet_third_party_loggers


def test_third_party_loggers_are_quieted_but_app_loggers_are_not():
    logging.getLogger("controllers").setLevel(logging.NOTSET)
    quiet_third_party_loggers()
    for name in ("httpcore.http11", "httpx", "deepagents.middleware._prompt_caching"):
        assert not logging.getLogger(name).isEnabledFor(logging.DEBUG)
        assert logging.getLogger(name).isEnabledFor(logging.WARNING)
    assert logging.getLogger("controllers").getEffectiveLevel() == logging.getLogger().getEffectiveLevel()
