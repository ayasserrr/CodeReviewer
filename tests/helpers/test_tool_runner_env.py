from helpers.tool_runner import safe_env


def test_subprocess_env_never_carries_server_secrets(monkeypatch):
    for name, value in {
        "GEMINI_API_KEY": "g", "JWT_SECRET_KEY": "j", "POSTGRES_PASSWORD": "p", "AWS_SECRET_ACCESS_KEY": "a",
        "DATABASE_URL": "postgres://u:p@h/db", "GITLAB_TOKEN": "t", "PATH": "/usr/bin", "HOME": "/home/x",
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.proxy", "GIT_CONFIG_VALUE_0": "http://proxy",
    }.items():
        monkeypatch.setenv(name, value)
    env = safe_env({"GIT_ASKPASS_TOKEN": "per-call"})
    for secret in ("GEMINI_API_KEY", "JWT_SECRET_KEY", "POSTGRES_PASSWORD", "AWS_SECRET_ACCESS_KEY", "DATABASE_URL",
                   "GITLAB_TOKEN"):
        assert secret not in env
    assert env["PATH"] == "/usr/bin" and env["HOME"] == "/home/x"
    assert env["GIT_CONFIG_KEY_0"] == "http.proxy" and env["GIT_CONFIG_COUNT"] == "1"
    assert env["GIT_ASKPASS_TOKEN"] == "per-call"  # explicit per-call values are always passed
