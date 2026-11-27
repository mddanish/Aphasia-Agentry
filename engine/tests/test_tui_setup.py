import asyncio

from aphasia import config
from aphasia.tui.app import AphasiaApp
from aphasia.tui.data import load_demo
from aphasia.tui.setup import SetupScreen


def _fill(screen, **values):
    for wid, v in values.items():
        screen.query_one(f"#{wid}").value = v


def test_first_run_setup_saves_two_separate_llms():
    async def go():
        assert config.is_first_run()
        app = AphasiaApp(load_demo(), setup=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            scr = app.screen
            assert isinstance(scr, SetupScreen)
            _fill(scr, **{"mode": "proxy", "a-on": True, "a-model": "anthropic/claude-x", "a-key": "sk-att",
                          "u-on": True, "u-model": "ollama_chat/qwen2.5:7b-instruct",
                          "u-base": "http://127.0.0.1:11434", "u-key": ""})
            for _ in range(5):  # walk every step so each view renders
                await pilot.press("ctrl+n")
                await pilot.pause()
            await pilot.press("ctrl+s")
            await pilot.pause()
            assert not isinstance(app.screen, SetupScreen)
        c = config.load()
        assert c.mode == "proxy"
        assert c.attacker.model == "anthropic/claude-x" and c.upstream.model.startswith("ollama_chat/")
        assert c.secret(config.ATTACKER_KEY) == "sk-att" and c.secret(config.UPSTREAM_KEY) == ""
        assert c.secret(config.PROXY_KEY).startswith("sk-aphasia-")
        assert "sk-att" not in (config.home() / "config.toml").read_text()
    asyncio.run(go())


def test_setup_refuses_attacker_through_proxy():
    async def go():
        app = AphasiaApp(load_demo(), setup=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _fill(app.screen, **{"a-on": True, "a-model": "gpt-4o-mini", "a-base": "http://127.0.0.1:4000/v1",
                                 "u-on": True, "u-model": "gpt-4o-mini"})
            await pilot.press("ctrl+s")
            await pilot.pause()
            assert isinstance(app.screen, SetupScreen)  # still open, not saved
        assert config.is_first_run()
    asyncio.run(go())


def test_env_secret_is_used_but_not_written(monkeypatch):
    monkeypatch.setenv(config.ATTACKER_KEY, "sk-from-env")

    async def go():
        app = AphasiaApp(load_demo(), setup=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert app.screen.query_one("#a-key").value == ""   # env value never copied into the form
            _fill(app.screen, **{"a-on": True, "a-model": "gpt-4o-mini"})
            await pilot.press("ctrl+s")
            await pilot.pause()
            assert not isinstance(app.screen, SetupScreen)       # env key satisfies the check
    asyncio.run(go())
    assert "sk-from-env" not in (config.home() / "secrets.env").read_text()
    assert config.load().secret(config.ATTACKER_KEY) == "sk-from-env"


def test_setup_only_exits_after_save():
    async def go():
        app = AphasiaApp(load_demo(), setup_only=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("ctrl+s")
            await pilot.pause()
        assert app.return_code == 0
    asyncio.run(go())
    assert not config.is_first_run()
