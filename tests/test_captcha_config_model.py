from src.core.models import CaptchaConfig, Token


def test_captcha_config_exposes_browser_max_solves_per_browser():
    config = CaptchaConfig(browser_max_solves_per_browser=7)

    assert config.browser_max_solves_per_browser == 7


def test_token_model_does_not_accept_captcha_config_only_field():
    token = Token(st="st", email="user@example.com")

    assert not hasattr(token, "browser_max_solves_per_browser")
