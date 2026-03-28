import asyncio

from src.services.browser_captcha import TokenBrowser


def test_shared_browser_recycles_after_ten_successful_solves(tmp_path):
    browser = TokenBrowser(token_id=0, user_data_dir=str(tmp_path / "browser"))

    old_playwright = object()
    old_browser = object()
    old_context = object()
    new_playwright = object()
    new_browser = object()
    new_context = object()

    browser._shared_playwright = old_playwright
    browser._shared_browser = old_browser
    browser._shared_context = old_context
    browser._shared_solve_count = browser.DEFAULT_MAX_SOLVES_PER_BROWSER

    recycle_calls = []
    create_calls = []

    async def fake_recycle(reason="unknown", rotate_profile=True):
        recycle_calls.append((reason, rotate_profile))
        browser._shared_playwright = None
        browser._shared_browser = None
        browser._shared_context = None
        browser._shared_keepalive_page = None
        browser._shared_proxy_url = None
        browser._shared_solve_count = 0

    async def fake_create(token_proxy_url=None):
        create_calls.append(token_proxy_url)
        return new_playwright, new_browser, new_context

    async def fake_keepalive():
        return object()

    browser._recycle_browser_locked = fake_recycle
    browser._create_browser = fake_create
    browser._ensure_shared_keepalive_page = fake_keepalive

    playwright, shared_browser, context = asyncio.run(browser._get_or_create_shared_browser())

    assert recycle_calls == [("max_solves_reached", True)]
    assert create_calls == [None]
    assert playwright is new_playwright
    assert shared_browser is new_browser
    assert context is new_context
    assert browser._shared_solve_count == 0
