"""OIDC authorization codes are bound to a per-login verifier."""
import base64
import hashlib
from types import SimpleNamespace
from urllib.parse import urlparse, parse_qs
import pytest
from gpustack.routes import auth


def request(cookies=None):
    config = SimpleNamespace(openid_configuration={'authorization_endpoint': 'https://id.example.internal/auth'}, oidc_client_id='gpu', oidc_redirect_uri='https://gpu.example.internal/auth/oidc/callback')
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(server_config=config)), url=SimpleNamespace(scheme='http'), cookies=cookies or {}, query_params={'state': 'valid', 'code': 'code'})


@pytest.mark.asyncio
async def test_login_generates_s256_and_secure_http_only_verifier():
    response = await auth.oidc_login(request())
    query = parse_qs(urlparse(response.headers['location']).query)
    cookies = response.headers.getlist('set-cookie')
    cookie = next(c for c in cookies if c.startswith(auth.OIDC_PKCE_COOKIE_NAME + '='))
    verifier = cookie.split(';')[0].split('=', 1)[1]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    assert query['code_challenge'] == [challenge]
    assert query['code_challenge_method'] == ['S256']
    assert 'HttpOnly' in cookie and 'Secure' in cookie and 'SameSite=lax' in cookie
    second = await auth.oidc_login(request())
    assert second.headers['location'] != response.headers['location']


@pytest.mark.asyncio
@pytest.mark.parametrize('verifier', ['', 'short', '!' * 43])
async def test_callback_rejects_missing_or_invalid_verifier_before_exchange(verifier):
    req = request({auth.OIDC_STATE_COOKIE_NAME: 'valid', auth.OIDC_PKCE_COOKIE_NAME: verifier})
    response = await auth.oidc_callback(req, object())
    assert response.status_code == 303
    assert response.headers['location'] == auth.AUTH_FAILED_LOGIN_URL

@pytest.mark.asyncio
async def test_callback_sends_saved_verifier_to_token_endpoint(monkeypatch):
    captured = {}
    class Client:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def request(self, method, url, data):
            captured.update(data)
            return SimpleNamespace(status_code=400, text='{"error_description":"invalid code"}')
    monkeypatch.setattr(auth.httpx, 'AsyncClient', Client)
    verifier = 'A' * 43
    req = request({auth.OIDC_STATE_COOKIE_NAME: 'valid', auth.OIDC_PKCE_COOKIE_NAME: verifier})
    config = req.app.state.server_config
    config.oidc_client_secret = 'test-secret'
    config.external_auth_insecure_skip_tls_verify = False
    config.openid_configuration['token_endpoint'] = 'https://id.example.internal/token'
    response = await auth.oidc_callback(req, object())
    assert captured['code_verifier'] == verifier
    assert captured['code'] == 'code'
    assert response.headers['location'] == auth.AUTH_FAILED_LOGIN_URL
