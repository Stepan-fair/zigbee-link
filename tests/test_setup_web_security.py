from dataclasses import replace
from app.setup.model import SupervisorCapabilities


def test_direct_lan_and_spoofed_forward_headers_denied():
    from app.web.security import IngressSecurity
    security = IngressSecurity()
    capabilities = SupervisorCapabilities("2026.10.2", 63001, True)
    assert security.check_peer("172.30.32.2", "admin-id", capabilities)
    for peer in ("127.0.0.1", "172.30.32.3", "192.168.1.20", "::1"):
        assert not security.check_peer(peer, "admin-id", capabilities)
    assert not security.check_peer("172.30.32.2", None, capabilities)
    assert not security.check_peer("172.30.32.2", "admin-id", replace(capabilities, web_write_allowed=False))


def test_missing_or_expired_csrf_and_unknown_user_denied():
    from app.web.security import IngressSecurity
    now = [0]
    security = IngressSecurity(clock=lambda: now[0])
    token = security.issue_csrf("admin-id")
    assert security.verify_csrf("admin-id", token)
    assert not security.verify_csrf("different-user", token)
    assert not security.verify_csrf("admin-id", "")
    assert not IngressSecurity().verify_csrf("admin-id", token)
    now[0] = 901
    assert not security.verify_csrf("admin-id", token)


def test_mutation_rate_limit_recovers_after_minute():
    from app.web.security import IngressSecurity
    now = [0]
    security = IngressSecurity(clock=lambda: now[0])
    assert all(security.admit_mutation("admin-id") for _ in range(30))
    assert not security.admit_mutation("admin-id")
    now[0] = 60
    assert security.admit_mutation("admin-id")
