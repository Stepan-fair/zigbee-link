from collections import deque
import hashlib
import hmac
import re
import secrets
import threading
import time

USER = re.compile(r"[A-Za-z0-9_-]{1,100}")


class IngressSecurity:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.secret = secrets.token_bytes(32)
        self.rates = {}
        self.lock = threading.Lock()

    def check_peer(self, peer_ip, user_id, capabilities):
        return bool(peer_ip == "172.30.32.2" and isinstance(user_id, str) and USER.fullmatch(user_id)
                    and capabilities.web_write_allowed)

    def issue_csrf(self, user_id):
        if not isinstance(user_id, str) or not USER.fullmatch(user_id):
            raise ValueError("unknown_user")
        value = str(int(self.clock())) + "." + secrets.token_hex(16)
        signature = hmac.new(self.secret, (user_id + ":" + value).encode(), hashlib.sha256).hexdigest()
        return value + "." + signature

    def verify_csrf(self, user_id, token):
        if not isinstance(user_id, str) or not USER.fullmatch(user_id) or not isinstance(token, str) or len(token) > 150:
            return False
        try:
            issued, nonce, signature = token.split(".")
            age = self.clock() - int(issued)
            if not 0 <= age <= 900 or not re.fullmatch(r"[0-9a-f]{32}", nonce):
                return False
            expected = hmac.new(self.secret, (user_id + ":" + issued + "." + nonce).encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature)
        except (ValueError, TypeError):
            return False

    def admit_mutation(self, user_id):
        with self.lock:
            now = self.clock()
            self.rates = {key: values for key, values in self.rates.items() if values and now - values[-1] < 60}
            if user_id not in self.rates and len(self.rates) >= 256:
                return False
            values = self.rates.setdefault(user_id, deque())
            while values and now - values[0] >= 60:
                values.popleft()
            if len(values) >= 30:
                return False
            values.append(now)
            return True
