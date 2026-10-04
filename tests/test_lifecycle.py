import os
import pytest
from app.main import InstanceLock
from app.network import NetworkError


@pytest.mark.skipif(os.name != "posix", reason="flock is a Linux runtime gate")
def test_second_process_lock_rejected(tmp_path):
    with InstanceLock(tmp_path):
        with pytest.raises(NetworkError):
            with InstanceLock(tmp_path): pass
