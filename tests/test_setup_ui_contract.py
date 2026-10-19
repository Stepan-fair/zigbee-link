from pathlib import Path
import re

STATIC = Path(__file__).resolve().parents[1] / "zigbee_link/app/web/static"


def test_ui_has_no_absolute_ingress_paths_or_remote_resources():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert './static/app.js' in html and './static/app.css' in html
    assert not re.search(r"(?:src|href)=[\"'](?:https?:|//|/api|/static)", html)
    assert "https://" not in script + css and "http://" not in script + css
    assert "fetch('./api/" in script
    assert "innerHTML" not in script and "textContent" in script


def test_ui_uses_field_modes_and_preserves_pending_edit_on_conflict():
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    assert all(name in script for name in ("renderState", "submitChange", "renderField", "expected_revision", "catalog_revision", "confirm_identity"))
    assert all(text in script for text in ("Вернуть автоматическое определение", "Данные изменились", "Введённые значения сохранены", "Источник", "Ручное значение"))
    assert "response.status === 409" in script and "pendingEdit" in script


def test_ui_has_explicit_readiness_and_radio_labels():
    source = (STATIC / "index.html").read_text(encoding="utf-8") + (STATIC / "app.js").read_text(encoding="utf-8")
    for text in ("Разрешён", "Настроен", "Управляет", "Найти сети", "Поддерживать сеть включённой", "Пауза обслуживания", "Радиообмен подтверждён", "Нет контрольных устройств", "Наблюдение", "Исправить"):
        assert text in source


def test_observation_does_not_claim_confirmed_application_health():
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "подтверждена только работа приложения" not in script
    assert "радиообмен не проверяется" in script
