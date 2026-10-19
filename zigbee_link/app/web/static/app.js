'use strict';
let state = null;
let csrf = '';
let pendingEdit = null;
let brokerRevision = null;
let busy = false;
const $ = id => document.getElementById(id);
const names = {name: 'Название сети', ip: 'IP координатора', serial_port: 'Порт координатора', addon_slug: 'Приложение Zigbee2MQTT', base_topic: 'Тема MQTT', coordinator_ieee: 'IEEE координатора', references: 'Контрольные устройства'};
const pins = new Set(['ip', 'serial_port', 'addon_slug', 'base_topic', 'coordinator_ieee']);
const sources = {manual: 'Введено вручную', legacy: 'Прежние настройки', supervisor: 'Home Assistant', mqtt: 'MQTT', bridge: 'MQTT', bridge_retained: 'Сохранённые сведения MQTT', app: 'Настройки приложения'};
const phases = {observing: 'Наблюдение', paused: 'Пауза обслуживания', dependency: 'Ожидание подключения', blocked: 'Нужна проверка', checking: 'Проверка приложения', suspect: 'Проверка отсутствия', absent: 'Координатор отсутствует', returning: 'Координатор вернулся', waiting: 'Ожидание повторной попытки', starting: 'Запускаем Zigbee2MQTT', confirmed: 'Работает', degraded: 'Радио требует проверки', unconfirmed: 'Приложение отвечает'};

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function notice(text, error = false) {
  $('notice').textContent = text;
  $('notice').className = 'notice ' + (error ? 'error' : 'success');
  $('notice').hidden = !text;
}
function button(text, action, className = '') {
  const node = el('button', text, className);
  node.type = 'button';
  node.addEventListener('click', () => Promise.resolve().then(action).catch(error => notice(error.message, true)));
  return node;
}
function check(text, checked, action, disabled = false) {
  const label = el('label', undefined, 'check');
  const input = document.createElement('input');
  input.type = 'checkbox'; input.checked = checked; input.disabled = disabled;
  input.addEventListener('change', async () => {
    input.disabled = true;
    try { await action(input.checked); }
    catch (error) { input.checked = checked; input.disabled = disabled; notice(error.message, true); }
  });
  label.append(input, el('span', text));
  return label;
}
async function read(path) {
  const response = await fetch('./api/' + path, {cache: 'no-store', credentials: 'same-origin'});
  if (!response.ok) throw new Error(response.status === 403 ? 'Доступ к экрану не подтверждён. Откройте Zigbee Link через Home Assistant.' : 'Не удалось получить состояние. Настройки не изменены.');
  return response.json();
}
async function loadState() { renderState(await read('state')); }
async function submitChange(path, payload) {
  if (busy) throw new Error('Дождитесь завершения предыдущего действия.');
  busy = true;
  try {
    const response = await fetch('./api/' + path, {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, body: JSON.stringify(payload)});
    if (response.status === 409) {
      throw new Error('Данные изменились в другом окне. Введённые значения сохранены. Сверьте их с новой версией перед повторным сохранением.');
    }
    if (!response.ok) {
      throw new Error(response.status === 403 ? 'Доступ отклонён. Настройки не сохранены. Обновите страницу через Home Assistant.' : response.status === 429 ? 'Слишком много действий. Подождите минуту; настройки не сохранены.' : 'Изменение не принято. Проверьте поля и подтверждение привязки. Настройки не сохранены.');
    }
    const result = await response.json();
    renderState(result.state);
    return result;
  } finally { busy = false; }
}
function fieldValue(record, name, fallback = '') { return record.fields[name]?.value ?? fallback; }
function guided() { return state?.mode === 'guided' && (!state.transition || state.transition.phase === 'verified'); }

function renderState(next) {
  state = next;
  $('enabled').textContent = next.readiness.enabled ? 'Да' : 'Нет';
  $('configured').textContent = next.readiness.configured ? 'Да' : 'Нет';
  $('managed').textContent = next.readiness.managed_count + (next.readiness.managed_count === 1 ? ' сетью' : ' сетями');
  $('global-control').replaceChildren(check('Разрешить восстановление', next.readiness.enabled, value => submitChange('networks/control', {network_id: null, enabled: value, expected_revision: state.revision}), !guided()));
  $('network-title').textContent = next.network.state === 'ready' ? 'Интерфейс готов' : next.network.state === 'unknown' ? 'Состояние ещё не получено' : 'Проверьте подключение';
  $('network-detail').textContent = (next.network.parent || 'auto') + ' → zigbee0 · ' + next.network.address;
  if (next.network.manual_unbound_ips?.length) $('network-detail').textContent += ' · Отдельно для диагностики: ' + next.network.manual_unbound_ips.join(', ');
  $('broker-title').textContent = next.broker?.configured ? 'Брокер настроен' : 'MQTT ещё не настроен';
  $('broker-detail').textContent = next.broker ? (next.broker.mode === 'auto' ? 'Найден в Home Assistant · ' : 'Указан вручную · ') + next.broker.server : 'Попробуем получить сведения из службы Home Assistant.';
  const modeText = el('div');
  modeText.append(el('strong', next.mode === 'guided' ? 'Настройки из этого экрана' : 'Работают прежние настройки'), el('p', next.mode === 'guided' ? 'Ручные исправления, паузы и разрешения сохраняются отдельно для каждой сети.' : 'Переход перенесёт разрешения и паузы. До подтверждения источником остаётся конфигурация приложения.'));
  let modeAction;
  if (next.transition && next.transition.phase !== 'verified') {
    modeAction = button('Проверить переход', () => openMigration());
    modeText.append(el('p', 'Переход не завершён. Новые команды восстановления заблокированы.'));
  } else {
    modeAction = button(next.mode === 'guided' ? 'Прежний способ настройки' : 'Перейти к настройке здесь', async () => {
      await submitChange('mode/prepare', {target_mode: next.mode === 'guided' ? 'legacy' : 'guided', expected_revision: state.revision});
      openMigration();
    }, 'secondary');
  }
  $('mode').replaceChildren(modeText, modeAction);
  const cards = next.networks.map(renderNetwork);
  $('networks').replaceChildren(...(cards.length ? cards : [el('div', 'Добавленных сетей пока нет. Используйте найденные сведения ниже или запустите поиск.', 'empty')]));
  const candidates = next.catalog.candidates.filter(c => !next.networks.some(n => fieldValue(n, 'addon_slug') && fieldValue(n, 'addon_slug') === fieldValue(c, 'addon_slug'))).map(renderCandidate);
  $('candidates').replaceChildren(...(candidates.length ? candidates : [el('div', 'Новых сетей пока не найдено. Поиск использует установленные приложения и сведения MQTT; ждать его завершения здесь не обязательно.', 'empty')]));
  if (next.readiness.reasons.includes('mqtt_unconfigured')) notice('Восстановление разрешено, но MQTT ещё не настроен. Сетевой интерфейс работает независимо.', true);
}
function renderNetwork(record) {
  const card = el('article', undefined, 'card');
  const title = el('div', undefined, 'card-head');
  title.append(el('h3', fieldValue(record, 'name') || 'Сеть Zigbee', 'card-name'), el('span', record.paused ? 'Пауза обслуживания' : record.accepted ? phases[record.phase] || 'Наблюдение' : 'Нужна проверка', 'badge ' + (record.phase === 'confirmed' ? 'good' : record.accepted ? '' : 'warn')));
  card.append(title, el('p', fieldValue(record, 'ip') || 'IP не определён', 'address'), el('p', fieldValue(record, 'addon_slug') || 'Приложение не определено'), el('p', 'MQTT · ' + (fieldValue(record, 'base_topic') || 'тема не определена')));
  const refs = fieldValue(record, 'references', []);
  card.append(el('div', record.radio === 'confirmed' ? 'Радиообмен подтверждён' : !refs.length ? 'Нет контрольных устройств · радиообмен не проверяется (application_only).' : 'Радиообмен пока не подтверждён. Проверка использует только чтение.', 'radio'));
  const controls = el('div', undefined, 'card-controls');
  controls.append(check('Поддерживать сеть включённой', record.managed, value => submitChange('networks/control', {network_id: record.network_id, managed: value, expected_revision: state.revision}), !guided() || !record.accepted), check('Пауза обслуживания', record.paused, value => submitChange('networks/control', {network_id: record.network_id, paused: value, expected_revision: state.revision}), !guided()));
  const actions = el('div', undefined, 'card-actions');
  actions.append(button('Исправить', () => openEditor(record), 'text-button'));
  if (Object.values(record.fields).some(f => f.proposal !== null && f.proposal !== undefined)) actions.append(el('span', 'Есть новые предложения', 'badge warn'));
  card.append(controls, actions);
  return card;
}
function renderCandidate(candidate) {
  const card = el('article', undefined, 'card');
  const ready = candidate.match_kind === 'verified' && candidate.issues.every(i => i === 'radio_reference_unavailable');
  card.append(el('h3', fieldValue(candidate, 'name') || 'Найденная сеть'), el('p', fieldValue(candidate, 'ip') || 'IP не определён', 'address'), el('p', fieldValue(candidate, 'addon_slug') || 'Приложение требует выбора'), el('p', ready ? 'Сведения однозначно сопоставлены. Можно добавить для наблюдения.' : 'Сведения неполные или противоречат друг другу. Проверьте привязку вручную.'));
  const action = button(ready ? 'Добавить для наблюдения' : 'Проверить привязку', async () => {
    const before = new Set(state.networks.map(n => n.network_id));
    await submitChange('networks/accept', {candidate_id: candidate.candidate_id, catalog_revision: state.catalog.revision, expected_revision: state.revision});
    const added = state.networks.find(n => !before.has(n.network_id));
    if (added && !added.accepted) openEditor(added);
    else notice('Сеть добавлена для наблюдения. Автоматическое восстановление можно разрешить отдельно.');
  });
  action.disabled = !guided();
  card.append(el('div', undefined, 'card-actions')); card.lastChild.append(action);
  return card;
}
function renderField(field) {
  const name = field.name;
  const wrap = el('div', undefined, 'field');
  const row = el('div', undefined, 'field-mode');
  const label = el('label', names[name]);
  const input = document.createElement(name === 'references' ? 'textarea' : 'input');
  input.id = 'field-' + name; input.name = name;
  input.value = name === 'references' ? JSON.stringify(field.value || [], null, 2) : field.value ?? '';
  if (name !== 'references') input.type = name === 'serial_port' ? 'number' : 'text';
  if (name === 'serial_port') { input.min = '1'; input.max = '65535'; }
  if (name === 'coordinator_ieee') input.pattern = '0x[0-9a-fA-F]{16}';
  if (name !== 'references') { input.required = true; input.maxLength = name === 'name' ? 80 : 200; }
  label.append(input);
  const mode = document.createElement('select'); mode.id = 'mode-' + name; mode.setAttribute('aria-label', 'Режим поля ' + names[name]);
  for (const [value, text] of [['auto', 'Автоматически'], ['manual', 'Ручное значение']]) { const option = el('option', text); option.value = value; mode.append(option); }
  mode.value = field.mode || 'auto';
  input.addEventListener('input', () => { mode.value = 'manual'; });
  row.append(label, mode); wrap.append(row);
  const time = field.observed_at ? new Date(field.observed_at * 1000).toLocaleString('ru-RU') : 'ещё не получено';
  wrap.append(el('div', 'Источник: ' + (sources[field.source] || 'Найденные сведения') + ' · ' + time, 'field-meta'));
  wrap.append(button('Вернуть автоматическое определение', () => { mode.value = 'auto'; if (field.proposal !== null && field.proposal !== undefined) input.value = name === 'references' ? JSON.stringify(field.proposal, null, 2) : field.proposal; }, 'text-button'));
  if (field.proposal !== null && field.proposal !== undefined) wrap.append(el('div', 'Найдено новое значение: ' + (name === 'references' ? JSON.stringify(field.proposal) : field.proposal), 'field-meta'));
  return wrap;
}
function openEditor(record) {
  pendingEdit = {record, revision: state.revision};
  $('edit-error').textContent = '';
  $('confirm-identity').checked = false;
  $('editor-title').textContent = 'Исправить · ' + (fieldValue(record, 'name') || 'Сеть Zigbee');
  const basic = ['name', 'ip', 'serial_port'].map(name => renderField({name, ...record.fields[name]}));
  const advanced = el('details'); advanced.append(el('summary', 'Дополнительные сведения и контрольные устройства'));
  for (const name of ['addon_slug', 'base_topic', 'coordinator_ieee', 'references']) advanced.append(renderField({name, ...record.fields[name]}));
  if (!record.accepted) advanced.open = true;
  $('edit-fields').replaceChildren(...basic, advanced);
  $('editor').showModal();
}
function openMigration() {
  const transition = state.transition;
  if (!transition) return;
  const preview = $('migration-preview');
  preview.replaceChildren(el('p', transition.target_mode === 'guided' ? 'Источник: прежняя конфигурация → этот экран. Разрешения, паузы и лимиты перезапусков сохраняются.' : 'Источник: этот экран → прежняя конфигурация. Управление останется выключенным, а сети — на паузе до явного разрешения в прежних настройках.'));
  for (const record of state.networks) preview.append(el('div', (fieldValue(record, 'name') || 'Сеть') + ' · управление: ' + (record.managed ? 'разрешено' : 'выключено') + ' · пауза: ' + (record.paused ? 'да' : 'нет'), 'migration-row'));
  preview.append(el('p', 'На время перехода команды восстановления заблокированы. Уже работающие приложения и сетевой интерфейс продолжают работу.'));
  $('migration-error').textContent = '';
  if (!$('migration').open) $('migration').showModal();
}
$('edit-form').addEventListener('submit', async event => {
  event.preventDefault();
  const patch = {};
  try {
    for (const name of Object.keys(names)) {
      const input = $('field-' + name), mode = $('mode-' + name).value;
      const value = name === 'references' ? JSON.parse(input.value) : name === 'serial_port' ? Number(input.value) : input.value;
      const old = pendingEdit.record.fields[name];
      if (!old || mode !== old.mode || JSON.stringify(value) !== JSON.stringify(old.value)) patch[name] = {mode, value};
    }
    if (!Object.keys(patch).length) throw new Error('Изменений нет.');
    await submitChange('networks/edit', {network_id: pendingEdit.record.network_id, patch, expected_revision: pendingEdit.revision, confirm_identity: $('confirm-identity').checked});
    $('editor').close(); pendingEdit = null; notice('Исправления сохранены.');
  } catch (error) { $('edit-error').textContent = error.message; }
});
$('editor-refresh').addEventListener('click', async () => {
  try { await loadState(); pendingEdit.revision = state.revision; $('edit-error').textContent = 'Новая версия получена. Введённые значения сохранены. Проверьте их перед повторным сохранением.'; }
  catch (error) { $('edit-error').textContent = error.message; }
});
$('broker-open').addEventListener('click', () => {
  brokerRevision = state.revision; $('broker-mode').value = state.broker?.mode || 'auto'; $('broker-server').value = state.broker?.server || '';
  $('broker-user').value = ''; $('broker-password').value = ''; $('broker-clear').checked = false; $('broker-error').textContent = '';
  $('broker-manual').hidden = $('broker-mode').value !== 'manual'; $('broker-editor').showModal();
});
$('broker-mode').addEventListener('change', () => { $('broker-manual').hidden = $('broker-mode').value !== 'manual'; });
$('broker-form').addEventListener('submit', async event => {
  event.preventDefault();
  const payload = {mode: $('broker-mode').value, expected_revision: brokerRevision};
  if (payload.mode === 'manual') { payload.server = $('broker-server').value; if ($('broker-user').value) payload.username = $('broker-user').value; payload.password = $('broker-password').value; payload.clear_password = $('broker-clear').checked; }
  try { await submitChange('broker', payload); $('broker-editor').close(); $('broker-password').value = ''; notice('Настройки MQTT сохранены.'); }
  catch (error) { $('broker-error').textContent = error.message; }
});
$('migration-commit').addEventListener('click', async () => {
  try {
    const result = await submitChange('mode/commit', {receipt: state.transition.receipt, expected_revision: state.revision});
    if (!result.verified) throw new Error('Переход пока не подтверждён. Команды заблокированы; можно повторить проверку позже.');
    $('migration').close(); notice('Переход подтверждён. Проверьте состояние сетей.');
  } catch (error) { $('migration-error').textContent = error.message; }
});
$('scan').addEventListener('click', async () => {
  try { const result = await submitChange('discovery/start', {expected_revision: state.revision}); notice(result.started ? 'Поиск запущен. Сведения появятся в течение 30 секунд.' : 'Поиск уже выполняется или ещё действует минутная пауза между поисками.'); }
  catch (error) { notice(error.message, true); }
});
document.querySelectorAll('[data-close]').forEach(node => node.addEventListener('click', () => $(node.dataset.close).close()));
(async () => { try { const session = await read('session'); csrf = session.csrf_token; renderState(session.state); } catch (error) { notice(error.message, true); } })();
setInterval(() => { if (!busy) loadState().catch(error => notice(error.message, true)); }, 15000);
