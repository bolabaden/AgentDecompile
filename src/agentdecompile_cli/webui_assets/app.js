const state = {
  meta: null,
  tools: [],
  promptDefinitions: [],
  resources: [],
  selectedTool: null,
};

const $ = (selector) => document.querySelector(selector);

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function defaultArgsFromSchema(schema) {
  const properties = schema?.properties || {};
  const result = {};
  for (const [key, definition] of Object.entries(properties)) {
    if (Object.prototype.hasOwnProperty.call(definition, 'default')) {
      result[key] = definition.default;
    }
  }
  return result;
}

function renderStats() {
  const summary = state.meta?.reference?.summary || {};
  const statsGrid = $('#statsGrid');
  const cards = [
    ['Canonical Tools', summary.canonical_tool_count ?? '-'],
    ['Advertised Tools', state.tools.length],
    ['Aliases', summary.alias_count ?? '-'],
    ['Prompts', state.promptDefinitions.length],
    ['Resources', state.resources.length],
    ['Surface Profile', summary.active_tool_surface_profile ?? '-'],
  ];
  statsGrid.innerHTML = cards.map(([label, value]) => `
    <article class="stat-card">
      <p>${label}</p>
      <h3>${value}</h3>
    </article>
  `).join('');
}

function updateMetaCard() {
  const application = state.meta?.application || {};
  $('#metaMode').textContent = application.backendMode || '-';
  $('#metaPort').textContent = application.port || '-';
  $('#metaTools').textContent = state.tools.length || 0;
  $('#metaPrograms').textContent = Object.keys(state.meta?.live?.openPrograms || {}).length;
}

function badge(text) {
  return `<span class="badge">${text}</span>`;
}

function renderToolList(filter = '') {
  const lookup = new Map((state.meta?.reference?.canonical_tools || []).map((tool) => [tool.name, tool]));
  const normalizedFilter = filter.trim().toLowerCase();
  const tools = (state.meta?.reference?.canonical_tools || []).filter((tool) => {
    const haystack = [tool.name, ...(tool.aliases || []), ...(tool.parameters || []), tool.metadata?.replacement?.join(' ') || ''].join(' ').toLowerCase();
    return haystack.includes(normalizedFilter);
  });
  $('#toolList').innerHTML = tools.map((tool) => {
    const live = state.tools.find((item) => item.name === tool.name);
    return `
      <li>
        <button data-tool-name="${tool.name}">
          <strong>${tool.name}</strong><br>
          <small>${live?.description || tool.aliases?.join(', ') || 'Canonical tool'}</small>
        </button>
      </li>
    `;
  }).join('');
  $('#toolList').querySelectorAll('button').forEach((button) => {
    button.addEventListener('click', () => selectTool(button.dataset.toolName, lookup.get(button.dataset.toolName)));
  });
}

function selectTool(name, reference) {
  const live = state.tools.find((tool) => tool.name === name);
  state.selectedTool = { name, live, reference };
  const badges = [
    reference?.advertised ? badge('Advertised') : badge('Legacy/Full Surface'),
    ...(reference?.profiles || []).map((profile) => badge(profile)),
    ...(reference?.metadata?.legacy ? [badge('Legacy-hidden')] : []),
    ...(reference?.metadata?.writes_state ? [badge('Writes state')] : []),
  ];
  $('#toolSummary').innerHTML = `
    <h3>${name}</h3>
    <div class="badge-row">${badges.join('')}</div>
    <p>${live?.description || 'Canonical tool reference entry.'}</p>
    <p><strong>Parameters:</strong> ${(reference?.parameters || Object.keys(live?.inputSchema?.properties || {})).join(', ') || 'none'}</p>
    <p><strong>Replacements:</strong> ${(reference?.metadata?.replacement || []).join(', ') || 'n/a'}</p>
  `;
  const defaults = live ? defaultArgsFromSchema(live.inputSchema) : {};
  $('#toolArgs').value = pretty(defaults);
  $('#toolHint').textContent = live ? 'Schema defaults loaded from the live backend.' : 'This canonical tool is not advertised live; use raw JSON if you still want to invoke it.';
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return response.json();
}

function renderResultsCard(title, payload) {
  const card = document.createElement('article');
  card.className = 'result-card';
  card.innerHTML = `
    <h3>${title}</h3>
    <pre>${pretty(payload)}</pre>
  `;
  $('#resultStack').prepend(card);
}

function renderDocsHub() {
  const docs = state.meta?.docs || {};
  const groups = Object.entries(docs).map(([label, links]) => `
    <section class="doc-group">
      <h3>${label}</h3>
      ${(links || []).map((link) => `
        <p><a href="${link.url}" target="_blank" rel="noreferrer">${link.title}</a><br>${link.description}</p>
      `).join('')}
    </section>
  `).join('');
  $('#docsHub').innerHTML = groups;
}

function renderPrompts() {
  const select = $('#promptSelect');
  select.innerHTML = state.promptDefinitions.map((prompt) => `<option value="${prompt.name}">${prompt.title}</option>`).join('');
  select.addEventListener('change', updatePromptSelection);
  if (state.promptDefinitions.length) {
    select.value = state.promptDefinitions[0].name;
    updatePromptSelection();
  }
}

function updatePromptSelection() {
  const prompt = state.promptDefinitions.find((item) => item.name === $('#promptSelect').value);
  if (!prompt) {
    return;
  }
  $('#promptMeta').innerHTML = `
    <p>${prompt.description}</p>
    <p><strong>Arguments:</strong> ${(prompt.arguments || []).map((argument) => argument.name).join(', ') || 'none'}</p>
  `;
  const defaults = {};
  for (const argument of (prompt.arguments || [])) {
    defaults[argument.name] = '';
  }
  $('#promptArgs').value = pretty(defaults);
}

function renderResources() {
  const select = $('#resourceSelect');
  select.innerHTML = state.resources.map((resource) => `<option value="${resource.uri}">${resource.name || resource.uri}</option>`).join('');
}

async function load() {
  state.meta = await fetchJson('/api/meta');
  state.tools = (await fetchJson('/api/tools')).tools || [];
  const promptPayload = await fetchJson('/api/prompts');
  state.promptDefinitions = promptPayload.definitions || [];
  state.resources = (await fetchJson('/api/resources')).resources || [];
  updateMetaCard();
  renderStats();
  renderToolList();
  renderPrompts();
  renderResources();
  renderDocsHub();
  if (state.tools.length) {
    selectTool(state.tools[0].name, state.meta?.reference?.canonical_tools?.find((tool) => tool.name === state.tools[0].name));
  }
}

$('#refreshAll').addEventListener('click', () => load().catch((error) => renderResultsCard('Refresh failed', { error: String(error) })));
$('#clearResults').addEventListener('click', () => { $('#resultStack').innerHTML = ''; });
$('#toolSearch').addEventListener('input', (event) => renderToolList(event.target.value));
$('#resetArgs').addEventListener('click', () => {
  if (!state.selectedTool) return;
  $('#toolArgs').value = pretty(defaultArgsFromSchema(state.selectedTool.live?.inputSchema));
});
$('#runTool').addEventListener('click', async () => {
  if (!state.selectedTool) return;
  const argumentsValue = JSON.parse($('#toolArgs').value || '{}');
  const payload = await fetchJson('/api/tools/call', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name: state.selectedTool.name, arguments: argumentsValue }),
  });
  renderResultsCard(`Tool: ${state.selectedTool.name}`, payload);
});

$('#renderPrompt').addEventListener('click', async () => {
  const argumentsValue = JSON.parse($('#promptArgs').value || '{}');
  const payload = await fetchJson('/api/prompts/render', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name: $('#promptSelect').value, arguments: argumentsValue }),
  });
  $('#promptOutput').textContent = pretty(payload);
});

$('#readResource').addEventListener('click', async () => {
  const payload = await fetchJson('/api/resources/read', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ uri: $('#resourceSelect').value }),
  });
  $('#resourceOutput').textContent = pretty(payload);
});

document.querySelectorAll('[data-tool]').forEach((button) => {
  button.addEventListener('click', () => {
    const tool = state.meta?.reference?.canonical_tools?.find((item) => item.name === button.dataset.tool);
    selectTool(button.dataset.tool, tool);
    window.scrollTo({ top: $('.panel-tools').offsetTop - 20, behavior: 'smooth' });
  });
});

load().catch((error) => renderResultsCard('Initial load failed', { error: String(error) }));