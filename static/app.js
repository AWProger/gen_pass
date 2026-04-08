document.getElementById('generate').addEventListener('click', async () => {
    const response = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            length: parseInt(document.getElementById('length').value),
            digits: document.getElementById('digits').checked,
            symbols: document.getElementById('symbols').checked,
            site: document.getElementById('site').value,
            email: document.getElementById('email').value,
            login: document.getElementById('login').value
        })
    });
    const data = await response.json();
    document.getElementById('result').value = data.password;
});

async function loadHistory() {
    const response = await fetch('/api/history');
    const data = await response.json();
    const list = document.getElementById('history-list');
    list.innerHTML = '';
    data.forEach(entry => {
        list.innerHTML += `<div class="entry">
            <p>Сайт: ${entry.site} | Логин: ${entry.login} | Пароль: ${entry.password}
            <button onclick="deleteRecord('${entry.id}')">Удалить</button></p>
        </div>`;
    });
}
async function search() {
    const query = document.getElementById('search-input').value;
    const response = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query })
    });
    const data = await response.json();
    const list = document.getElementById('search-results');
    list.innerHTML = '';
    data.forEach(entry => {
        list.innerHTML += `<div class="entry">
            <p>ID: ${entry.id} | Сайт: ${entry.site} | Логин: ${entry.login} | Пароль: ${entry.password}</p>
        </div>`;
    });
}
async function deleteRecord(id) {
    await fetch(`/api/delete/${id}`, { method: 'DELETE' });
    loadHistory();
}
