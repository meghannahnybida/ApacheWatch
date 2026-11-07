// Run with: node --test tests/test_terminal_tools.cjs
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');

const context = { window: {} };
vm.runInNewContext(readFileSync(join(__dirname, '../static/js/terminal-tools.js'), 'utf8'), context);

function controls() {
    const tools = Object.create(context.window.ApacheWatchTerminalTools.prototype);
    tools.history = [];
    tools.commandInput = { value: '' };
    tools.calls = [];
    tools.message = text => tools.reply = text;
    tools.onSearch = (query, immediate) => tools.calls.push(['find', query, immediate]);
    tools.onTail = options => tools.calls.push(['tail', { ...options }]);
    tools.onClear = () => tools.calls.push(['clear']);
    tools.toggleForm = kind => tools.calls.push(['open', kind]);
    return tools;
}

test('find forwards literal text and shell metacharacters without evaluating them', () => {
    const tools = controls();
    tools.execute('find "<script>needle.*[ $(whoami); | &</script>"');
    assert.deepEqual(tools.calls, [['find', '<script>needle.*[ $(whoami); | &</script>', true]]);
    tools.execute('find ""');
    assert.deepEqual(tools.calls.at(-1), ['find', '', true]);
    tools.execute('find');
    assert.deepEqual(tools.calls.at(-1), ['open', 'find']);
});

test('invalid tail arguments leave the source, filters, and live mode unchanged', () => {
    for (const command of ['tail /etc/passwd', 'tail error; whoami', 'tail -n 9999', 'tail -n',
        'tail access error', 'tail -x', 'tail -- -f', 'tail -n 20 -n 50', 'tail access | grep needle']) {
        const tools = controls();
        tools.execute(command);
        assert.deepEqual(tools.calls, [], command);
        assert.match(tools.reply, /Use tail|Choose -n/, command);
    }
});

test('tail accepts configured sources and bounded line counts with follow', () => {
    const tools = controls();
    tools.execute('tail -n 100 -f -- access.log');
    assert.deepEqual(tools.calls, [['tail', { source: 'access', limit: '100', live: true }]]);
    tools.execute('tail error');
    assert.deepEqual(tools.calls.at(-1), ['tail', { source: 'error', limit: undefined, live: false }]);
});

test('unknown commands and invalid clear commands cannot invoke viewer actions', () => {
    const tools = controls();
    for (const command of ['rm -rf /', 'clear; whoami', 'clear error.log', 'help && tail', 'fetch /api/metrics']) {
        tools.execute(command);
        assert.match(tools.reply, /Unknown viewer command/);
    }
    assert.deepEqual(tools.calls, []);
    tools.execute('clear');
    assert.deepEqual(tools.calls, [['clear']]);
});

test('overlong search commands fail before changing the query', () => {
    const tools = controls();
    tools.execute('find ' + 'x'.repeat(1001));
    assert.deepEqual(tools.calls, []);
    assert.match(tools.reply, /1,000 characters/);
});

test('command history is bounded, omits consecutive duplicates, and restores drafts', () => {
    const tools = controls();
    for (let i = 0; i < 60; i++) tools.execute(`find request-${i}`);
    tools.execute('find request-59');
    assert.equal(tools.history.length, 50);
    assert.equal(tools.history[0], 'find request-10');
    tools.commandInput.value = 'unfinished search';
    tools.commandInput.setSelectionRange = () => {};
    const event = key => ({ key, preventDefault() {} });
    tools.navigateHistory(event('ArrowUp'));
    assert.equal(tools.commandInput.value, 'find request-59');
    tools.navigateHistory(event('ArrowDown'));
    assert.equal(tools.commandInput.value, 'unfinished search');
});
