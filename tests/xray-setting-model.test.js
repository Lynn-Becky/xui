'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const context = vm.createContext({console});
const source = fs.readFileSync(path.join(root, 'web/assets/js/model/xray-setting.js'), 'utf8');
vm.runInContext(`${source}\nglobalThis.__settings = {XraySettingsEditor};`, context);
const {XraySettingsEditor} = context.__settings;

const editor = new XraySettingsEditor(JSON.stringify({
    customTopLevel: {keep: true},
    outbounds: [{protocol: 'freedom', settings: {redirect: '127.0.0.1:80'}}, {protocol: 'blackhole', tag: 'blocked'}],
    routing: {rules: [{type: 'field', outboundTag: 'blocked'}]},
}));

assert.equal(editor.freedomStrategy(), 'AsIs');
editor.setFreedomStrategy('UseIPv4');
editor.setRoutingDomainStrategy('IPIfNonMatch');
editor.setLogField('loglevel', 'info');
editor.setLogField('dnsLog', true);

let parsed = JSON.parse(editor.serialize());
assert.equal(parsed.outbounds.length, 2, 'legacy untagged Freedom outbound should be reused');
assert.equal(parsed.outbounds[0].settings.redirect, '127.0.0.1:80');
assert.equal(parsed.outbounds[0].settings.domainStrategy, 'UseIPv4');
assert.equal(parsed.routing.domainStrategy, 'IPIfNonMatch');
assert.equal(parsed.routing.rules[0].outboundTag, 'blocked');
assert.equal(parsed.customTopLevel.keep, true);
assert.equal(parsed.log.loglevel, 'info');
assert.equal(parsed.log.dnsLog, true);

editor.toggleDns(true);
assert.equal(editor.dnsSettings().tag, 'dns_inbound');
assert.deepEqual(Array.from(editor.dnsSettings().servers), []);
editor.setDnsField('clientIp', '203.0.113.10');
editor.setHosts([
    {domain: 'domain:example.com', values: ['1.1.1.1']},
    {domain: 'domain:multi.example', values: ['1.0.0.1', '1.1.1.1']},
    {domain: '', values: ['ignored']},
]);
editor.setDnsServers(['1.1.1.1']);
editor.setFakeDnsRows([{ipPool: '198.18.0.0/15', poolSize: 65535}]);
parsed = JSON.parse(editor.serialize());
assert.equal(parsed.dns.clientIp, '203.0.113.10');
assert.equal(parsed.dns.hosts['domain:example.com'], '1.1.1.1');
assert.deepEqual(Array.from(parsed.dns.hosts['domain:multi.example']), ['1.0.0.1', '1.1.1.1']);
assert.equal(parsed.dns.servers[0], '1.1.1.1');
assert.equal(parsed.fakedns[0].ipPool, '198.18.0.0/15');
assert.equal('fakeDns' in parsed, false);

const plainServer = XraySettingsEditor.dnsServerFromForm(
    XraySettingsEditor.dnsServerToForm('localhost'), null,
);
assert.equal(plainServer, 'localhost');

const serverForm = XraySettingsEditor.dnsServerToForm({
    address: 'https://1.1.1.1/dns-query',
    port: 443,
    expectIPs: ['geoip:cloudflare'],
    extensionField: 'keep-me',
});
serverForm.finalQuery = true;
const objectServer = XraySettingsEditor.dnsServerFromForm(serverForm, {
    address: 'https://1.1.1.1/dns-query', extensionField: 'keep-me',
});
assert.equal(objectServer.address, 'https://1.1.1.1/dns-query');
assert.equal('port' in objectServer, false, 'encrypted DNS addresses should omit port');
assert.deepEqual(Array.from(objectServer.expectedIPs), ['geoip:cloudflare']);
assert.equal(objectServer.finalQuery, true);
assert.equal(objectServer.extensionField, 'keep-me');

editor.toggleDns(false);
parsed = JSON.parse(editor.serialize());
assert.equal('dns' in parsed, false);
assert.equal('fakedns' in parsed, false);

assert.throws(() => new XraySettingsEditor('[]'), /JSON 对象/);
assert.throws(() => new XraySettingsEditor('{'), /有效 JSON/);

console.log('xray setting model tests passed');
