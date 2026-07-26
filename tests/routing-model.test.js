'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const context = vm.createContext({console});
const source = fs.readFileSync(path.join(root, 'web/assets/js/model/routing.js'), 'utf8');
vm.runInContext(`${source}\nglobalThis.__routing = {RoutingRuleModel, RoutingRulesEditor};`, context);

const {RoutingRuleModel, RoutingRulesEditor} = context.__routing;
const editor = new RoutingRulesEditor(JSON.stringify({
    // Only the template's own inbound. The panel's inbounds live in the
    // database and are appended to the running config by the server, so the
    // routing page fetches those separately.
    inbounds: [{tag: 'api'}],
    outbounds: [{tag: 'direct'}, {tag: 'blocked'}],
    routing: {
        balancers: [{tag: 'auto'}],
        rules: [{
            type: 'field',
            enabled: true,
            domain: ['geosite:cn'],
            inboundTag: ['in-1'],
            outboundTag: 'direct',
            ruleTag: 'preserve-me',
            vlessRoute: '443',
            attrs: {'User-Agent': 'regexp:^Mozilla.*'},
        }],
    },
}));

assert.deepEqual(Array.from(editor.inboundTags()), ['api']);
assert.deepEqual(Array.from(editor.outboundTags()), ['direct', 'blocked']);
assert.deepEqual(Array.from(editor.balancerTags()), ['auto']);

// A template with no inbounds section must not throw; the routing page still
// has the panel's own inbound tags to offer.
const emptyEditor = new RoutingRulesEditor(JSON.stringify({outbounds: [{tag: 'direct'}]}));
assert.deepEqual(Array.from(emptyEditor.inboundTags()), []);

const original = editor.rules[0];
const form = RoutingRuleModel.toForm(original);
form.domain = 'geosite:private,\nregexp:^example\\.com$';
form.protocol = ['http', 'tls'];
const updated = RoutingRuleModel.fromForm(form, original);

assert.deepEqual(Array.from(updated.domain), ['geosite:private', 'regexp:^example\\.com$']);
assert.deepEqual(Array.from(updated.protocol), ['http', 'tls']);
assert.equal(updated.ruleTag, 'preserve-me');
assert.equal(updated.vlessRoute, '443');
assert.equal(updated.attrs['User-Agent'], 'regexp:^Mozilla.*');
assert.equal(updated.type, 'field');
assert.equal(RoutingRuleModel.hasMatcher(updated), true);
assert.equal(RoutingRuleModel.isApiRule({outboundTag: 'api', inboundTag: ['api']}), true);

editor.rules.splice(0, 1, updated);
const serialized = JSON.parse(editor.serialize());
assert.equal(serialized.routing.rules[0].ruleTag, 'preserve-me');
assert.equal('importRules' in RoutingRulesEditor.prototype, false);
assert.equal('exportRules' in RoutingRulesEditor.prototype, false);

console.log('routing model tests passed');
