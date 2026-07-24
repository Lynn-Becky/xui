'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const context = vm.createContext({
    URL,
    URLSearchParams,
    Map,
    atob: value => Buffer.from(value, 'base64').toString('binary'),
    console,
    location: {hostname: 'panel.example.test'},
    window: {
        crypto: globalThis.crypto,
        btoa: value => Buffer.from(value, 'binary').toString('base64'),
        atob: value => Buffer.from(value, 'base64').toString('binary'),
    },
});

vm.runInContext(fs.readFileSync(path.join(root, 'web/assets/js/util/utils.js'), 'utf8'), context);
const modelSource = fs.readFileSync(path.join(root, 'web/assets/js/model/xray.js'), 'utf8');
vm.runInContext(`${modelSource}\nglobalThis.__xray = {Inbound, StreamSettings, Sniffing, Protocols, SSMethods, Wireguard};`, context);
const outboundSource = fs.readFileSync(path.join(root, 'web/assets/js/model/outbound.js'), 'utf8');
vm.runInContext(`${outboundSource}\nglobalThis.__outbound = {Outbound, OutboundProtocolValues, buildWarpOutbound};`, context);
const modelsSource = fs.readFileSync(path.join(root, 'web/assets/js/model/models.js'), 'utf8');
vm.runInContext(`${modelsSource}\nglobalThis.__models = {DBInbound};`, context);

const {Inbound, StreamSettings, Sniffing, Protocols, SSMethods, Wireguard} = context.__xray;
const {Outbound, OutboundProtocolValues, buildWarpOutbound} = context.__outbound;
const {DBInbound} = context.__models;

const defaultSniffing = new Sniffing();
assert.equal(defaultSniffing.enabled, false);
assert.deepEqual(Array.from(defaultSniffing.destOverride), ['http', 'tls', 'quic', 'fakedns']);
const parsedDisabledSniffing = Sniffing.fromJson({enabled: false});
assert.equal(parsedDisabledSniffing.enabled, false);
assert.deepEqual(Array.from(parsedDisabledSniffing.destOverride), ['http', 'tls', 'quic', 'fakedns']);

const generatedVmess = new Inbound(443, '', Protocols.VMESS);
assert.match(generatedVmess.settings.vmesses[0].id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
assert.match(generatedVmess.settings.vmesses[0].email, /^[a-z0-9]{10}$/);

const generatedVless = new Inbound(443, '', Protocols.VLESS);
assert.match(generatedVless.settings.vlesses[0].id, /^[0-9a-f-]{36}$/);
assert.match(generatedVless.settings.vlesses[0].email, /^[a-z0-9]{10}$/);

const generatedTrojan = new Inbound(443, '', Protocols.TROJAN);
assert.equal(generatedTrojan.settings.clients[0].password.length, 10);
assert.match(generatedTrojan.settings.clients[0].email, /^[a-z0-9]{10}$/);

const generatedMixed = new Inbound(443, '', Protocols.MIXED);
assert.match(generatedMixed.settings.accounts[0].user, /^[a-z0-9]{8}$/);
assert.match(generatedMixed.settings.accounts[0].pass, /^[a-z0-9]{12}$/);

const generatedHttp = new Inbound(443, '', Protocols.HTTP);
assert.match(generatedHttp.settings.accounts[0].user, /^[a-z0-9]{8}$/);
assert.match(generatedHttp.settings.accounts[0].pass, /^[a-z0-9]{12}$/);

const generatedShadowsocks = new Inbound(443, '', Protocols.SHADOWSOCKS);
generatedShadowsocks.settings.addClient();
assert.match(generatedShadowsocks.settings.clients[0].email, /^[a-z0-9]{10}$/);
assert.equal(generatedShadowsocks.settings.clients[0].password.length, 43);

const generatedHysteria = new Inbound(443, '', Protocols.HYSTERIA);
generatedHysteria.settings.addClient();
assert.match(generatedHysteria.settings.clients[0].auth, /^[a-z0-9]{16}$/);
assert.match(generatedHysteria.settings.clients[0].email, /^[a-z0-9]{10}$/);

const generatedWireguard = new Inbound(443, '', Protocols.WIREGUARD);
generatedWireguard.settings.addClient();
assert.match(generatedWireguard.settings.clients[0].email, /^[a-z0-9]{10}$/);
assert.equal(generatedWireguard.settings.clients[0].privateKey.length, 44);

const inbound = new Inbound(443, '', Protocols.VLESS);
inbound.stream.network = 'xhttp';
inbound.stream.security = 'reality';
inbound.stream.xhttp.path = '/api';
inbound.stream.xhttp.sessionIDPlacement = 'header';
inbound.stream.xhttp.sessionIDKey = 'X-Session';
inbound.stream.xhttp.enableXmux = true;
inbound.stream.reality.target = 'example.com:443';
inbound.stream.reality.serverNames = ['example.com'];
inbound.settings.encryption = 'none';

const serialized = JSON.parse(inbound.stream.toString());
assert.equal(serialized.network, 'xhttp');
assert.equal(serialized.security, 'reality');
assert.equal(serialized.xhttpSettings.sessionIDPlacement, 'header');
assert.equal(serialized.xhttpSettings.sessionIDKey, 'X-Session');
assert.equal(serialized.xhttpSettings.xmux.maxConnections, 6);
assert.equal(serialized.realitySettings.target, 'example.com:443');

const concurrencyXmux = StreamSettings.fromJson({
    network: 'xhttp',
    xhttpSettings: {xmux: {maxConcurrency: '16-32'}},
});
const concurrencyXmuxJson = concurrencyXmux.toJson().xhttpSettings.xmux;
assert.equal(concurrencyXmuxJson.maxConcurrency, '16-32');
assert.equal(concurrencyXmuxJson.maxConnections, 0);

const connectionXmux = StreamSettings.fromJson({
    network: 'xhttp',
    xhttpSettings: {xmux: {maxConnections: 6}},
});
const connectionXmuxJson = connectionXmux.toJson().xhttpSettings.xmux;
assert.equal(connectionXmuxJson.maxConnections, 6);
assert.equal(Object.hasOwn(connectionXmuxJson, 'maxConcurrency'), false);

inbound.stream.reality.settings.publicKey = 'public-key';
inbound.stream.reality.settings.fingerprint = 'chrome';
inbound.stream.reality.shortIds = ['abcd'];
inbound.settings.vlesses[0].flow = 'xtls-rprx-vision';
const link = new URL(inbound.genVLESSLink('203.0.113.10', 'modern'));
assert.equal(link.searchParams.get('type'), 'xhttp');
assert.equal(link.searchParams.get('security'), 'reality');
assert.equal(link.searchParams.get('encryption'), 'none');
assert.equal(link.searchParams.get('pbk'), 'public-key');
assert.equal(link.searchParams.get('sid'), 'abcd');
assert.equal(link.searchParams.get('sni'), 'example.com');

const legacyRealitySni = StreamSettings.fromJson({
    security: 'reality',
    realitySettings: {
        serverNames: ['allowed.example'],
        settings: {serverName: 'legacy.example', spiderX: '/'},
    },
});
assert.deepEqual(Array.from(legacyRealitySni.reality.serverNames), ['legacy.example', 'allowed.example']);
assert.equal(legacyRealitySni.reality.settings.serverName, '');
assert.equal(legacyRealitySni.reality.settings.spiderX, '/');

const current = StreamSettings.fromJson({
    method: 'xhttp',
    security: 'reality',
    xhttpSettings: {sessionIDPlacement: 'cookie', sessionIDKey: 'sid'},
    realitySettings: {target: 'current.example:443', serverNames: 'current.example'},
});
assert.equal(current.network, 'xhttp');
assert.equal(current.xhttp.sessionIDPlacement, 'cookie');
assert.equal(current.xhttp.sessionIDKey, 'sid');
assert.equal(current.reality.target, 'current.example:443');
assert.deepEqual(Array.from(current.reality.serverNames), ['current.example']);
assert.equal(current.reality.settings.spiderX, '/');

const unsupportedLegacy = StreamSettings.fromJson({
    network: 'xhttp',
    security: 'xtls',
    xtlsSettings: {serverName: 'legacy.example'},
    xhttpSettings: {sessionPlacement: 'cookie', sessionKey: 'sid'},
    realitySettings: {dest: 'legacy.example:443'},
});
assert.equal(unsupportedLegacy.security, 'xtls');
assert.equal(unsupportedLegacy.tls.server, '');
assert.equal(unsupportedLegacy.xhttp.sessionIDPlacement, '');
assert.equal(unsupportedLegacy.xhttp.sessionIDKey, '');
assert.equal(unsupportedLegacy.reality.target, '');

const tls = StreamSettings.fromJson({
    network: 'ws',
    security: 'tls',
    wsSettings: {path: '/ws', host: 'cdn.example'},
    tlsSettings: {
        serverName: 'cdn.example',
        minVersion: '1.2',
        maxVersion: '1.3',
        alpn: ['h2', 'http/1.1'],
        settings: {fingerprint: 'firefox', pinnedPeerCertSha256: ['pin']},
    },
});
assert.equal(tls.ws.host, 'cdn.example');
assert.equal(tls.tls.settings.fingerprint, 'firefox');
assert.deepEqual(Array.from(tls.tls.settings.pinnedPeerCertSha256), ['pin']);

const futureStream = StreamSettings.fromJson({
    network: 'xhttp',
    security: 'tls',
    futureTopLevel: {keep: true},
    xhttpSettings: {
        path: '/future',
        futureTransportField: {keep: true},
        xmux: {maxConnections: 6, futureXmuxField: 'keep'},
    },
    tlsSettings: {
        serverName: 'future.example',
        futureTlsField: {keep: true},
        settings: {fingerprint: 'chrome', futureTlsSetting: 'keep'},
    },
});
futureStream.xhttp.path = '/edited';
const futureStreamJson = JSON.parse(JSON.stringify(futureStream.toJson()));
assert.equal(futureStreamJson.xhttpSettings.path, '/edited');
assert.deepEqual(futureStreamJson.futureTopLevel, {keep: true});
assert.deepEqual(futureStreamJson.xhttpSettings.futureTransportField, {keep: true});
assert.equal(futureStreamJson.xhttpSettings.xmux.futureXmuxField, 'keep');
assert.deepEqual(futureStreamJson.tlsSettings.futureTlsField, {keep: true});
assert.equal(futureStreamJson.tlsSettings.settings.futureTlsSetting, 'keep');
futureStream.network = 'httpupgrade';
const switchedFutureStreamJson = JSON.parse(JSON.stringify(futureStream.toJson()));
assert.equal(Object.hasOwn(switchedFutureStreamJson, 'xhttpSettings'), false);
assert.equal(switchedFutureStreamJson.httpupgradeSettings.path, '/');

const shadowsocks = Inbound.Settings.getSettings(Protocols.SHADOWSOCKS);
assert.equal(shadowsocks.method, SSMethods.BLAKE3_AES_256_GCM);
assert.ok(shadowsocks.password.length > 20);

const mixed = Inbound.Settings.getSettings(Protocols.MIXED);
assert.equal(mixed.auth, 'password');
assert.equal(mixed.accounts.length, 1);
assert.deepEqual(
    JSON.parse(JSON.stringify(mixed.toJson())),
    {
        auth: 'password',
        accounts: [{user: mixed.accounts[0].user, pass: mixed.accounts[0].pass}],
        udp: false,
        ip: '127.0.0.1',
    },
);
mixed.auth = 'noauth';
assert.equal(Object.hasOwn(mixed.toJson(), 'accounts'), true);
assert.equal(mixed.toJson().accounts, undefined);

const tunnel = Inbound.Settings.getSettings(Protocols.TUNNEL);
tunnel.rewriteAddress = '127.0.0.1';
tunnel.rewritePort = 8443;
tunnel.newPortMapSource = '443';
tunnel.newPortMapDestination = '8443';
tunnel.addPortMap();
assert.deepEqual(JSON.parse(JSON.stringify(tunnel.toJson())), {
    rewriteAddress: '127.0.0.1',
    rewritePort: 8443,
    portMap: {443: '8443'},
    allowedNetwork: 'tcp,udp',
    followRedirect: false,
});
tunnel.rewritePort = 0;
assert.equal(JSON.parse(JSON.stringify(tunnel.toJson())).rewritePort, undefined);

const wireguard = Inbound.Settings.getSettings(Protocols.WIREGUARD);
assert.match(wireguard.secretKey, /^[A-Za-z0-9+/]{43}=$/);
assert.match(wireguard.publicKey, /^[A-Za-z0-9+/]{43}=$/);
wireguard.secretKey = 'server-private-key';
wireguard.addClient();
wireguard.clients[0].privateKey = 'client-private-key';
wireguard.clients[0].publicKey = 'client-public-key';
wireguard.clients[0].allowedIPs = ['10.0.0.2/32'];
wireguard.clients[0].email = 'device@example.test';
const wireguardJson = JSON.parse(JSON.stringify(wireguard.toJson()));
assert.equal(wireguardJson.secretKey, 'server-private-key');
assert.equal(wireguardJson.clients[0].privateKey, 'client-private-key');
assert.deepEqual(Array.from(wireguardJson.clients[0].allowedIPs), ['10.0.0.2/32']);
const wireguardKeypair = Wireguard.generateKeypair();
assert.match(wireguardKeypair.privateKey, /^[A-Za-z0-9+/]{43}=$/);
assert.match(wireguardKeypair.publicKey, /^[A-Za-z0-9+/]{43}=$/);
assert.equal(Wireguard.generateKeypair(wireguardKeypair.privateKey).publicKey, wireguardKeypair.publicKey);

const hysteria = new Inbound(8443, '', Protocols.HYSTERIA);
assert.equal(hysteria.stream.network, 'hysteria');
assert.equal(hysteria.stream.security, 'tls');
assert.deepEqual(Array.from(hysteria.stream.tls.alpn), ['h3']);
const hysteriaAlpn = hysteria.stream.tls.alpn;
hysteria.toJson();
assert.equal(hysteria.stream.tls.alpn, hysteriaAlpn);
assert.equal(hysteria.stream.tls.settings.fingerprint, '');
assert.equal(hysteria.stream.tls.certs.length, 1);
assert.equal(hysteria.stream.tls.certs[0].useFile, true);
hysteria.settings.version = 1;
hysteria.stream.hysteria.version = 1;
hysteria.stream.security = 'none';
hysteria.stream.tls.alpn = ['h2'];
hysteria.stream.hysteria.masquerade = {type: 'string', statusCode: 200, content: 'ok', headers: {}};
const hysteriaJson = JSON.parse(JSON.stringify(hysteria.toJson()));
assert.equal(hysteriaJson.streamSettings.network, 'hysteria');
assert.equal(hysteriaJson.streamSettings.security, 'tls');
assert.deepEqual(Array.from(hysteriaJson.streamSettings.tlsSettings.alpn), ['h3']);
assert.equal(hysteriaJson.streamSettings.hysteriaSettings.version, 2);
assert.equal(hysteriaJson.settings.version, 2);
assert.equal(hysteriaJson.streamSettings.hysteriaSettings.masquerade.type, 'string');
assert.equal(hysteriaJson.settings.clients.length, 0);
assert.equal(Inbound.Settings.fromJson(Protocols.HYSTERIA, {version: 1}).version, 2);
const savedHysteria = Inbound.fromJson({
    port: 443,
    protocol: Protocols.HYSTERIA,
    settings: {version: 2, clients: []},
    streamSettings: {
        network: 'hysteria',
        security: 'tls',
        tlsSettings: {
            alpn: ['h3'],
            settings: {fingerprint: 'firefox'},
            certificates: [{certificateFile: '/etc/xray/cert.pem', keyFile: '/etc/xray/key.pem'}],
        },
        hysteriaSettings: {version: 2, udpIdleTimeout: 60},
    },
    sniffing: {enabled: true},
});
const savedHysteriaJson = JSON.parse(JSON.stringify(savedHysteria.toJson()));
assert.equal(savedHysteriaJson.streamSettings.tlsSettings.settings.fingerprint, 'firefox');
assert.equal(savedHysteriaJson.streamSettings.tlsSettings.certificates[0].certificateFile, '/etc/xray/cert.pem');

hysteria.settings.addClient();
hysteria.settings.clients[0].auth = 'auth@example.test';
hysteria.stream.tls.server = 'hy.example.test';
hysteria.stream.tls.settings.fingerprint = 'chrome';
hysteria.stream.tls.settings.echConfigList = 'ech-value';
hysteria.stream.tls.settings.verifyPeerCertByName = 'cert.example.test';
hysteria.stream.tls.settings.pinnedPeerCertSha256 = ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='];
const hysteriaLink = new URL(hysteria.genLink('2001:db8::1', 'hy2 share'));
assert.equal(hysteriaLink.protocol, 'hysteria2:');
assert.equal(decodeURIComponent(hysteriaLink.username), 'auth@example.test');
assert.equal(hysteriaLink.hostname, '[2001:db8::1]');
assert.equal(hysteriaLink.searchParams.get('security'), 'tls');
assert.equal(hysteriaLink.searchParams.get('sni'), 'hy.example.test');
assert.equal(hysteriaLink.searchParams.get('alpn'), 'h3');
assert.equal(hysteriaLink.searchParams.get('fp'), 'chrome');
assert.equal(hysteriaLink.searchParams.get('ech'), 'ech-value');
assert.equal(hysteriaLink.searchParams.get('vcn'), 'cert.example.test');
assert.equal(hysteriaLink.searchParams.get('pinSHA256'), '0'.repeat(64));

const wireguardShare = new Inbound(51820, '', Protocols.WIREGUARD);
const wireguardClientKeypair = Wireguard.generateKeypair();
wireguardShare.settings.clients.push(new Inbound.WireguardSettings.Client(
    wireguardClientKeypair.privateKey,
    wireguardClientKeypair.publicKey,
    'preshared-key',
    ['10.0.0.2/32', 'fd00::2/128'],
    25,
    'device@example.test',
    true,
));
wireguardShare.settings.dns = '9.9.9.9';
const wireguardLink = new URL(wireguardShare.genLink('2001:db8::2', 'wg share'));
assert.equal(wireguardLink.protocol, 'wireguard:');
assert.equal(decodeURIComponent(wireguardLink.username), wireguardClientKeypair.privateKey);
assert.equal(wireguardLink.hostname, '[2001:db8::2]');
assert.equal(wireguardLink.searchParams.get('publickey'), wireguardShare.settings.publicKey);
assert.equal(wireguardLink.searchParams.get('address'), '10.0.0.2/32,fd00::2/128');
assert.equal(wireguardLink.searchParams.get('mtu'), '1420');
const wireguardConfig = wireguardShare.genWireguardConfig('2001:db8::2');
assert.ok(wireguardConfig.includes(`PrivateKey = ${wireguardClientKeypair.privateKey}`));
assert.ok(wireguardConfig.includes('Address = 10.0.0.2/32, fd00::2/128'));
assert.ok(wireguardConfig.includes('DNS = 9.9.9.9'));
assert.ok(wireguardConfig.includes(`PublicKey = ${wireguardShare.settings.publicKey}`));
assert.ok(wireguardConfig.includes('PresharedKey = preshared-key'));
assert.ok(wireguardConfig.includes('AllowedIPs = 0.0.0.0/0, ::/0'));
assert.ok(wireguardConfig.includes('Endpoint = [2001:db8::2]:51820'));
assert.ok(wireguardConfig.includes('PersistentKeepalive = 25'));

const hysteriaDB = new DBInbound({
    port: hysteria.port, protocol: Protocols.HYSTERIA, settings: hysteria.settings.toString(),
    streamSettings: hysteria.stream.toString(), sniffing: '{}', remark: 'hy2', listen: '203.0.113.1',
});
assert.equal(hysteriaDB.hasLink(), true);
assert.equal(hysteriaDB.shareEntries()[0].label, hysteria.settings.clients[0].email);
const wireguardDB = new DBInbound({
    port: wireguardShare.port, protocol: Protocols.WIREGUARD, settings: wireguardShare.settings.toString(),
    streamSettings: '{}', sniffing: '{}', remark: 'wg', listen: '203.0.113.2',
});
assert.equal(wireguardDB.hasLink(), true);
assert.equal(wireguardDB.hasClientConfig(), true);
assert.equal(wireguardDB.shareEntries()[0].label, 'device@example.test');
const invalidWireguardDB = new DBInbound({
    port: 51820, protocol: Protocols.WIREGUARD, settings: 'null',
    streamSettings: '{}', sniffing: '{}', remark: 'invalid', listen: '203.0.113.3',
});
assert.equal(invalidWireguardDB.shareEntries().length, 0);
assert.equal(invalidWireguardDB.hasLink(), false);
assert.equal(invalidWireguardDB.hasClientConfig(), false);

for (const protocol of [Protocols.HTTP, Protocols.MIXED, Protocols.TUNNEL, Protocols.WIREGUARD]) {
    assert.equal(new Inbound(443, '', protocol).canEnableStream(), false);
}
assert.equal(hysteria.canEnableStream(), true);
const inboundsTemplate = fs.readFileSync(path.join(root, 'web/html/xui/inbounds.html'), 'utf8');
assert.equal(
    (inboundsTemplate.match(/streamSettings: inbound\.canEnableStream\(\) \? inbound\.stream\.toString\(\) : '\{\}',/g) || []).length,
    2,
);
const inboundFormTemplate = fs.readFileSync(path.join(root, 'web/html/xui/form/inbound.html'), 'utf8');
assert.ok(inboundFormTemplate.includes('{{template "form/hysteriaStream"}}'));
assert.ok(inboundFormTemplate.includes('{{template "form/tlsSettings"}}'));
for (const tab of ['basic', 'protocol', 'transport', 'security', 'sniffing', 'advanced']) {
    assert.ok(inboundFormTemplate.includes(`key="${tab}"`));
}
assert.ok(inboundFormTemplate.includes('@change="inboundTabChange"'));
assert.ok(inboundFormTemplate.includes('[[ inModal.inboundJsonPreview ]]'));
assert.ok(!inboundFormTemplate.includes('[[ inbound.toString() ]]'));

assert.deepEqual(Array.from(OutboundProtocolValues), [
    'vmess', 'vless', 'trojan', 'shadowsocks', 'socks', 'http', 'wireguard',
    'hysteria', 'freedom', 'blackhole', 'dns', 'loopback',
]);
assert.equal(OutboundProtocolValues.includes('mixed'), false);
assert.equal(OutboundProtocolValues.includes('mtproto'), false);

const outboundVmess = Outbound.fromJson({
    protocol: 'vmess', tag: 'proxy', unknownTop: {keep: true},
    settings: {vnext: [{address: 'vm.example', port: 443, users: [{id: 'uuid', security: 'auto'}]}], unknownSetting: 'keep'},
});
const outboundVmessJson = JSON.parse(JSON.stringify(outboundVmess.toJson()));
assert.equal(outboundVmessJson.settings.vnext[0].address, 'vm.example');
assert.equal(outboundVmessJson.settings.unknownSetting, 'keep');
assert.deepEqual(outboundVmessJson.unknownTop, {keep: true});

const outboundVless = new Outbound('vless');
outboundVless.settings.address = 'vless.example';
outboundVless.settings.port = 8443;
outboundVless.settings.id = 'uuid';
outboundVless.settings.flow = 'xtls-rprx-vision';
outboundVless.settings.testpre = 3;
outboundVless.settings.testseed = [1, 2, 3, 4];
const outboundVlessJson = JSON.parse(JSON.stringify(outboundVless.toJson()));
assert.equal(outboundVlessJson.settings.address, 'vless.example');
assert.equal(outboundVlessJson.settings.encryption, 'none');
assert.equal(outboundVlessJson.settings.testpre, 3);
assert.deepEqual(Array.from(outboundVlessJson.settings.testseed), [1, 2, 3, 4]);
outboundVless.settings.testseed = [1, -2, 3, 4];
assert.equal(Object.hasOwn(outboundVless.toJson().settings, 'testseed'), false);
const parsedOutboundVless = Outbound.fromJson({
    protocol: 'vless',
    settings: {address: 'vless.example', port: 443, id: 'uuid', flow: 'xtls-rprx-vision', testseed: [1, '2', 3, 4]},
});
assert.deepEqual(Array.from(parsedOutboundVless.settings.testseed), [1, 2, 3, 4]);

const outboundHttp = new Outbound('http');
outboundHttp.settings.address = 'http.example';
outboundHttp.settings.user = 'u';
outboundHttp.settings.pass = 'p';
outboundHttp.settings.headers = {'X-Test': '1'};
outboundHttp.sockopt = {tcpFastOpen: true};
outboundHttp.mux.enabled = true;
const outboundHttpJson = JSON.parse(JSON.stringify(outboundHttp.toJson()));
assert.deepEqual(outboundHttpJson.settings.servers[0].users, [{user: 'u', pass: 'p'}]);
assert.equal(outboundHttpJson.settings.headers['X-Test'], '1');
assert.equal(outboundHttpJson.streamSettings.sockopt.tcpFastOpen, true);
assert.equal(outboundHttpJson.mux.enabled, true);

const outboundWireguard = new Outbound('wireguard');
outboundWireguard.settings.secretKey = 'private';
outboundWireguard.settings.pubKey = 'ui-only';
outboundWireguard.settings.address = '10.0.0.2/32, fd00::2/128';
outboundWireguard.settings.reserved = '1, 2, 3';
outboundWireguard.settings.peers = [{publicKey: 'peer', psk: 'psk', allowedIPs: ['0.0.0.0/0'], endpoint: 'wg.example:51820', keepAlive: 25}];
const outboundWireguardJson = JSON.parse(JSON.stringify(outboundWireguard.toJson()));
assert.equal(Object.hasOwn(outboundWireguardJson.settings, 'pubKey'), false);
assert.deepEqual(Array.from(outboundWireguardJson.settings.address), ['10.0.0.2/32', 'fd00::2/128']);
assert.deepEqual(Array.from(outboundWireguardJson.settings.reserved), [1, 2, 3]);
assert.equal(outboundWireguardJson.settings.peers[0].preSharedKey, 'psk');
const outboundWireguardDefaults = Outbound.fromJson({
    protocol: 'wireguard', settings: {peers: [{publicKey: 'peer', endpoint: 'wg.example:51820'}]},
});
assert.deepEqual(Array.from(outboundWireguardDefaults.settings.peers[0].allowedIPs), ['0.0.0.0/0', '::/0']);

const outboundHysteria = new Outbound('hysteria');
outboundHysteria.ensureHysteriaStream();
outboundHysteria.stream.security = 'none';
outboundHysteria.stream.tls.alpn = ['h2'];
outboundHysteria.stream.hysteria.version = 1;
const outboundHysteriaJson = JSON.parse(JSON.stringify(outboundHysteria.toJson()));
assert.equal(outboundHysteriaJson.settings.version, 2);
assert.equal(outboundHysteriaJson.streamSettings.network, 'hysteria');
assert.equal(outboundHysteriaJson.streamSettings.security, 'tls');
assert.deepEqual(Array.from(outboundHysteriaJson.streamSettings.tlsSettings.alpn), ['h3']);
assert.equal(outboundHysteriaJson.streamSettings.hysteriaSettings.version, 2);
assert.equal(new Outbound('vless').canEnableMux(), true);
outboundVless.stream = new StreamSettings('xhttp');
assert.equal(outboundVless.canEnableMux(), false);

const warpOutbound = buildWarpOutbound(
    {tag: 'warp', protocol: 'wireguard', settings: {mtu: 1280, peers: [{allowedIPs: ['10.0.0.0/8'], keepAlive: 25}], custom: true}},
    {private_key: 'warp-private', client_id: 'AQID'},
    {config: {interface: {addresses: {v4: '172.16.0.2', v6: '2606:4700::2'}}, peers: [{public_key: 'warp-public', endpoint: {host: 'engage.cloudflareclient.com:2408'}}]}},
);
assert.equal(warpOutbound.protocol, 'wireguard');
assert.equal(warpOutbound.tag, 'warp');
assert.equal(warpOutbound.settings.secretKey, 'warp-private');
assert.deepEqual(Array.from(warpOutbound.settings.address), ['172.16.0.2/32', '2606:4700::2/128']);
assert.deepEqual(Array.from(warpOutbound.settings.reserved), [1, 2, 3]);
assert.deepEqual(Array.from(warpOutbound.settings.peers[0].allowedIPs), ['10.0.0.0/8']);
assert.equal(warpOutbound.settings.peers[0].endpoint, 'engage.cloudflareclient.com:2408');
assert.equal(warpOutbound.settings.domainStrategy, 'ForceIPv4v6');
assert.equal(warpOutbound.settings.noKernelTun, true);
assert.equal(warpOutbound.settings.custom, true);

const settingTemplate = fs.readFileSync(path.join(root, 'web/html/xui/setting.html'), 'utf8');
assert.ok(settingTemplate.includes('template.outbounds = this.outboundItems'));
assert.ok(settingTemplate.includes('parseOutboundTemplate()'));
assert.ok(settingTemplate.includes('JSON 高级编辑'));

const realityTemplate = fs.readFileSync(path.join(root, 'web/html/xui/form/reality_settings.html'), 'utf8');
assert.ok(realityTemplate.includes('label="SNI"'));
assert.equal(realityTemplate.includes('REALITY 客户端参数'), false);
assert.equal(realityTemplate.includes('label="serverName"'), false);
assert.equal(realityTemplate.includes('regenerateRealitySpiderX'), false);

console.log('xray model serialization tests passed');
