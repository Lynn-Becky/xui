// Xray outbound editor model.  This deliberately keeps the form values small,
// while retaining unknown wire fields so an edit does not discard options from
// a newer xray-core.
const OutboundProtocols = Object.freeze({
    VMESS: 'vmess', VLESS: 'vless', TROJAN: 'trojan', SHADOWSOCKS: 'shadowsocks',
    SOCKS: 'socks', HTTP: 'http', WIREGUARD: 'wireguard', HYSTERIA: 'hysteria',
    FREEDOM: 'freedom', BLACKHOLE: 'blackhole', DNS: 'dns', LOOPBACK: 'loopback',
});

const OutboundProtocolValues = Object.freeze(Object.values(OutboundProtocols));
const OutboundStreamProtocols = Object.freeze(['vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria']);
const OutboundMuxProtocols = Object.freeze(['vmess', 'vless', 'trojan', 'shadowsocks', 'socks', 'http']);

function outboundObject(value) {
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}
function outboundArray(value) { return Array.isArray(value) ? value : []; }
function outboundString(value, fallback='') { return typeof value === 'string' ? value : fallback; }
function outboundNumber(value, fallback=0) {
    const n = typeof value === 'number' ? value : Number(value);
    return Number.isFinite(n) ? n : fallback;
}
function outboundPort(value, fallback) {
    const n = outboundNumber(value, fallback);
    return Number.isInteger(n) && n > 0 && n <= 65535 ? n : fallback;
}
function outboundClone(value) { return JSON.parse(JSON.stringify(value || {})); }
function outboundMerge(base, changed) {
    return Object.assign({}, outboundObject(base), outboundObject(changed));
}
function outboundStringArray(value) {
    return Array.isArray(value) ? value.map(String).map(v => v.trim()).filter(Boolean) :
        (typeof value === 'string' ? value.split(',').map(v => v.trim()).filter(Boolean) : []);
}
function outboundPositiveIntegerArray(value) {
    return outboundArray(value).map(Number).filter(value => Number.isInteger(value) && value > 0);
}
function outboundSniffingFromWire(value) {
    const raw = outboundObject(value);
    return {
        enabled: raw.enabled === true,
        destOverride: outboundArray(raw.destOverride).map(String).filter(v => ['http', 'tls', 'quic', 'fakedns'].includes(v)),
        metadataOnly: raw.metadataOnly === true, routeOnly: raw.routeOnly === true,
        ipsExcluded: outboundStringArray(raw.ipsExcluded), domainsExcluded: outboundStringArray(raw.domainsExcluded),
    };
}
function outboundSniffingToWire(value) {
    const v = outboundObject(value);
    return {
        enabled: v.enabled === true,
        destOverride: outboundArray(v.destOverride).map(String).filter(v => ['http', 'tls', 'quic', 'fakedns'].includes(v)),
        metadataOnly: v.metadataOnly === true, routeOnly: v.routeOnly === true,
        ipsExcluded: outboundStringArray(v.ipsExcluded), domainsExcluded: outboundStringArray(v.domainsExcluded),
    };
}
function outboundDefaultSniffing() {
    return { enabled: false, destOverride: ['http', 'tls', 'quic', 'fakedns'], metadataOnly: false, routeOnly: false, ipsExcluded: [], domainsExcluded: [] };
}

function warpReservedBytes(value) {
    if (typeof value !== 'string' || !value) return [];
    try {
        let normalized = value.replace(/-/g, '+').replace(/_/g, '/');
        while (normalized.length % 4) normalized += '=';
        const decoded = atob(normalized);
        return Array.from(decoded, character => character.charCodeAt(0));
    } catch (_) {
        return [];
    }
}

// Build or refresh the dedicated WARP WireGuard outbound. WARP is an account
// integration, not an Xray protocol of its own; unknown existing fields are
// preserved so newer core options survive a rotation.
function buildWarpOutbound(existing, data, response) {
    const credentials = outboundObject(data);
    const envelope = outboundObject(response);
    const config = outboundObject(envelope.config);
    const peers = outboundArray(config.peers);
    const cloudflarePeer = outboundObject(peers[0]);
    if (!credentials.private_key || !cloudflarePeer.public_key) return null;

    const base = outboundClone(outboundObject(existing));
    const settings = outboundClone(outboundObject(base.settings));
    const configuredPeers = outboundArray(settings.peers).map(outboundClone);
    const peer = outboundObject(configuredPeers[0]);
    const endpoint = outboundObject(cloudflarePeer.endpoint);
    const addressInfo = outboundObject(outboundObject(config.interface).addresses);
    const addresses = [];
    if (outboundString(addressInfo.v4)) addresses.push(`${addressInfo.v4}/32`);
    if (outboundString(addressInfo.v6)) addresses.push(`${addressInfo.v6}/128`);

    peer.publicKey = cloudflarePeer.public_key;
    if (outboundString(endpoint.host)) peer.endpoint = endpoint.host;
    if (!outboundStringArray(peer.allowedIPs).length) peer.allowedIPs = ['0.0.0.0/0', '::/0'];
    settings.mtu = outboundNumber(settings.mtu, 1420) || 1420;
    settings.secretKey = credentials.private_key;
    if (addresses.length) settings.address = addresses;
    const reserved = warpReservedBytes(outboundString(config.client_id, outboundString(credentials.client_id)));
    if (reserved.length) settings.reserved = reserved;
    settings.domainStrategy = 'ForceIPv4v6';
    settings.peers = [peer].concat(configuredPeers.slice(1));
    settings.noKernelTun = true;
    base.tag = 'warp';
    base.protocol = 'wireguard';
    base.settings = settings;
    return base;
}

class Outbound {
    constructor(protocol=OutboundProtocols.VLESS) {
        this.protocol = OutboundProtocolValues.includes(protocol) ? protocol : OutboundProtocols.VLESS;
        this.tag = '';
        this.sendThrough = '';
        this.targetStrategy = '';
        this.settings = Outbound.defaultSettings(this.protocol);
        this.stream = null;
        this.sockopt = {};
        this.mux = { enabled: false, concurrency: 8, xudpConcurrency: 16, xudpProxyUDP443: 'reject' };
        this.raw = {};
        this._rawSettings = {};
        this._rawStream = {};
    }

    static canEnableStream(protocol) { return OutboundStreamProtocols.includes(protocol); }
    static canEnableMux(protocol, flow='', network='') {
        return OutboundMuxProtocols.includes(protocol) && !(protocol === 'vless' && flow) && network !== 'xhttp';
    }
    canEnableStream() { return Outbound.canEnableStream(this.protocol); }
    canEnableMux() { return Outbound.canEnableMux(this.protocol, this.settings.flow, this.stream && this.stream.network); }

    static defaultSettings(protocol) {
        switch (protocol) {
            case 'vmess': return { address: '', port: 443, id: '', security: 'auto' };
            case 'vless': return { address: '', port: 443, id: '', flow: '', encryption: 'none', reverseTag: '', reverseSniffing: outboundDefaultSniffing(), testpre: 0, testseed: [900, 500, 900, 256] };
            case 'trojan': return { address: '', port: 443, password: '' };
            case 'shadowsocks': return { address: '', port: 443, password: '', method: '2022-blake3-aes-128-gcm', uot: false, UoTVersion: 1 };
            case 'socks': return { address: '', port: 1080, user: '', pass: '' };
            case 'http': return { address: '', port: 8080, user: '', pass: '', headers: {} };
            case 'wireguard': return { mtu: 1420, secretKey: '', pubKey: '', address: '', domainStrategy: '', reserved: '', peers: [], noKernelTun: false };
            case 'hysteria': return { address: '', port: 443, version: 2 };
            case 'freedom': return { domainStrategy: '', redirect: '', userLevel: 0, proxyProtocol: 0, fragment: { packets: '', length: '', interval: '', maxSplit: '' }, noises: [], finalRules: [] };
            case 'blackhole': return { type: '' };
            case 'dns': return { rewriteNetwork: '', rewriteAddress: '', rewritePort: 53, userLevel: 0, rules: [] };
            case 'loopback': return { inboundTag: '', sniffing: outboundDefaultSniffing() };
            default: return {};
        }
    }

    static fromJson(json={}) {
        const raw = outboundClone(outboundObject(json));
        const result = new Outbound(outboundString(raw.protocol, 'vless'));
        result.raw = raw;
        result.tag = outboundString(raw.tag);
        result.sendThrough = outboundString(raw.sendThrough);
        result.targetStrategy = outboundString(raw.targetStrategy);
        result._rawSettings = outboundClone(outboundObject(raw.settings));
        result.settings = Outbound.settingsFromWire(result.protocol, result._rawSettings);
        result._rawStream = outboundClone(outboundObject(raw.streamSettings));
        if (Object.keys(result._rawStream).length) {
            result.stream = typeof StreamSettings !== 'undefined' ? StreamSettings.fromJson(result._rawStream) : outboundClone(result._rawStream);
            result.sockopt = outboundClone(outboundObject(result._rawStream.sockopt));
        }
        const mux = outboundObject(raw.mux);
        result.mux = {
            enabled: mux.enabled === true, concurrency: outboundNumber(mux.concurrency, 8),
            xudpConcurrency: outboundNumber(mux.xudpConcurrency, 16),
            xudpProxyUDP443: ['reject', 'allow', 'skip'].includes(mux.xudpProxyUDP443) ? mux.xudpProxyUDP443 : 'reject',
        };
        if (result.protocol === 'hysteria') result.ensureHysteriaStream();
        return result;
    }

    static settingsFromWire(protocol, raw) {
        const s = outboundObject(raw), server = outboundObject(outboundArray(s.servers)[0]), user = outboundObject(outboundArray(server.users)[0]);
        switch (protocol) {
            case 'vmess': { const v = outboundObject(outboundArray(s.vnext)[0]), u = outboundObject(outboundArray(v.users)[0]); return { address: outboundString(v.address), port: outboundPort(v.port, 443), id: outboundString(u.id), security: ['aes-128-gcm', 'chacha20-poly1305', 'auto'].includes(u.security) ? u.security : 'auto' }; }
            case 'vless': { const v = outboundObject(outboundArray(s.vnext)[0]), u = outboundObject(outboundArray(v.users)[0]), reverse = outboundObject(s.reverse), testseed = outboundPositiveIntegerArray(s.testseed); return { address: outboundString(v.address, outboundString(s.address)), port: outboundPort(v.port || s.port, 443), id: outboundString(u.id, outboundString(s.id)), flow: outboundString(u.flow, outboundString(s.flow)), encryption: outboundString(u.encryption, outboundString(s.encryption, 'none')) || 'none', reverseTag: outboundString(reverse.tag), reverseSniffing: reverse.tag ? outboundSniffingFromWire(reverse.sniffing) : outboundDefaultSniffing(), testpre: outboundNumber(s.testpre), testseed: testseed.length === 4 ? testseed : [900, 500, 900, 256] }; }
            case 'trojan': return { address: outboundString(server.address), port: outboundPort(server.port, 443), password: outboundString(server.password) };
            case 'shadowsocks': return { address: outboundString(server.address), port: outboundPort(server.port, 443), password: outboundString(server.password), method: outboundString(server.method, '2022-blake3-aes-128-gcm'), uot: server.uot === true, UoTVersion: outboundNumber(server.UoTVersion, 1) };
            case 'socks': return { address: outboundString(server.address), port: outboundPort(server.port, 1080), user: outboundString(user.user), pass: outboundString(user.pass) };
            case 'http': return { address: outboundString(server.address), port: outboundPort(server.port, 8080), user: outboundString(user.user), pass: outboundString(user.pass), headers: outboundClone(outboundObject(s.headers)) };
            case 'wireguard': { const secretKey = outboundString(s.secretKey); return { mtu: outboundNumber(s.mtu, 1420), secretKey, pubKey: secretKey && typeof Wireguard !== 'undefined' ? Wireguard.generateKeypair(secretKey).publicKey : '', address: outboundArray(s.address).map(String).join(','), domainStrategy: outboundString(s.domainStrategy), reserved: outboundArray(s.reserved).map(String).join(','), peers: outboundArray(s.peers).map(p => { p = outboundObject(p); const allowedIPs = outboundStringArray(p.allowedIPs); return { publicKey: outboundString(p.publicKey), psk: outboundString(p.preSharedKey), allowedIPs: allowedIPs.length ? allowedIPs : ['0.0.0.0/0', '::/0'], endpoint: outboundString(p.endpoint), keepAlive: outboundNumber(p.keepAlive) }; }), noKernelTun: s.noKernelTun === true }; }
            case 'hysteria': return { address: outboundString(s.address), port: outboundPort(s.port, 443), version: 2 };
            case 'freedom': return Object.assign(Outbound.defaultSettings('freedom'), outboundClone(s), { domainStrategy: outboundString(s.targetStrategy, outboundString(s.domainStrategy)), fragment: Object.assign(Outbound.defaultSettings('freedom').fragment, outboundObject(s.fragment)), noises: outboundArray(s.noises), finalRules: outboundArray(s.finalRules) });
            case 'blackhole': return { type: ['none', 'http'].includes(outboundObject(s.response).type) ? s.response.type : '' };
            case 'dns': return { rewriteNetwork: ['udp', 'tcp'].includes(s.rewriteNetwork || s.network) ? (s.rewriteNetwork || s.network) : '', rewriteAddress: outboundString(s.rewriteAddress, outboundString(s.address)), rewritePort: outboundPort(s.rewritePort || s.port, 53), userLevel: outboundNumber(s.userLevel), rules: outboundArray(s.rules).map(r => { r = outboundObject(r); return { action: ['direct', 'drop', 'return', 'hijack'].includes(r.action) ? r.action : 'direct', qType: Array.isArray(r.qType) ? r.qType.join(',') : String(r.qType || r.qtype || ''), domain: Array.isArray(r.domain) ? r.domain.join(',') : outboundString(r.domain), rCode: outboundNumber(r.rCode) }; }) };
            case 'loopback': return { inboundTag: outboundString(s.inboundTag), sniffing: outboundSniffingFromWire(s.sniffing) };
            default: return Outbound.defaultSettings(protocol);
        }
    }

    ensureHysteriaStream() {
        if (!this.stream) this.stream = typeof StreamSettings !== 'undefined' ? new StreamSettings('hysteria', 'tls') : {};
        this.stream.network = 'hysteria'; this.stream.security = 'tls';
        if (this.stream.tls) this.stream.tls.alpn = ['h3'];
        if (this.stream.hysteria) this.stream.hysteria.version = 2;
    }

    settingsToWire() {
        const s = outboundObject(this.settings);
        switch (this.protocol) {
            case 'vmess': return { vnext: [{ address: s.address, port: s.port, users: [{ id: s.id, security: s.security }] }] };
            case 'vless': { const r = { address: s.address, port: s.port, id: s.id, flow: s.flow, encryption: s.encryption || 'none' }; if (s.reverseTag) r.reverse = { tag: s.reverseTag, sniffing: s.reverseSniffing && s.reverseSniffing.enabled ? outboundSniffingToWire(s.reverseSniffing) : {} }; if (s.flow === 'xtls-rprx-vision') { if (s.testpre > 0) r.testpre = s.testpre; const testseed = outboundPositiveIntegerArray(s.testseed); if (testseed.length === 4) r.testseed = testseed; } return r; }
            case 'trojan': return { servers: [{ address: s.address, port: s.port, password: s.password }] };
            case 'shadowsocks': return { servers: [{ address: s.address, port: s.port, password: s.password, method: s.method, uot: s.uot === true, UoTVersion: s.UoTVersion }] };
            case 'socks': case 'http': { const r = { servers: [{ address: s.address, port: s.port, users: s.user ? [{ user: s.user, pass: s.pass }] : [] }] }; if (this.protocol === 'http' && Object.keys(outboundObject(s.headers)).length) r.headers = s.headers; return r; }
            case 'wireguard': return { mtu: s.mtu || undefined, secretKey: s.secretKey, address: outboundStringArray(s.address), domainStrategy: s.domainStrategy || undefined, reserved: outboundStringArray(s.reserved).map(Number).filter(Number.isFinite), peers: outboundArray(s.peers).map(p => { p = outboundObject(p); const allowedIPs = outboundStringArray(p.allowedIPs); return { publicKey: p.publicKey, preSharedKey: p.psk || undefined, allowedIPs: allowedIPs.length ? allowedIPs : ['0.0.0.0/0', '::/0'], endpoint: p.endpoint, keepAlive: p.keepAlive || undefined }; }), noKernelTun: s.noKernelTun === true };
            case 'hysteria': return { address: s.address, port: s.port, version: 2 };
            case 'freedom': { const fragment = outboundObject(s.fragment), enabled = fragment.length || fragment.interval || fragment.maxSplit; return { domainStrategy: s.domainStrategy || undefined, redirect: s.redirect || undefined, userLevel: s.userLevel || undefined, proxyProtocol: s.proxyProtocol || undefined, fragment: enabled ? Object.fromEntries(Object.entries(fragment).filter(([, v]) => v !== '' && v != null)) : undefined, noises: outboundArray(s.noises).length ? s.noises : undefined, finalRules: outboundArray(s.finalRules).length ? s.finalRules.map(r => { r = outboundObject(r); return { action: r.action, network: r.network || undefined, port: r.port || undefined, ip: outboundStringArray(r.ip), blockDelay: r.action === 'block' ? r.blockDelay || undefined : undefined }; }) : undefined }; }
            case 'blackhole': return { response: s.type ? { type: s.type } : undefined };
            case 'dns': { const r = {}; if (s.rewriteNetwork) r.rewriteNetwork = s.rewriteNetwork; if (s.rewriteAddress) r.rewriteAddress = s.rewriteAddress; if (s.rewritePort) r.rewritePort = s.rewritePort; if (s.userLevel) r.userLevel = s.userLevel; if (outboundArray(s.rules).length) r.rules = s.rules.map(rule => { rule = outboundObject(rule); const q = outboundString(rule.qType).trim(); const v = { action: ['direct', 'drop', 'return', 'hijack'].includes(rule.action) ? rule.action : 'direct' }; if (q) v.qType = /^\d+$/.test(q) ? Number(q) : q; const domains = outboundStringArray(rule.domain); if (domains.length) v.domain = domains; if (rule.rCode > 0) v.rCode = rule.rCode; return v; }); return r; }
            case 'loopback': { const r = { inboundTag: s.inboundTag || undefined }; if (s.sniffing && s.sniffing.enabled) r.sniffing = outboundSniffingToWire(s.sniffing); return r; }
            default: return {};
        }
    }

    managedSettingsKeys() {
        switch (this.protocol) {
            case 'vmess': return ['vnext'];
            case 'vless': return ['address', 'port', 'id', 'flow', 'encryption', 'vnext', 'reverse', 'testpre', 'testseed'];
            case 'trojan': case 'shadowsocks': case 'socks': return ['servers'];
            case 'http': return ['servers', 'headers'];
            case 'wireguard': return ['mtu', 'secretKey', 'address', 'domainStrategy', 'reserved', 'peers', 'noKernelTun'];
            case 'hysteria': return ['address', 'port', 'version'];
            case 'freedom': return ['domainStrategy', 'targetStrategy', 'redirect', 'userLevel', 'proxyProtocol', 'fragment', 'noises', 'finalRules'];
            case 'blackhole': return ['response'];
            case 'dns': return ['rewriteNetwork', 'network', 'rewriteAddress', 'address', 'rewritePort', 'port', 'userLevel', 'rules'];
            case 'loopback': return ['inboundTag', 'sniffing'];
            default: return [];
        }
    }

    toJson() {
        const result = outboundClone(this.raw);
        result.protocol = this.protocol;
        const preservedSettings = outboundClone(this._rawSettings);
        this.managedSettingsKeys().forEach(key => delete preservedSettings[key]);
        result.settings = outboundMerge(preservedSettings, this.settingsToWire());
        if (this.tag) result.tag = this.tag; else delete result.tag;
        if (this.targetStrategy) result.targetStrategy = this.targetStrategy; else delete result.targetStrategy;
        if (this.sendThrough) result.sendThrough = this.sendThrough; else delete result.sendThrough;
        let stream = this.stream;
        if (this.protocol === 'hysteria') { this.ensureHysteriaStream(); stream = this.stream; }
        if (stream && (this.canEnableStream() || Object.keys(this.sockopt).length)) {
            const streamWire = stream.toJson ? stream.toJson() : outboundClone(stream);
            const merged = outboundMerge(this._rawStream, streamWire);
            if (Object.keys(this.sockopt).length) merged.sockopt = outboundClone(this.sockopt);
            if (this.protocol === 'hysteria') { merged.network = 'hysteria'; merged.security = 'tls'; merged.hysteriaSettings = outboundMerge(merged.hysteriaSettings, { version: 2 }); merged.tlsSettings = outboundMerge(merged.tlsSettings, { alpn: ['h3'] }); }
            result.streamSettings = merged;
        } else if (Object.keys(this.sockopt).length) {
            // Xray accepts sockopt for otherwise transport-less outbounds such
            // as HTTP, SOCKS and WireGuard.  Do not manufacture a transport.
            result.streamSettings = outboundMerge(this._rawStream, {sockopt: outboundClone(this.sockopt)});
        } else delete result.streamSettings;
        if (this.mux && this.mux.enabled && this.canEnableMux()) result.mux = outboundClone(this.mux); else delete result.mux;
        return result;
    }

    toString(format=true) { return JSON.stringify(this.toJson(), null, format ? 2 : 0); }
}
