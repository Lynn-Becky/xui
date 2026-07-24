const Protocols = {
    VMESS: 'vmess',
    VLESS: 'vless',
    TROJAN: 'trojan',
    SHADOWSOCKS: 'shadowsocks',
    HTTP: 'http',
    MIXED: 'mixed',
    TUNNEL: 'tunnel',
    WIREGUARD: 'wireguard',
    HYSTERIA: 'hysteria',
};

const VmessMethods = {
    AES_128_GCM: 'aes-128-gcm',
    CHACHA20_POLY1305: 'chacha20-poly1305',
    AUTO: 'auto',
    NONE: 'none',
};

const SSMethods = {
    CHACHA20_POLY1305: 'chacha20-poly1305',
    CHACHA20_IETF_POLY1305: 'chacha20-ietf-poly1305',
    XCHACHA20_IETF_POLY1305: 'xchacha20-ietf-poly1305',
    AES_256_GCM: 'aes-256-gcm',
    AES_128_GCM: 'aes-128-gcm',
    BLAKE3_AES_128_GCM: '2022-blake3-aes-128-gcm',
    BLAKE3_AES_256_GCM: '2022-blake3-aes-256-gcm',
    BLAKE3_CHACHA20_POLY1305: '2022-blake3-chacha20-poly1305',
};

const RULE_IP = {
    PRIVATE: 'geoip:private',
    CN: 'geoip:cn',
};

const RULE_DOMAIN = {
    ADS: 'geosite:category-ads',
    ADS_ALL: 'geosite:category-ads-all',
    CN: 'geosite:cn',
    GOOGLE: 'geosite:google',
    FACEBOOK: 'geosite:facebook',
    SPEEDTEST: 'geosite:speedtest',
};

const FLOW_CONTROL = {
    VISION: 'xtls-rprx-vision',
    VISION_UDP443: 'xtls-rprx-vision-udp443',
};

Object.freeze(Protocols);
Object.freeze(VmessMethods);
Object.freeze(SSMethods);
Object.freeze(RULE_IP);
Object.freeze(RULE_DOMAIN);
Object.freeze(FLOW_CONTROL);

class XrayCommonClass {

    static mergeJson(original={}, managed={}) {
        const source = original && typeof original === 'object' && !Array.isArray(original) ? original : {};
        const result = ObjectUtil.deepClone(source);
        for (const [key, value] of Object.entries(managed)) {
            if (value === undefined) {
                delete result[key];
            } else if (value && typeof value === 'object' && !Array.isArray(value)) {
                result[key] = XrayCommonClass.mergeJson(result[key], value);
            } else {
                result[key] = ObjectUtil.deepClone(value);
            }
        }
        return result;
    }

    static toJsonArray(arr) {
        return arr.map(obj => obj.toJson());
    }

    static fromJson() {
        return new XrayCommonClass();
    }

    toJson() {
        return this;
    }

    toString(format=true) {
        return format ? JSON.stringify(this.toJson(), null, 2) : JSON.stringify(this.toJson());
    }

    static toHeaders(v2Headers) {
        let newHeaders = [];
        if (v2Headers) {
            Object.keys(v2Headers).forEach(key => {
                let values = v2Headers[key];
                if (typeof(values) === 'string') {
                    newHeaders.push({ name: key, value: values });
                } else {
                    for (let i = 0; i < values.length; ++i) {
                        newHeaders.push({ name: key, value: values[i] });
                    }
                }
            });
        }
        return newHeaders;
    }

    static toV2Headers(headers, arr=true) {
        let v2Headers = {};
        for (let i = 0; i < headers.length; ++i) {
            let name = headers[i].name;
            let value = headers[i].value;
            if (ObjectUtil.isEmpty(name) || ObjectUtil.isEmpty(value)) {
                continue;
            }
            if (!(name in v2Headers)) {
                v2Headers[name] = arr ? [value] : value;
            } else {
                if (arr) {
                    v2Headers[name].push(value);
                } else {
                    v2Headers[name] = value;
                }
            }
        }
        return v2Headers;
    }

    static toStringArray(value) {
        if (Array.isArray(value)) {
            return value.map(item => String(item).trim()).filter(item => item !== '');
        }
        if (typeof value === 'string') {
            return value.split(',').map(item => item.trim()).filter(item => item !== '');
        }
        return [];
    }
}

class TcpStreamSettings extends XrayCommonClass {
    constructor(acceptProxyProtocol=false,
                type='none',
                request=new TcpStreamSettings.TcpRequest(),
                response=new TcpStreamSettings.TcpResponse(),
                ) {
        super();
        this.acceptProxyProtocol = acceptProxyProtocol;
        this.type = type;
        this.request = request;
        this.response = response;
    }

    static fromJson(json={}) {
        let header = json.header;
        if (!header) {
            header = {};
        }
        return new TcpStreamSettings(json.acceptProxyProtocol,
            header.type,
            TcpStreamSettings.TcpRequest.fromJson(header.request),
            TcpStreamSettings.TcpResponse.fromJson(header.response),
        );
    }

    toJson() {
        return {
            acceptProxyProtocol: this.acceptProxyProtocol,
            header: {
                type: this.type,
                request: this.type === 'http' ? this.request.toJson() : undefined,
                response: this.type === 'http' ? this.response.toJson() : undefined,
            },
        };
    }
}

TcpStreamSettings.TcpRequest = class extends XrayCommonClass {
    constructor(version='1.1',
                method='GET',
                path=['/'],
                headers=[],
    ) {
        super();
        this.version = version;
        this.method = method;
        this.path = path.length === 0 ? ['/'] : path;
        this.headers = headers;
    }

    addPath(path) {
        this.path.push(path);
    }

    removePath(index) {
        this.path.splice(index, 1);
    }

    addHeader(name, value) {
        this.headers.push({ name: name, value: value });
    }

    getHeader(name) {
        for (const header of this.headers) {
            if (header.name.toLowerCase() === name.toLowerCase()) {
                return header.value;
            }
        }
        return null;
    }

    removeHeader(index) {
        this.headers.splice(index, 1);
    }

    static fromJson(json={}) {
        return new TcpStreamSettings.TcpRequest(
            json.version,
            json.method,
            json.path,
            XrayCommonClass.toHeaders(json.headers),
        );
    }

    toJson() {
        return {
            method: this.method,
            path: ObjectUtil.clone(this.path),
            headers: XrayCommonClass.toV2Headers(this.headers),
        };
    }
};

TcpStreamSettings.TcpResponse = class extends XrayCommonClass {
    constructor(version='1.1',
                status='200',
                reason='OK',
                headers=[],
    ) {
        super();
        this.version = version;
        this.status = status;
        this.reason = reason;
        this.headers = headers;
    }

    addHeader(name, value) {
        this.headers.push({ name: name, value: value });
    }

    removeHeader(index) {
        this.headers.splice(index, 1);
    }

    static fromJson(json={}) {
        return new TcpStreamSettings.TcpResponse(
            json.version,
            json.status,
            json.reason,
            XrayCommonClass.toHeaders(json.headers),
        );
    }

    toJson() {
        return {
            version: this.version,
            status: this.status,
            reason: this.reason,
            headers: XrayCommonClass.toV2Headers(this.headers),
        };
    }
};

class KcpStreamSettings extends XrayCommonClass {
    constructor(mtu=1350, tti=20,
                uplinkCapacity=5,
                downlinkCapacity=20,
                congestion=false,
                readBufferSize=2,
                writeBufferSize=2,
                type='none',
                seed=RandomUtil.randomSeq(10),
                ) {
        super();
        this.mtu = mtu;
        this.tti = tti;
        this.upCap = uplinkCapacity;
        this.downCap = downlinkCapacity;
        this.congestion = congestion;
        this.readBuffer = readBufferSize;
        this.writeBuffer = writeBufferSize;
        this.type = type;
        this.seed = seed;
    }

    static fromJson(json={}) {
        return new KcpStreamSettings(
            json.mtu,
            json.tti,
            json.uplinkCapacity,
            json.downlinkCapacity,
            json.congestion,
            json.readBufferSize,
            json.writeBufferSize,
            ObjectUtil.isEmpty(json.header) ? 'none' : json.header.type,
            json.seed,
        );
    }

    toJson() {
        return {
            mtu: this.mtu,
            tti: this.tti,
            uplinkCapacity: this.upCap,
            downlinkCapacity: this.downCap,
            congestion: this.congestion,
            readBufferSize: this.readBuffer,
            writeBufferSize: this.writeBuffer,
            header: {
                type: this.type,
            },
            seed: this.seed,
        };
    }
}

class WsStreamSettings extends XrayCommonClass {
    constructor(acceptProxyProtocol=false, path='/', host='', headers=[], heartbeatPeriod=0) {
        super();
        this.acceptProxyProtocol = acceptProxyProtocol;
        this.path = path;
        this.host = host;
        this.headers = headers;
        this.heartbeatPeriod = heartbeatPeriod;
    }

    addHeader(name, value) {
        this.headers.push({ name: name, value: value });
    }

    getHeader(name) {
        for (const header of this.headers) {
            if (header.name.toLowerCase() === name.toLowerCase()) {
                return header.value;
            }
        }
        return null;
    }

    removeHeader(index) {
        this.headers.splice(index, 1);
    }

    static fromJson(json={}) {
        return new WsStreamSettings(
            !!json.acceptProxyProtocol,
            json.path === undefined ? '/' : json.path,
            json.host || '',
            XrayCommonClass.toHeaders(json.headers),
            json.heartbeatPeriod || 0,
        );
    }

    toJson() {
        return {
            acceptProxyProtocol: this.acceptProxyProtocol,
            path: this.path,
            host: this.host,
            headers: XrayCommonClass.toV2Headers(this.headers, false),
            heartbeatPeriod: this.heartbeatPeriod,
        };
    }
}

class HttpStreamSettings extends XrayCommonClass {
    constructor(path='/', host=['']) {
        super();
        this.path = path;
        this.host = host.length === 0 ? [''] : host;
    }

    addHost(host) {
        this.host.push(host);
    }

    removeHost(index) {
        this.host.splice(index, 1);
    }

    static fromJson(json={}) {
        return new HttpStreamSettings(json.path, json.host);
    }

    toJson() {
        let host = [];
        for (let i = 0; i < this.host.length; ++i) {
            if (!ObjectUtil.isEmpty(this.host[i])) {
                host.push(this.host[i]);
            }
        }
        return {
            path: this.path,
            host: host,
        }
    }
}

class QuicStreamSettings extends XrayCommonClass {
    constructor(security=VmessMethods.NONE,
                key='', type='none') {
        super();
        this.security = security;
        this.key = key;
        this.type = type;
    }

    static fromJson(json={}) {
        return new QuicStreamSettings(
            json.security,
            json.key,
            json.header ? json.header.type : 'none',
        );
    }

    toJson() {
        return {
            security: this.security,
            key: this.key,
            header: {
                type: this.type,
            }
        }
    }
}

class GrpcStreamSettings extends XrayCommonClass {
    constructor(serviceName='', authority='', multiMode=false) {
        super();
        this.serviceName = serviceName;
        this.authority = authority;
        this.multiMode = multiMode;
    }

    static fromJson(json={}) {
        return new GrpcStreamSettings(
            json.serviceName || '',
            json.authority || '',
            !!json.multiMode,
        );
    }

    toJson() {
        return {
            serviceName: this.serviceName,
            authority: this.authority,
            multiMode: this.multiMode,
        }
    }
}

class HttpUpgradeStreamSettings extends XrayCommonClass {
    constructor(acceptProxyProtocol=false, path='/', host='', headers=[]) {
        super();
        this.acceptProxyProtocol = acceptProxyProtocol;
        this.path = path;
        this.host = host;
        this.headers = headers;
    }

    addHeader(name, value) {
        this.headers.push({name: name, value: value});
    }

    removeHeader(index) {
        this.headers.splice(index, 1);
    }

    static fromJson(json={}) {
        return new HttpUpgradeStreamSettings(
            !!json.acceptProxyProtocol,
            json.path === undefined ? '/' : json.path,
            json.host || '',
            XrayCommonClass.toHeaders(json.headers),
        );
    }

    toJson() {
        return {
            acceptProxyProtocol: this.acceptProxyProtocol,
            path: this.path,
            host: this.host,
            headers: XrayCommonClass.toV2Headers(this.headers, false),
        };
    }
}

class XHttpStreamSettings extends XrayCommonClass {
    constructor(json={}) {
        super();
        this.path = '/';
        this.host = '';
        this.mode = 'auto';
        this.xPaddingBytes = '100-1000';
        this.xPaddingObfsMode = false;
        this.xPaddingKey = '';
        this.xPaddingHeader = '';
        this.xPaddingPlacement = '';
        this.xPaddingMethod = '';
        this.sessionIDPlacement = '';
        this.sessionIDKey = '';
        this.sessionIDTable = '';
        this.sessionIDLength = '';
        this.seqPlacement = '';
        this.seqKey = '';
        this.uplinkDataPlacement = '';
        this.uplinkDataKey = '';
        this.scMaxEachPostBytes = '';
        this.scMaxBufferedPosts = 30;
        this.scMinPostsIntervalMs = '';
        this.scStreamUpServerSecs = '20-80';
        this.serverMaxHeaderBytes = 0;
        this.uplinkHTTPMethod = '';
        this.noSSEHeader = false;
        const loadedXmux = json.xmux && typeof json.xmux === 'object' ? json.xmux : null;
        const xmuxDefaults = {
            maxConcurrency: loadedXmux ? '16-32' : '',
            maxConnections: loadedXmux ? 0 : 6,
            cMaxReuseTimes: 0,
            hMaxRequestTimes: '600-900',
            hMaxReusableSecs: '1800-3000',
            hKeepAlivePeriod: 0,
        };
        this.enableXmux = !!loadedXmux;
        this.xmux = xmuxDefaults;
        this.headers = [];
        ObjectUtil.cloneProps(this, json);
        this.enableXmux = !!loadedXmux;
        this.xmux = Object.assign({}, xmuxDefaults, loadedXmux || {});
        this.headers = XrayCommonClass.toHeaders(json.headers);
    }

    addHeader(name, value) {
        this.headers.push({name: name, value: value});
    }

    removeHeader(index) {
        this.headers.splice(index, 1);
    }

    static fromJson(json={}) {
        return new XHttpStreamSettings(json);
    }

    toJson() {
        const packetMode = this.mode === 'packet-up' || this.mode === 'auto';
        const streamUpMode = this.mode === 'stream-up';
        const xmux = Object.assign({}, this.xmux);
        const rangeUpper = value => {
            const parts = String(value || '').split('-');
            const result = Number(parts[parts.length - 1]);
            return Number.isFinite(result) ? result : 0;
        };
        if (rangeUpper(xmux.maxConnections) > 0 && rangeUpper(xmux.maxConcurrency) > 0) {
            delete xmux.maxConcurrency;
        }
        return {
            path: this.path,
            host: this.host,
            mode: this.mode,
            xPaddingBytes: this.xPaddingBytes,
            xPaddingObfsMode: this.xPaddingObfsMode || undefined,
            xPaddingKey: this.xPaddingObfsMode && this.xPaddingKey ? this.xPaddingKey : undefined,
            xPaddingHeader: this.xPaddingObfsMode && this.xPaddingHeader ? this.xPaddingHeader : undefined,
            xPaddingPlacement: this.xPaddingObfsMode && this.xPaddingPlacement ? this.xPaddingPlacement : undefined,
            xPaddingMethod: this.xPaddingObfsMode && this.xPaddingMethod ? this.xPaddingMethod : undefined,
            sessionIDPlacement: this.sessionIDPlacement || undefined,
            sessionIDKey: this.sessionIDKey || undefined,
            sessionIDTable: this.sessionIDTable || undefined,
            sessionIDLength: this.sessionIDTable && this.sessionIDLength ? this.sessionIDLength : undefined,
            seqPlacement: this.seqPlacement || undefined,
            seqKey: this.seqKey || undefined,
            uplinkDataPlacement: packetMode && this.uplinkDataPlacement ? this.uplinkDataPlacement : undefined,
            uplinkDataKey: packetMode && this.uplinkDataKey ? this.uplinkDataKey : undefined,
            scMaxEachPostBytes: packetMode && this.scMaxEachPostBytes ? this.scMaxEachPostBytes : undefined,
            scMaxBufferedPosts: packetMode ? this.scMaxBufferedPosts : undefined,
            scMinPostsIntervalMs: packetMode && this.scMinPostsIntervalMs && this.scMinPostsIntervalMs !== '30' ? this.scMinPostsIntervalMs : undefined,
            scStreamUpServerSecs: streamUpMode && this.scStreamUpServerSecs ? this.scStreamUpServerSecs : undefined,
            serverMaxHeaderBytes: this.serverMaxHeaderBytes || undefined,
            uplinkHTTPMethod: this.uplinkHTTPMethod || undefined,
            noSSEHeader: this.noSSEHeader || undefined,
            headers: XrayCommonClass.toV2Headers(this.headers, false),
            xmux: this.enableXmux ? xmux : undefined,
        };
    }
}

// The panel exposes Xray's current Hysteria2 implementation under the core's
// protocol string, `hysteria`.
class HysteriaStreamSettings extends XrayCommonClass {
    constructor(json={}) {
        super();
        this.version = 2;
        this.auth = '';
        this.udpIdleTimeout = 60;
        this.masquerade = undefined;
        ObjectUtil.cloneProps(this, json);
        this.version = 2;
        this.udpIdleTimeout = Number.isInteger(this.udpIdleTimeout) ? this.udpIdleTimeout : 60;
    }

    static fromJson(json={}) {
        return new HysteriaStreamSettings(json);
    }

    toJson() {
        return {
            version: 2,
            auth: this.auth || undefined,
            udpIdleTimeout: this.udpIdleTimeout,
            masquerade: this.masquerade && typeof this.masquerade === 'object' ? this.masquerade : undefined,
        };
    }
}

class RealityStreamSettings extends XrayCommonClass {
    constructor(json={}) {
        super();
        this.show = false;
        this.xver = 0;
        this.target = '';
        this.serverNames = [];
        this.privateKey = '';
        this.minClientVer = '';
        this.maxClientVer = '';
        this.maxTimediff = 0;
        this.shortIds = [];
        this.mldsa65Seed = '';
        this.masterKeyLog = '';
        const defaultSettings = {
            publicKey: '',
            fingerprint: 'chrome',
            serverName: '',
            spiderX: '/',
            mldsa65Verify: '',
        };
        this.settings = defaultSettings;
        ObjectUtil.cloneProps(this, json);
        this.target = json.target || '';
        this.serverNames = XrayCommonClass.toStringArray(json.serverNames);
        this.shortIds = XrayCommonClass.toStringArray(json.shortIds);
        this.settings = Object.assign({}, defaultSettings, json.settings || {});
        const legacyServerName = String(this.settings.serverName || '').trim();
        if (legacyServerName) {
            this.serverNames = [
                legacyServerName,
                ...this.serverNames.filter(serverName => serverName !== legacyServerName),
            ];
            this.settings.serverName = '';
        }
    }

    static fromJson(json={}) {
        return new RealityStreamSettings(json);
    }

    toJson() {
        return {
            show: this.show,
            xver: this.xver,
            target: this.target,
            serverNames: XrayCommonClass.toStringArray(this.serverNames),
            privateKey: this.privateKey,
            minClientVer: this.minClientVer,
            maxClientVer: this.maxClientVer,
            maxTimediff: this.maxTimediff,
            shortIds: XrayCommonClass.toStringArray(this.shortIds),
            mldsa65Seed: this.mldsa65Seed,
            masterKeyLog: this.masterKeyLog || undefined,
            settings: Object.assign({}, this.settings),
        };
    }
}

class TlsStreamSettings extends XrayCommonClass {
    constructor(serverName='',
                certificates=[new TlsStreamSettings.Cert()], alpn=['h2', 'http/1.1']) {
        super();
        this.server = serverName;
        this.certs = certificates;
        this.minVersion = '1.2';
        this.maxVersion = '1.3';
        this.cipherSuites = '';
        this.rejectUnknownSni = false;
        this.disableSystemRoot = false;
        this.enableSessionResumption = false;
        this.echServerKeys = '';
        this.curvePreferences = [];
        this.masterKeyLog = '';
        this.settings = {
            fingerprint: 'chrome',
            echConfigList: '',
            pinnedPeerCertSha256: [],
            verifyPeerCertByName: '',
        };
        this.alpn = XrayCommonClass.toStringArray(alpn);
    }

    addCert(cert) {
        this.certs.push(cert);
    }

    removeCert(index) {
        this.certs.splice(index, 1);
    }

    static fromJson(json={}) {
        let certs;
        if (!ObjectUtil.isEmpty(json.certificates)) {
            certs = json.certificates.map(cert => TlsStreamSettings.Cert.fromJson(cert));
        }

        const tls = new TlsStreamSettings(
            json.serverName || '',
            certs,
            json.alpn,
        );
        ObjectUtil.cloneProps(tls, json);
        tls.server = json.serverName || '';
        tls.certs = certs || [new TlsStreamSettings.Cert()];
        tls.alpn = json.alpn === undefined ? ['h2', 'http/1.1'] : XrayCommonClass.toStringArray(json.alpn);
        tls.curvePreferences = XrayCommonClass.toStringArray(json.curvePreferences);
        tls.settings = Object.assign({}, tls.settings, json.settings || {});
        tls.settings.pinnedPeerCertSha256 = XrayCommonClass.toStringArray(tls.settings.pinnedPeerCertSha256);
        return tls;
    }

    toJson() {
        return {
            serverName: this.server,
            minVersion: this.minVersion,
            maxVersion: this.maxVersion,
            cipherSuites: this.cipherSuites,
            rejectUnknownSni: this.rejectUnknownSni,
            disableSystemRoot: this.disableSystemRoot,
            enableSessionResumption: this.enableSessionResumption,
            certificates: TlsStreamSettings.toJsonArray(this.certs),
            alpn: XrayCommonClass.toStringArray(this.alpn),
            echServerKeys: this.echServerKeys,
            curvePreferences: XrayCommonClass.toStringArray(this.curvePreferences),
            masterKeyLog: this.masterKeyLog || undefined,
            settings: {
                fingerprint: this.settings.fingerprint,
                echConfigList: this.settings.echConfigList,
                pinnedPeerCertSha256: XrayCommonClass.toStringArray(this.settings.pinnedPeerCertSha256),
                verifyPeerCertByName: this.settings.verifyPeerCertByName,
            },
        };
    }
}

TlsStreamSettings.Cert = class extends XrayCommonClass {
    constructor(useFile=true, certificateFile='', keyFile='', certificate='', key='',
                ocspStapling=0, oneTimeLoading=false, usage='encipherment', buildChain=false) {
        super();
        this.useFile = useFile;
        this.certFile = certificateFile;
        this.keyFile = keyFile;
        this.cert = certificate instanceof Array ? certificate.join('\n') : certificate;
        this.key = key instanceof Array ? key.join('\n') : key;
        this.ocspStapling = ocspStapling;
        this.oneTimeLoading = oneTimeLoading;
        this.usage = usage;
        this.buildChain = buildChain;
    }

    static fromJson(json={}) {
        if ('certificateFile' in json && 'keyFile' in json) {
            return new TlsStreamSettings.Cert(
                true,
                json.certificateFile,
                json.keyFile,
                '', '',
                json.ocspStapling || 0,
                !!json.oneTimeLoading,
                json.usage || 'encipherment',
                !!json.buildChain,
            );
        } else {
            return new TlsStreamSettings.Cert(
                false, '', '',
                json.certificate || '',
                json.key || '',
                json.ocspStapling || 0,
                !!json.oneTimeLoading,
                json.usage || 'encipherment',
                !!json.buildChain,
            );
        }
    }

    toJson() {
        if (this.useFile) {
            return {
                certificateFile: this.certFile,
                keyFile: this.keyFile,
                ocspStapling: this.ocspStapling,
                oneTimeLoading: this.oneTimeLoading,
                usage: this.usage,
                buildChain: this.buildChain,
            };
        } else {
            return {
                certificate: this.cert.split('\n'),
                key: this.key.split('\n'),
                ocspStapling: this.ocspStapling,
                oneTimeLoading: this.oneTimeLoading,
                usage: this.usage,
                buildChain: this.buildChain,
            };
        }
    }
};

class StreamSettings extends XrayCommonClass {
    constructor(network='tcp',
                security='none',
                tlsSettings=new TlsStreamSettings(),
                tcpSettings=new TcpStreamSettings(),
                kcpSettings=new KcpStreamSettings(),
                wsSettings=new WsStreamSettings(),
                httpSettings=new HttpStreamSettings(),
                quicSettings=new QuicStreamSettings(),
                grpcSettings=new GrpcStreamSettings(),
                httpUpgradeSettings=new HttpUpgradeStreamSettings(),
                xhttpSettings=new XHttpStreamSettings(),
                realitySettings=new RealityStreamSettings(),
                hysteriaSettings=new HysteriaStreamSettings(),
                ) {
        super();
        this.network = network;
        this.security = security;
        this.tls = tlsSettings;
        this.tcp = tcpSettings;
        this.kcp = kcpSettings;
        this.ws = wsSettings;
        this.http = httpSettings;
        this.quic = quicSettings;
        this.grpc = grpcSettings;
        this.httpupgrade = httpUpgradeSettings;
        this.xhttp = xhttpSettings;
        this.reality = realitySettings;
        this.hysteria = hysteriaSettings;
        this._raw = {};
    }

    get isTls() {
        return this.security === 'tls';
    }

    set isTls(isTls) {
        if (isTls) {
            this.security = 'tls';
        } else {
            this.security = 'none';
        }
    }

    get isReality() {
        return this.security === 'reality';
    }

    set isReality(enabled) {
        this.security = enabled ? 'reality' : 'none';
    }

    static fromJson(json={}) {
        const tls = TlsStreamSettings.fromJson(json.tlsSettings);
        const stream = new StreamSettings(
            json.method || json.network || 'tcp',
            json.security || 'none',
            tls,
            TcpStreamSettings.fromJson(json.tcpSettings),
            KcpStreamSettings.fromJson(json.kcpSettings),
            WsStreamSettings.fromJson(json.wsSettings),
            HttpStreamSettings.fromJson(json.httpSettings),
            QuicStreamSettings.fromJson(json.quicSettings),
            GrpcStreamSettings.fromJson(json.grpcSettings),
            HttpUpgradeStreamSettings.fromJson(json.httpupgradeSettings),
            XHttpStreamSettings.fromJson(json.xhttpSettings),
            RealityStreamSettings.fromJson(json.realitySettings),
            HysteriaStreamSettings.fromJson(json.hysteriaSettings),
        );
        stream._raw = ObjectUtil.deepClone(json);
        return stream;
    }

    toJson() {
        const network = this.network;
        const managed = {
            network: network,
            security: this.security,
            tlsSettings: this.isTls ? this.tls.toJson() : undefined,
            realitySettings: this.isReality ? this.reality.toJson() : undefined,
            tcpSettings: network === 'tcp' ? this.tcp.toJson() : undefined,
            kcpSettings: network === 'kcp' ? this.kcp.toJson() : undefined,
            wsSettings: network === 'ws' ? this.ws.toJson() : undefined,
            httpSettings: network === 'http' ? this.http.toJson() : undefined,
            quicSettings: network === 'quic' ? this.quic.toJson() : undefined,
            grpcSettings: network === 'grpc' ? this.grpc.toJson() : undefined,
            httpupgradeSettings: network === 'httpupgrade' ? this.httpupgrade.toJson() : undefined,
            xhttpSettings: network === 'xhttp' ? this.xhttp.toJson() : undefined,
            hysteriaSettings: network === 'hysteria' ? this.hysteria.toJson() : undefined,
        };
        const result = XrayCommonClass.mergeJson(this._raw, managed);
        delete result.method;
        return result;
    }
}

class Sniffing extends XrayCommonClass {
    constructor(enabled=false, destOverride=['http', 'tls', 'quic', 'fakedns'],
                metadataOnly=false, routeOnly=false, ipsExcluded=[], domainsExcluded=[]) {
        super();
        this.enabled = enabled;
        this.destOverride = destOverride;
        this.metadataOnly = metadataOnly;
        this.routeOnly = routeOnly;
        this.ipsExcluded = ipsExcluded;
        this.domainsExcluded = domainsExcluded;
    }

    static fromJson(json={}) {
        let destOverride = ObjectUtil.isEmpty(json.destOverride)
            ? ['http', 'tls', 'quic', 'fakedns']
            : ObjectUtil.clone(json.destOverride);
        if (!ObjectUtil.isEmpty(destOverride) && !ObjectUtil.isArrEmpty(destOverride)) {
            if (ObjectUtil.isEmpty(destOverride[0])) {
                destOverride = ['http', 'tls', 'quic', 'fakedns'];
            }
        }
        return new Sniffing(
            !!json.enabled,
            destOverride,
            !!json.metadataOnly,
            !!json.routeOnly,
            XrayCommonClass.toStringArray(json.ipsExcluded),
            XrayCommonClass.toStringArray(json.domainsExcluded),
        );
    }

    toJson() {
        if (!this.enabled) {
            return {enabled: false};
        }
        return {
            enabled: true,
            destOverride: XrayCommonClass.toStringArray(this.destOverride),
            metadataOnly: this.metadataOnly,
            routeOnly: this.routeOnly,
            ipsExcluded: XrayCommonClass.toStringArray(this.ipsExcluded),
            domainsExcluded: XrayCommonClass.toStringArray(this.domainsExcluded),
        };
    }
}

class Inbound extends XrayCommonClass {
    constructor(port=RandomUtil.randomIntRange(10000, 60000),
                listen='',
                protocol=Protocols.VMESS,
                settings=null,
                streamSettings=null,
                tag='',
                sniffing=new Sniffing(),
                ) {
        super();
        this.port = port;
        this.listen = listen;
        this._protocol = protocol;
        this.settings = ObjectUtil.isEmpty(settings) ? Inbound.Settings.getSettings(protocol) : settings;
        const newStream = streamSettings == null;
        this.stream = streamSettings || new StreamSettings();
        this.tag = tag;
        this.sniffing = sniffing;
        this.normalizeProtocolStream();
        // Match 3x-ui's Hysteria2 defaults without rewriting an existing
        // inbound's TLS settings when it is opened and saved again.
        if (newStream && this._protocol === Protocols.HYSTERIA) {
            this.stream.tls.settings.fingerprint = '';
        }
    }

    get protocol() {
        return this._protocol;
    }

    set protocol(protocol) {
        this._protocol = protocol;
        this.settings = Inbound.Settings.getSettings(protocol);
        if (protocol === Protocols.TROJAN) {
            this.tls = true;
        } else if (protocol === Protocols.HYSTERIA) {
            this.normalizeProtocolStream();
            this.stream.tls.settings.fingerprint = '';
        } else if (this.stream.network === 'hysteria') {
            this.stream = new StreamSettings();
        } else if (this.stream.security === 'reality' && !this.canEnableReality()) {
            this.stream.security = 'none';
        }
    }

    normalizeProtocolStream() {
        if (this._protocol !== Protocols.HYSTERIA) return;
        this.stream.network = 'hysteria';
        this.stream.security = 'tls';
        if (this.stream.tls.alpn.length !== 1 || this.stream.tls.alpn[0] !== 'h3') {
            this.stream.tls.alpn = ['h3'];
        }
        this.settings.version = 2;
        // Current 3x-ui/Xray Hysteria inbounds are always Hysteria2.
        this.stream.hysteria.version = 2;
    }

    get tls() {
        return this.stream.security === 'tls';
    }

    set tls(isTls) {
        if (isTls) {
            this.stream.security = 'tls';
        } else {
            this.stream.security = 'none';
        }
    }

    get network() {
        return this.stream.network;
    }

    set network(network) {
        this.stream.network = network;
    }

    get isTcp() {
        return this.network === "tcp";
    }

    get isWs() {
        return this.network === "ws";
    }

    get isKcp() {
        return this.network === "kcp";
    }

    get isQuic() {
        return this.network === "quic"
    }

    get isGrpc() {
        return this.network === "grpc";
    }

    get isHttpUpgrade() {
        return this.network === 'httpupgrade';
    }

    get isXHttp() {
        return this.network === 'xhttp';
    }

    get isH2() {
        return this.network === "http";
    }

    // VMess & VLess
    get uuid() {
        switch (this.protocol) {
            case Protocols.VMESS:
                return this.settings.vmesses[0].id;
            case Protocols.VLESS:
                return this.settings.vlesses[0].id;
            default:
                return "";
        }
    }

    // VLess & Trojan
    get flow() {
        switch (this.protocol) {
            case Protocols.VLESS:
                return this.settings.vlesses[0].flow;
            case Protocols.TROJAN:
                return this.settings.clients[0].flow;
            default:
                return "";
        }
    }

    // VMess
    get alterId() {
        switch (this.protocol) {
            case Protocols.VMESS:
                return this.settings.vmesses[0].alterId;
            default:
                return "";
        }
    }

    // HTTP
    get username() {
        switch (this.protocol) {
            case Protocols.HTTP:
                return this.settings.accounts[0] ? this.settings.accounts[0].user : '';
            case Protocols.MIXED:
                return this.settings.accounts[0] ? this.settings.accounts[0].user : '';
            default:
                return "";
        }
    }

    // Trojan, Shadowsocks & HTTP
    get password() {
        switch (this.protocol) {
            case Protocols.TROJAN:
                return this.settings.clients[0].password;
            case Protocols.SHADOWSOCKS:
                return this.settings.password;
            case Protocols.HTTP:
                return this.settings.accounts[0] ? this.settings.accounts[0].pass : '';
            case Protocols.MIXED:
                return this.settings.accounts[0] ? this.settings.accounts[0].pass : '';
            default:
                return "";
        }
    }

    // Shadowsocks
    get method() {
        switch (this.protocol) {
            case Protocols.SHADOWSOCKS:
                return this.settings.method;
            default:
                return "";
        }
    }

    get serverName() {
        if (this.stream.isTls) {
            return this.stream.tls.server;
        }
        if (this.stream.isReality) {
            return this.stream.reality.serverNames[0] || '';
        }
        return "";
    }

    get host() {
        if (this.isTcp) {
            return this.stream.tcp.request.getHeader("Host");
        } else if (this.isWs) {
            return this.stream.ws.getHeader("Host");
        } else if (this.isH2) {
            return this.stream.http.host[0];
        } else if (this.isHttpUpgrade) {
            return this.stream.httpupgrade.host;
        } else if (this.isXHttp) {
            return this.stream.xhttp.host;
        }
        return null;
    }

    get path() {
        if (this.isTcp) {
            return this.stream.tcp.request.path[0];
        } else if (this.isWs) {
            return this.stream.ws.path;
        } else if (this.isH2) {
            return this.stream.http.path[0];
        } else if (this.isHttpUpgrade) {
            return this.stream.httpupgrade.path;
        } else if (this.isXHttp) {
            return this.stream.xhttp.path;
        }
        return null;
    }

    get quicSecurity() {
        return this.stream.quic.security;
    }

    get quicKey() {
        return this.stream.quic.key;
    }

    get quicType() {
        return this.stream.quic.type;
    }

    get kcpType() {
        return this.stream.kcp.type;
    }

    get kcpSeed() {
        return this.stream.kcp.seed;
    }

    get serviceName() {
        return this.stream.grpc.serviceName;
    }

    canEnableTls() {
        if (this.protocol === Protocols.HYSTERIA) {
            return true;
        }
        switch (this.protocol) {
            case Protocols.VMESS:
            case Protocols.VLESS:
            case Protocols.TROJAN:
            case Protocols.SHADOWSOCKS:
                break;
            default:
                return false;
        }

        switch (this.network) {
            case "tcp":
            case "ws":
            case "http":
            case "grpc":
            case "httpupgrade":
            case "xhttp":
                return true;
            default:
                return false;
        }
    }

    canSetTls() {
        return this.canEnableTls();
    }

    canEnableReality() {
        switch (this.protocol) {
            case Protocols.VLESS:
            case Protocols.TROJAN:
                break;
            default:
                return false;
        }
        switch (this.network) {
            case 'tcp':
            case 'http':
            case 'grpc':
            case 'xhttp':
                return true;
            default:
                return false;
        }
    }

    canEnableTlsFlow() {
        if (this.protocol !== Protocols.VLESS) {
            return false;
        }
        if (this.network === 'tcp' && (this.stream.security === 'tls' || this.stream.security === 'reality')) {
            return true;
        }
        return this.network === 'xhttp' &&
            this.settings &&
            ((this.settings.encryption && this.settings.encryption !== 'none') ||
             (this.settings.decryption && this.settings.decryption !== 'none'));
    }

    canEnableStream() {
        switch (this.protocol) {
            case Protocols.VMESS:
            case Protocols.VLESS:
            case Protocols.SHADOWSOCKS:
            case Protocols.TROJAN:
            case Protocols.HYSTERIA:
                return true;
            default:
                return false;
        }
    }

    canSniffing() {
        return true;
    }

    reset() {
        this.port = RandomUtil.randomIntRange(10000, 60000);
        this.listen = '';
        this.protocol = Protocols.VMESS;
        this.settings = Inbound.Settings.getSettings(Protocols.VMESS);
        this.stream = new StreamSettings();
        this.tag = '';
        this.sniffing = new Sniffing();
    }

    genVmessLink(address='', remark='') {
        if (this.protocol !== Protocols.VMESS) {
            return '';
        }
        let network = this.stream.network;
        let type = 'none';
        let host = '';
        let path = '';
        if (network === 'tcp') {
            let tcp = this.stream.tcp;
            type = tcp.type;
            if (type === 'http') {
                let request = tcp.request;
                path = request.path.join(',');
                let index = request.headers.findIndex(header => header.name.toLowerCase() === 'host');
                if (index >= 0) {
                    host = request.headers[index].value;
                }
            }
        } else if (network === 'kcp') {
            let kcp = this.stream.kcp;
            type = kcp.type;
            path = kcp.seed;
        } else if (network === 'ws') {
            let ws = this.stream.ws;
            path = ws.path;
            let index = ws.headers.findIndex(header => header.name.toLowerCase() === 'host');
            if (index >= 0) {
                host = ws.headers[index].value;
            }
        } else if (network === 'http') {
            network = 'h2';
            path = this.stream.http.path;
            host = this.stream.http.host.join(',');
        } else if (network === 'quic') {
            type = this.stream.quic.type;
            host = this.stream.quic.security;
            path = this.stream.quic.key;
        } else if (network === 'grpc') {
            path = this.stream.grpc.serviceName;
        }

        if (this.stream.security === 'tls') {
            if (!ObjectUtil.isEmpty(this.stream.tls.server)) {
                address = this.stream.tls.server;
            }
        }

        let obj = {
            v: '2',
            ps: remark,
            add: address,
            port: this.port,
            id: this.settings.vmesses[0].id,
            aid: this.settings.vmesses[0].alterId,
            net: network,
            type: type,
            host: host,
            path: path,
            tls: this.stream.security,
        };
        return 'vmess://' + base64(JSON.stringify(obj, null, 2));
    }

    formatLinkHost(address) {
        if (address.indexOf(':') >= 0 && !(address.startsWith('[') && address.endsWith(']'))) {
            return `[${address}]`;
        }
        return address;
    }

    applyNetworkParams(params) {
        switch (this.stream.network) {
            case 'tcp': {
                const tcp = this.stream.tcp;
                if (tcp.type === 'http') {
                    params.set('headerType', 'http');
                    params.set('path', tcp.request.path.join(','));
                    const host = tcp.request.getHeader('Host');
                    if (host) params.set('host', host);
                }
                break;
            }
            case 'kcp':
                params.set('headerType', this.stream.kcp.type);
                params.set('seed', this.stream.kcp.seed);
                break;
            case 'ws': {
                const ws = this.stream.ws;
                params.set('path', ws.path);
                const host = ws.host || ws.getHeader('Host');
                if (host) params.set('host', host);
                break;
            }
            case 'http':
                params.set('path', this.stream.http.path);
                params.set('host', this.stream.http.host.join(','));
                break;
            case 'quic':
                params.set('quicSecurity', this.stream.quic.security);
                params.set('key', this.stream.quic.key);
                params.set('headerType', this.stream.quic.type);
                break;
            case 'grpc':
                params.set('serviceName', this.stream.grpc.serviceName);
                params.set('authority', this.stream.grpc.authority);
                if (this.stream.grpc.multiMode) params.set('mode', 'multi');
                break;
            case 'httpupgrade': {
                const upgrade = this.stream.httpupgrade;
                params.set('path', upgrade.path);
                params.set('host', upgrade.host);
                break;
            }
            case 'xhttp': {
                const xhttp = this.stream.xhttp;
                params.set('path', xhttp.path);
                params.set('host', xhttp.host);
                params.set('mode', xhttp.mode);
                if (xhttp.xPaddingBytes) params.set('x_padding_bytes', xhttp.xPaddingBytes);
                const extra = {};
                for (const key of [
                    'xPaddingKey', 'xPaddingHeader', 'xPaddingPlacement', 'xPaddingMethod',
                    'sessionIDPlacement', 'sessionIDKey', 'sessionIDTable', 'sessionIDLength',
                    'seqPlacement', 'seqKey', 'uplinkDataPlacement', 'uplinkDataKey',
                    'uplinkHTTPMethod', 'scMaxEachPostBytes', 'scMinPostsIntervalMs',
                ]) {
                    if (xhttp[key]) extra[key] = xhttp[key];
                }
                if (xhttp.xPaddingObfsMode) extra.xPaddingObfsMode = true;
                const headers = XrayCommonClass.toV2Headers(xhttp.headers, false);
                if (Object.keys(headers).length > 0) extra.headers = headers;
                if (Object.keys(extra).length > 0) params.set('extra', JSON.stringify(extra));
                break;
            }
        }
    }

    applySecurityParams(params) {
        params.set('security', this.stream.security);
        if (this.stream.security === 'tls') {
            const tls = this.stream.tls;
            if (tls.server) params.set('sni', tls.server);
            if (tls.alpn.length > 0) params.set('alpn', tls.alpn.join(','));
            if (tls.settings.fingerprint) params.set('fp', tls.settings.fingerprint);
            if (tls.settings.echConfigList) params.set('ech', tls.settings.echConfigList);
            if (tls.settings.pinnedPeerCertSha256.length > 0) {
                params.set('pcs', tls.settings.pinnedPeerCertSha256.join(','));
            }
            if (tls.settings.verifyPeerCertByName) params.set('vcn', tls.settings.verifyPeerCertByName);
        } else if (this.stream.security === 'reality') {
            const reality = this.stream.reality;
            if (reality.settings.publicKey) params.set('pbk', reality.settings.publicKey);
            if (reality.settings.fingerprint) params.set('fp', reality.settings.fingerprint);
            const sni = reality.settings.serverName || reality.serverNames[0] || reality.target.split(':')[0];
            if (sni) params.set('sni', sni);
            if (reality.shortIds.length > 0) params.set('sid', reality.shortIds[0]);
            if (reality.settings.spiderX) params.set('spx', reality.settings.spiderX);
            if (reality.settings.mldsa65Verify) params.set('pqv', reality.settings.mldsa65Verify);
        }
    }

    genVLESSLink(address = '', remark='') {
        const settings = this.settings;
        const uuid = settings.vlesses[0].id;
        const port = this.port;
        const params = new URLSearchParams();
        params.set("type", this.stream.network);
        params.set("encryption", settings.encryption || 'none');
        this.applyNetworkParams(params);
        this.applySecurityParams(params);
        if (this.canEnableTlsFlow() && this.settings.vlesses[0].flow) {
            params.set("flow", this.settings.vlesses[0].flow);
        }

        const link = `vless://${uuid}@${this.formatLinkHost(address)}:${port}`;
        const url = new URL(link);
        for (const [key, value] of params) url.searchParams.set(key, value);
        url.hash = encodeURIComponent(remark);
        return url.toString();
    }

    genSSLink(address='', remark='') {
        let settings = this.settings;
        const server = this.stream.tls.server;
        if (!ObjectUtil.isEmpty(server)) {
            address = server;
        }
        return 'ss://' + safeBase64(settings.method + ':' + settings.password + '@' + address + ':' + this.port)
            + '#' + encodeURIComponent(remark);
    }

    genTrojanLink(address='', remark='') {
        const params = new URLSearchParams();
        params.set('type', this.stream.network);
        this.applyNetworkParams(params);
        this.applySecurityParams(params);
        const settings = this.settings;
        const url = new URL(`trojan://${encodeURIComponent(settings.clients[0].password)}@${this.formatLinkHost(address)}:${this.port}`);
        for (const [key, value] of params) url.searchParams.set(key, value);
        url.hash = encodeURIComponent(remark);
        return url.toString();
    }

    normalizeHysteriaPin(pin) {
        const original = String(pin || '').trim();
        const stripped = original.replace(/:/g, '');
        if (/^[0-9a-fA-F]{64}$/.test(stripped)) return stripped.toLowerCase();
        try {
            const normalized = original.replace(/-/g, '+').replace(/_/g, '/');
            const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
            const binary = window.atob(padded);
            if (binary.length !== 32) return original;
            let hex = '';
            for (let i = 0; i < binary.length; ++i) {
                hex += binary.charCodeAt(i).toString(16).padStart(2, '0');
            }
            return hex;
        } catch (_) {
            return original;
        }
    }

    hysteriaClients() {
        return this.settings.clients.filter(client => client && client.auth);
    }

    genHysteriaLink(address='', remark='', clientIndex=0) {
        if (this.protocol !== Protocols.HYSTERIA || this.stream.security !== 'tls') return '';
        const client = this.hysteriaClients()[clientIndex];
        if (!client) return '';
        const params = new URLSearchParams();
        const tls = this.stream.tls;
        params.set('security', 'tls');
        if (tls.settings.fingerprint) params.set('fp', tls.settings.fingerprint);
        if (tls.alpn.length > 0) params.set('alpn', tls.alpn.join(','));
        if (tls.settings.echConfigList) params.set('ech', tls.settings.echConfigList);
        if (tls.server) params.set('sni', tls.server);
        if (tls.settings.verifyPeerCertByName) params.set('vcn', tls.settings.verifyPeerCertByName);
        if (tls.settings.pinnedPeerCertSha256.length > 0) {
            params.set('pinSHA256', tls.settings.pinnedPeerCertSha256.map(pin => this.normalizeHysteriaPin(pin)).join(','));
        }
        const url = new URL(`hysteria2://${this.formatLinkHost(address)}:${this.port}`);
        url.username = client.auth;
        for (const [key, value] of params) url.searchParams.set(key, value);
        url.hash = encodeURIComponent(remark);
        return url.toString();
    }

    wireguardClients() {
        const settings = this.settings;
        const clients = settings.clients.length > 0 ? settings.clients : settings.peers;
        return clients.filter(client => client && client.enable !== false && client.privateKey);
    }

    genWireguardLink(address='', remark='', clientIndex=0) {
        if (this.protocol !== Protocols.WIREGUARD) return '';
        const client = this.wireguardClients()[clientIndex];
        const serverPublicKey = this.settings.publicKey;
        if (!client || !serverPublicKey) return '';
        const url = new URL(`wireguard://${this.formatLinkHost(address)}:${this.port}`);
        url.username = client.privateKey;
        url.searchParams.set('publickey', serverPublicKey);
        const allowedIPs = XrayCommonClass.toStringArray(client.allowedIPs);
        if (allowedIPs.length > 0) url.searchParams.set('address', allowedIPs.join(','));
        if (this.settings.mtu > 0) url.searchParams.set('mtu', String(this.settings.mtu));
        url.hash = encodeURIComponent(remark);
        return url.toString();
    }

    genWireguardConfig(address='', clientIndex=0) {
        if (this.protocol !== Protocols.WIREGUARD) return '';
        const client = this.wireguardClients()[clientIndex];
        const serverPublicKey = this.settings.publicKey;
        if (!client || !serverPublicKey) return '';
        const allowedIPs = XrayCommonClass.toStringArray(client.allowedIPs);
        if (allowedIPs.length === 0) return '';
        const lines = [
            '[Interface]',
            `PrivateKey = ${client.privateKey}`,
            `Address = ${allowedIPs.join(', ')}`,
            `DNS = ${this.settings.dns || '1.1.1.1, 1.0.0.1'}`,
        ];
        if (this.settings.mtu > 0) lines.push(`MTU = ${this.settings.mtu}`);
        lines.push('', '[Peer]', `PublicKey = ${serverPublicKey}`);
        const preSharedKey = client.preSharedKey || client.psk || '';
        if (preSharedKey) lines.push(`PresharedKey = ${preSharedKey}`);
        lines.push('AllowedIPs = 0.0.0.0/0, ::/0');
        lines.push(`Endpoint = ${this.formatLinkHost(address)}:${this.port}`);
        if (client.keepAlive > 0) lines.push(`PersistentKeepalive = ${client.keepAlive}`);
        return lines.join('\n') + '\n';
    }

    genLink(address='', remark='', clientIndex=0) {
        switch (this.protocol) {
            case Protocols.VMESS: return this.genVmessLink(address, remark);
            case Protocols.VLESS: return this.genVLESSLink(address, remark);
            case Protocols.SHADOWSOCKS: return this.genSSLink(address, remark);
            case Protocols.TROJAN: return this.genTrojanLink(address, remark);
            case Protocols.HYSTERIA: return this.genHysteriaLink(address, remark, clientIndex);
            case Protocols.WIREGUARD: return this.genWireguardLink(address, remark, clientIndex);
            default: return '';
        }
    }

    static fromJson(json={}) {
        return new Inbound(
            json.port,
            json.listen,
            json.protocol,
            Inbound.Settings.fromJson(json.protocol, json.settings),
            StreamSettings.fromJson(json.streamSettings),
            json.tag,
            Sniffing.fromJson(json.sniffing),
        )
    }

    toJson() {
        this.normalizeProtocolStream();
        let streamSettings;
        if (this.canEnableStream()) {
            streamSettings = this.stream.toJson();
        }
        return {
            port: this.port,
            listen: this.listen,
            protocol: this.protocol,
            settings: this.settings instanceof XrayCommonClass ? this.settings.toJson() : this.settings,
            streamSettings: streamSettings,
            tag: this.tag,
            sniffing: this.sniffing.toJson(),
        };
    }
}

Inbound.Settings = class extends XrayCommonClass {
    constructor(protocol) {
        super();
        this.protocol = protocol;
    }

    static getSettings(protocol) {
        switch (protocol) {
            case Protocols.VMESS: return new Inbound.VmessSettings(protocol);
            case Protocols.VLESS: return new Inbound.VLESSSettings(protocol);
            case Protocols.TROJAN: return new Inbound.TrojanSettings(protocol);
            case Protocols.SHADOWSOCKS: return new Inbound.ShadowsocksSettings(protocol);
            case Protocols.HTTP: return new Inbound.HttpSettings(protocol);
            case Protocols.MIXED: return new Inbound.MixedSettings(protocol);
            case Protocols.TUNNEL: return new Inbound.TunnelSettings(protocol);
            case Protocols.WIREGUARD: return new Inbound.WireguardSettings(protocol);
            case Protocols.HYSTERIA: return new Inbound.HysteriaSettings(protocol);
            default: return null;
        }
    }

    static fromJson(protocol, json) {
        switch (protocol) {
            case Protocols.VMESS: return Inbound.VmessSettings.fromJson(json);
            case Protocols.VLESS: return Inbound.VLESSSettings.fromJson(json);
            case Protocols.TROJAN: return Inbound.TrojanSettings.fromJson(json);
            case Protocols.SHADOWSOCKS: return Inbound.ShadowsocksSettings.fromJson(json);
            case Protocols.HTTP: return Inbound.HttpSettings.fromJson(json);
            case Protocols.MIXED: return Inbound.MixedSettings.fromJson(json);
            case Protocols.TUNNEL: return Inbound.TunnelSettings.fromJson(json);
            case Protocols.WIREGUARD: return Inbound.WireguardSettings.fromJson(json);
            case Protocols.HYSTERIA: return Inbound.HysteriaSettings.fromJson(json);
            default: return null;
        }
    }

    toJson() {
        return {};
    }
};

Inbound.VmessSettings = class extends Inbound.Settings {
    constructor(protocol,
                vmesses=[new Inbound.VmessSettings.Vmess()],
                disableInsecureEncryption=false) {
        super(protocol);
        this.vmesses = vmesses;
        this.disableInsecure = disableInsecureEncryption;
    }

    indexOfVmessById(id) {
        return this.vmesses.findIndex(vmess => vmess.id === id);
    }

    addVmess(vmess) {
        if (this.indexOfVmessById(vmess.id) >= 0) {
            return false;
        }
        this.vmesses.push(vmess);
    }

    delVmess(vmess) {
        const i = this.indexOfVmessById(vmess.id);
        if (i >= 0) {
            this.vmesses.splice(i, 1);
        }
    }

    static fromJson(json={}) {
        const clients = (json.clients || []).map(client => Inbound.VmessSettings.Vmess.fromJson(client));
        if (clients.length === 0) clients.push(new Inbound.VmessSettings.Vmess());
        return new Inbound.VmessSettings(
            Protocols.VMESS,
            clients,
            ObjectUtil.isEmpty(json.disableInsecureEncryption) ? false : json.disableInsecureEncryption,
        );
    }

    toJson() {
        return {
            clients: Inbound.VmessSettings.toJsonArray(this.vmesses),
            disableInsecureEncryption: this.disableInsecure,
        };
    }
};
Inbound.VmessSettings.Vmess = class extends XrayCommonClass {
    constructor(id=RandomUtil.randomUUID(), alterId=0, security='auto', email=RandomUtil.randomLowerAndNum(10)) {
        super();
        this.id = id;
        this.alterId = alterId;
        this.security = security;
        this.email = email;
    }

    static fromJson(json={}) {
        return new Inbound.VmessSettings.Vmess(
            json.id || RandomUtil.randomUUID(),
            json.alterId || 0,
            json.security || 'auto',
            json.email || '',
        );
    }

    toJson() {
        return {
            id: this.id,
            alterId: this.alterId,
            security: this.security,
            email: this.email,
        };
    }
};

Inbound.VLESSSettings = class extends Inbound.Settings {
    constructor(protocol,
                vlesses=[new Inbound.VLESSSettings.VLESS()],
                decryption='none',
                fallbacks=[],
                encryption='none',
                testseed=null,) {
        super(protocol);
        this.vlesses = vlesses;
        this.decryption = decryption;
        this.fallbacks = fallbacks;
        this.encryption = encryption;
        this.testseed = testseed;
    }

    addFallback() {
        this.fallbacks.push(new Inbound.VLESSSettings.Fallback());
    }

    delFallback(index) {
        this.fallbacks.splice(index, 1);
    }

    static fromJson(json={}) {
        const clients = (json.clients || []).map(client => Inbound.VLESSSettings.VLESS.fromJson(client));
        if (clients.length === 0) clients.push(new Inbound.VLESSSettings.VLESS());
        return new Inbound.VLESSSettings(
            Protocols.VLESS,
            clients,
            json.decryption || 'none',
            Inbound.VLESSSettings.Fallback.fromJson(json.fallbacks || []),
            json.encryption || 'none',
            json.testseed,
        );
    }

    toJson() {
        return {
            clients: Inbound.VLESSSettings.toJsonArray(this.vlesses),
            decryption: this.decryption,
            encryption: this.encryption,
            fallbacks: Inbound.VLESSSettings.toJsonArray(this.fallbacks),
            testseed: Array.isArray(this.testseed) && this.testseed.length === 4 ? this.testseed : undefined,
        };
    }
};
Inbound.VLESSSettings.VLESS = class extends XrayCommonClass {

    constructor(id=RandomUtil.randomUUID(), flow='', email=RandomUtil.randomLowerAndNum(10)) {
        super();
        this.id = id;
        this.flow = flow;
        this.email = email;
    }

    static fromJson(json={}) {
        return new Inbound.VLESSSettings.VLESS(
            json.id || RandomUtil.randomUUID(),
            json.flow || '',
            json.email || '',
        );
    }

    toJson() {
        return {id: this.id, flow: this.flow, email: this.email};
    }
};
Inbound.VLESSSettings.Fallback = class extends XrayCommonClass {
    constructor(name="", alpn='', path='', dest='', xver=0) {
        super();
        this.name = name;
        this.alpn = alpn;
        this.path = path;
        this.dest = dest;
        this.xver = xver;
    }

    toJson() {
        let xver = this.xver;
        if (!Number.isInteger(xver)) {
            xver = 0;
        }
        return {
            name: this.name,
            alpn: this.alpn,
            path: this.path,
            dest: this.dest,
            xver: xver,
        }
    }

    static fromJson(json=[]) {
        const fallbacks = [];
        for (let fallback of (json || [])) {
            fallbacks.push(new Inbound.VLESSSettings.Fallback(
                fallback.name,
                fallback.alpn,
                fallback.path,
                fallback.dest,
                fallback.xver,
            ))
        }
        return fallbacks;
    }
};

Inbound.TrojanSettings = class extends Inbound.Settings {
    constructor(protocol,
                clients=[new Inbound.TrojanSettings.Client()],
                fallbacks=[],) {
        super(protocol);
        this.clients = clients;
        this.fallbacks = fallbacks;
    }

    addTrojanFallback() {
        this.fallbacks.push(new Inbound.TrojanSettings.Fallback());
    }

    delTrojanFallback(index) {
        this.fallbacks.splice(index, 1);
    }

    toJson() {
        return {
            clients: Inbound.TrojanSettings.toJsonArray(this.clients),
            fallbacks: Inbound.TrojanSettings.toJsonArray(this.fallbacks),
        };
    }

    static fromJson(json={}) {
        const clients = [];
        for (const c of (json.clients || [])) {
            clients.push(Inbound.TrojanSettings.Client.fromJson(c));
        }
        if (clients.length === 0) clients.push(new Inbound.TrojanSettings.Client());
        return new Inbound.TrojanSettings(
            Protocols.TROJAN,
            clients,
            Inbound.TrojanSettings.Fallback.fromJson(json.fallbacks),);
    }
};
Inbound.TrojanSettings.Client = class extends XrayCommonClass {
    constructor(password=RandomUtil.randomSeq(10), flow='', email=RandomUtil.randomLowerAndNum(10)) {
        super();
        this.password = password;
        this.flow = flow;
        this.email = email;
    }

    toJson() {
        return {
            password: this.password,
            flow: this.flow,
            email: this.email,
        };
    }

    static fromJson(json={}) {
        return new Inbound.TrojanSettings.Client(
            json.password || RandomUtil.randomSeq(10),
            json.flow || '',
            json.email || '',
        );
    }

};

Inbound.TrojanSettings.Fallback = class extends XrayCommonClass {
    constructor(name="", alpn='', path='', dest='', xver=0) {
        super();
        this.name = name;
        this.alpn = alpn;
        this.path = path;
        this.dest = dest;
        this.xver = xver;
    }

    toJson() {
        let xver = this.xver;
        if (!Number.isInteger(xver)) {
            xver = 0;
        }
        return {
            name: this.name,
            alpn: this.alpn,
            path: this.path,
            dest: this.dest,
            xver: xver,
        }
    }

    static fromJson(json=[]) {
        const fallbacks = [];
        for (let fallback of (json || [])) {
            fallbacks.push(new Inbound.TrojanSettings.Fallback(
                fallback.name,
                fallback.alpn,
                fallback.path,
                fallback.dest,
                fallback.xver,
            ))
        }
        return fallbacks;
    }
};

Inbound.ShadowsocksSettings = class extends Inbound.Settings {
    constructor(protocol,
                method=SSMethods.BLAKE3_AES_256_GCM,
                password=RandomUtil.randomShadowsocksPassword(SSMethods.BLAKE3_AES_256_GCM),
                network='tcp,udp', clients=[], ivCheck=false
    ) {
        super(protocol);
        this.method = method;
        this.password = password;
        this.network = network;
        this.clients = clients;
        this.ivCheck = ivCheck;
    }

    static fromJson(json={}) {
        return new Inbound.ShadowsocksSettings(
            Protocols.SHADOWSOCKS,
            json.method || SSMethods.BLAKE3_AES_256_GCM,
            json.password || '',
            json.network || 'tcp,udp',
            (json.clients || []).map(client => Inbound.ShadowsocksSettings.Client.fromJson(client)),
            !!json.ivCheck,
        );
    }

    toJson() {
        return {
            method: this.method,
            password: this.password,
            network: this.network,
            clients: Inbound.ShadowsocksSettings.toJsonArray(this.clients),
            ivCheck: this.ivCheck,
        };
    }

    get is2022() {
        return this.method.indexOf('2022-') === 0;
    }

    regeneratePassword() {
        this.password = this.is2022 ? RandomUtil.randomShadowsocksPassword(this.method) : RandomUtil.randomSeq(16);
    }

    addClient() {
        this.clients.push(new Inbound.ShadowsocksSettings.Client(
            RandomUtil.randomLowerAndNum(10),
            RandomUtil.randomShadowsocksPassword(this.method),
        ));
    }

    delClient(index) {
        this.clients.splice(index, 1);
    }
};

Inbound.ShadowsocksSettings.Client = class extends XrayCommonClass {
    constructor(email=RandomUtil.randomLowerAndNum(10), password='', method='') {
        super();
        this.email = email;
        this.password = password;
        this.method = method;
    }

    static fromJson(json={}) {
        return new Inbound.ShadowsocksSettings.Client(json.email || '', json.password || '', json.method || '');
    }
};

// `mixed` is the current Xray SOCKS/HTTP combined inbound and the sole
// SOCKS-style protocol exposed by the panel.
Inbound.MixedSettings = class extends Inbound.Settings {
    constructor(protocol, auth='password', accounts=[new Inbound.MixedSettings.Account()], udp=false, ip='127.0.0.1') {
        super(protocol);
        this.auth = auth === 'noauth' ? 'noauth' : 'password';
        this.accounts = accounts;
        this.udp = !!udp;
        this.ip = ip || '127.0.0.1';
    }

    addAccount() {
        this.accounts.push(new Inbound.MixedSettings.Account());
    }

    delAccount(index) {
        this.accounts.splice(index, 1);
    }

    static fromJson(json={}) {
        let accounts = (json.accounts || []).map(account => Inbound.MixedSettings.Account.fromJson(account));
        if ((json.auth || 'password') === 'password' && accounts.length === 0) accounts = [new Inbound.MixedSettings.Account()];
        return new Inbound.MixedSettings(Protocols.MIXED, json.auth || 'password', accounts, !!json.udp, json.ip || '127.0.0.1');
    }

    toJson() {
        return {
            auth: this.auth,
            accounts: this.auth === 'password' ? Inbound.MixedSettings.toJsonArray(this.accounts) : undefined,
            udp: this.udp,
            ip: this.ip,
        };
    }
};
Inbound.MixedSettings.Account = class extends XrayCommonClass {
    constructor(user=RandomUtil.randomLowerAndNum(8), pass=RandomUtil.randomLowerAndNum(12)) {
        super();
        this.user = user;
        this.pass = pass;
    }

    static fromJson(json={}) {
        return new Inbound.MixedSettings.Account(json.user || '', json.pass || '');
    }

    toJson() {
        return {user: this.user, pass: this.pass};
    }
};

// tunnel is the current Xray transparent forwarder.  It intentionally does
// not share dokodemo-door's old address/port/userLevel shape.
Inbound.TunnelSettings = class extends Inbound.Settings {
    constructor(protocol, rewriteAddress='', rewritePort=undefined, portMap={}, allowedNetwork='tcp,udp', followRedirect=false) {
        super(protocol);
        this.rewriteAddress = rewriteAddress || '';
        this.rewritePort = Number.isInteger(rewritePort) && rewritePort >= 1 ? rewritePort : undefined;
        this.portMap = portMap && typeof portMap === 'object' ? portMap : {};
        this.newPortMapSource = '';
        this.newPortMapDestination = '';
        this.allowedNetwork = ['tcp', 'udp', 'tcp,udp'].includes(allowedNetwork) ? allowedNetwork : 'tcp,udp';
        this.followRedirect = !!followRedirect;
    }

    addPortMap() {
        const source = String(this.newPortMapSource || '').trim();
        if (!source) return;
        this.portMap = Object.assign({}, this.portMap, {[source]: String(this.newPortMapDestination || '').trim()});
        this.newPortMapSource = '';
        this.newPortMapDestination = '';
    }

    delPortMap(source) {
        const portMap = Object.assign({}, this.portMap);
        delete portMap[source];
        this.portMap = portMap;
    }

    static fromJson(json={}) {
        return new Inbound.TunnelSettings(
            Protocols.TUNNEL,
            json.rewriteAddress || '',
            json.rewritePort,
            json.portMap || {},
            json.allowedNetwork || 'tcp,udp',
            !!json.followRedirect,
        );
    }

    toJson() {
        return {
            rewriteAddress: this.rewriteAddress || undefined,
            rewritePort: Number.isInteger(this.rewritePort) && this.rewritePort >= 1 ? this.rewritePort : undefined,
            portMap: Object.assign({}, this.portMap),
            allowedNetwork: this.allowedNetwork,
            followRedirect: this.followRedirect,
        };
    }
};

// The panel retains WireGuard clients (including their private keys) and the
// backend translates them to Xray's peers at runtime.  `peers` is retained for
// parsing existing settings but clients remain the editable source of truth.
Inbound.WireguardSettings = class extends Inbound.Settings {
    constructor(protocol, mtu=1420, secretKey=Wireguard.generateKeypair().privateKey, dns='', peers=[], clients=[], noKernelTun=false, domainStrategy='') {
        super(protocol);
        this.mtu = Number.isInteger(mtu) ? mtu : 1420;
        this.secretKey = secretKey || '';
        this.dns = dns || '';
        this.peers = peers || [];
        this.clients = clients;
        this.noKernelTun = !!noKernelTun;
        this.domainStrategy = domainStrategy || undefined;
    }

    get publicKey() {
        if (!this.secretKey) return '';
        try {
            return Wireguard.generateKeypair(this.secretKey).publicKey;
        } catch (_) {
            return '';
        }
    }

    addClient() {
        this.clients.push(new Inbound.WireguardSettings.Client());
    }

    delClient(index) {
        this.clients.splice(index, 1);
    }

    static fromJson(json={}) {
        const clients = (json.clients || []).map(client => Inbound.WireguardSettings.Client.fromJson(client));
        return new Inbound.WireguardSettings(
            Protocols.WIREGUARD, json.mtu, json.secretKey, json.dns,
            json.peers || [], clients, !!json.noKernelTun, json.domainStrategy,
        );
    }

    toJson() {
        return {
            mtu: this.mtu,
            secretKey: this.secretKey,
            dns: this.dns || undefined,
            peers: this.peers,
            clients: Inbound.WireguardSettings.toJsonArray(this.clients),
            noKernelTun: this.noKernelTun,
            domainStrategy: this.domainStrategy || undefined,
        };
    }
};
Inbound.WireguardSettings.Client = class extends XrayCommonClass {
    constructor(privateKey='', publicKey='', preSharedKey='', allowedIPs=[], keepAlive=0, email=RandomUtil.randomLowerAndNum(10), enable=true) {
        super();
        const keypair = privateKey ? null : Wireguard.generateKeypair();
        this.privateKey = privateKey || keypair.privateKey;
        this.publicKey = publicKey || keypair.publicKey;
        this.preSharedKey = preSharedKey || '';
        this.allowedIPs = XrayCommonClass.toStringArray(allowedIPs);
        this.keepAlive = Number.isInteger(keepAlive) ? keepAlive : 0;
        this.email = email || '';
        this.enable = enable !== false;
    }

    static fromJson(json={}) {
        return new Inbound.WireguardSettings.Client(
            json.privateKey, json.publicKey, json.preSharedKey, json.allowedIPs,
            json.keepAlive, json.email, json.enable,
        );
    }

    toJson() {
        return {
            privateKey: this.privateKey || undefined,
            publicKey: this.publicKey || undefined,
            preSharedKey: this.preSharedKey || undefined,
            allowedIPs: XrayCommonClass.toStringArray(this.allowedIPs),
            keepAlive: this.keepAlive || undefined,
            email: this.email || undefined,
            enable: this.enable,
        };
    }
};

Inbound.HysteriaSettings = class extends Inbound.Settings {
    constructor(protocol, clients=[]) {
        super(protocol);
        this.version = 2;
        this.clients = clients;
    }

    addClient() {
        this.clients.push(new Inbound.HysteriaSettings.Client());
    }

    delClient(index) {
        this.clients.splice(index, 1);
    }

    static fromJson(json={}) {
        const clients = (json.clients || []).map(client => Inbound.HysteriaSettings.Client.fromJson(client));
        return new Inbound.HysteriaSettings(Protocols.HYSTERIA, clients);
    }

    toJson() {
        return {
            version: 2,
            clients: Inbound.HysteriaSettings.toJsonArray(this.clients),
        };
    }
};
Inbound.HysteriaSettings.Client = class extends XrayCommonClass {
    constructor(auth=RandomUtil.randomLowerAndNum(16), email=RandomUtil.randomLowerAndNum(10)) {
        super();
        this.auth = auth;
        this.email = email;
    }

    static fromJson(json={}) {
        return new Inbound.HysteriaSettings.Client(json.auth || RandomUtil.randomLowerAndNum(16), json.email || '');
    }

    toJson() {
        return {auth: this.auth, email: this.email};
    }
};

Inbound.HttpSettings = class extends Inbound.Settings {
    constructor(protocol, accounts=[new Inbound.HttpSettings.HttpAccount()], allowTransparent=false) {
        super(protocol);
        this.accounts = accounts;
        this.allowTransparent = allowTransparent;
    }

    addAccount(account=new Inbound.HttpSettings.HttpAccount()) {
        this.accounts.push(account);
    }

    delAccount(index) {
        this.accounts.splice(index, 1);
    }

    static fromJson(json={}) {
        const accounts = (json.accounts || []).map(account => Inbound.HttpSettings.HttpAccount.fromJson(account));
        if (accounts.length === 0) accounts.push(new Inbound.HttpSettings.HttpAccount());
        return new Inbound.HttpSettings(
            Protocols.HTTP,
            accounts,
            !!json.allowTransparent,
        );
    }

    toJson() {
        return {
            accounts: Inbound.HttpSettings.toJsonArray(this.accounts),
            allowTransparent: this.allowTransparent,
        };
    }
};

Inbound.HttpSettings.HttpAccount = class extends XrayCommonClass {
    constructor(user=RandomUtil.randomLowerAndNum(8), pass=RandomUtil.randomLowerAndNum(12)) {
        super();
        this.user = user;
        this.pass = pass;
    }

    static fromJson(json={}) {
        return new Inbound.HttpSettings.HttpAccount(json.user, json.pass);
    }
};
