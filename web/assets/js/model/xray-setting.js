class XraySettingsEditor {
    constructor(templateText) {
        const text = String(templateText || '').trim();
        if (!text) throw new Error('Xray 配置模板为空。');
        let template;
        try {
            template = JSON.parse(text);
        } catch (_) {
            throw new Error('Xray 配置模板不是有效 JSON。');
        }
        if (!XraySettingsEditor.isObject(template)) {
            throw new Error('Xray 配置模板必须是 JSON 对象。');
        }
        this.template = template;
    }

    static isObject(value) {
        return value !== null && typeof value === 'object' && !Array.isArray(value);
    }

    static clone(value) {
        return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
    }

    serialize() {
        return JSON.stringify(this.template, null, 2);
    }

    freedomOutbound() {
        if (!Array.isArray(this.template.outbounds)) return null;
        return this.template.outbounds.find(item => item && item.protocol === 'freedom' && item.tag === 'direct') ||
            this.template.outbounds.find(item => item && item.protocol === 'freedom') || null;
    }

    freedomStrategy() {
        const outbound = this.freedomOutbound();
        return XraySettingsEditor.isObject(outbound && outbound.settings) && outbound.settings.domainStrategy
            ? outbound.settings.domainStrategy : 'AsIs';
    }

    setFreedomStrategy(value) {
        if (!Array.isArray(this.template.outbounds)) this.template.outbounds = [];
        let outbound = this.freedomOutbound();
        if (!outbound) {
            outbound = {protocol: 'freedom', tag: 'direct', settings: {}};
            this.template.outbounds.push(outbound);
        }
        if (!XraySettingsEditor.isObject(outbound.settings)) outbound.settings = {};
        outbound.settings.domainStrategy = value;
    }

    routingDomainStrategy() {
        return XraySettingsEditor.isObject(this.template.routing) && this.template.routing.domainStrategy
            ? this.template.routing.domainStrategy : 'AsIs';
    }

    setRoutingDomainStrategy(value) {
        if (!XraySettingsEditor.isObject(this.template.routing)) this.template.routing = {};
        this.template.routing.domainStrategy = value;
    }

    logSettings() {
        const log = XraySettingsEditor.isObject(this.template.log) ? this.template.log : {};
        return {
            loglevel: log.loglevel || 'warning',
            access: log.access || 'none',
            error: log.error || '',
            maskAddress: log.maskAddress || '',
            dnsLog: log.dnsLog === true,
        };
    }

    setLogField(field, value) {
        if (!XraySettingsEditor.isObject(this.template.log)) this.template.log = {};
        if ((field === 'error' || field === 'maskAddress') && value === '') {
            delete this.template.log[field];
        } else {
            this.template.log[field] = value;
        }
    }

    dnsEnabled() {
        return XraySettingsEditor.isObject(this.template.dns);
    }

    dnsSettings() {
        if (!this.dnsEnabled()) return null;
        const dns = this.template.dns;
        return Object.assign({
            tag: 'dns_inbound',
            clientIp: '',
            queryStrategy: 'UseIP',
            disableCache: false,
            disableFallback: false,
            disableFallbackIfMatch: false,
            enableParallelQuery: false,
            useSystemHosts: false,
            serveStale: false,
            serveExpiredTTL: 0,
            servers: [],
        }, XraySettingsEditor.clone(dns), {
            servers: Array.isArray(dns.servers) ? XraySettingsEditor.clone(dns.servers) : [],
        });
    }

    toggleDns(enabled) {
        if (enabled) {
            this.template.dns = {
                tag: 'dns_inbound',
                queryStrategy: 'UseIP',
                disableCache: false,
                disableFallback: false,
                disableFallbackIfMatch: false,
                useSystemHosts: false,
                enableParallelQuery: false,
                serveStale: false,
                serveExpiredTTL: 0,
                hosts: {},
                servers: [],
            };
        } else {
            delete this.template.dns;
        }
        delete this.template.fakedns;
        delete this.template.fakeDns;
    }

    setDnsField(field, value, omitEmpty = false) {
        if (!this.dnsEnabled()) return;
        if (omitEmpty && (value === '' || value === null || value === undefined)) {
            delete this.template.dns[field];
        } else {
            this.template.dns[field] = value;
        }
    }

    hostRows() {
        if (!this.dnsEnabled() || !XraySettingsEditor.isObject(this.template.dns.hosts)) return [];
        return Object.entries(this.template.dns.hosts).map(([domain, value]) => ({
            domain,
            values: (Array.isArray(value) ? value : [value]).map(String),
        }));
    }

    setHosts(rows) {
        if (!this.dnsEnabled()) return;
        const hosts = {};
        for (const row of rows || []) {
            const domain = String(row && row.domain || '').trim();
            const values = (Array.isArray(row && row.values) ? row.values : [])
                .map(value => String(value).trim()).filter(Boolean);
            if (!domain || values.length === 0) continue;
            hosts[domain] = values.length === 1 ? values[0] : values;
        }
        if (Object.keys(hosts).length === 0) delete this.template.dns.hosts;
        else this.template.dns.hosts = hosts;
    }

    setDnsServers(servers) {
        if (!this.dnsEnabled()) return;
        this.template.dns.servers = XraySettingsEditor.clone(Array.isArray(servers) ? servers : []);
    }

    fakeDnsRows() {
        const rows = Array.isArray(this.template.fakedns) ? this.template.fakedns : this.template.fakeDns;
        return Array.isArray(rows) ? XraySettingsEditor.clone(rows) : [];
    }

    setFakeDnsRows(rows) {
        delete this.template.fakeDns;
        if (!Array.isArray(rows) || rows.length === 0) delete this.template.fakedns;
        else this.template.fakedns = XraySettingsEditor.clone(rows);
    }

    view() {
        return {
            freedomStrategy: this.freedomStrategy(),
            routingDomainStrategy: this.routingDomainStrategy(),
            log: this.logSettings(),
            dnsEnabled: this.dnsEnabled(),
            dns: this.dnsSettings(),
            fakeDns: this.fakeDnsRows(),
        };
    }

    static isEncryptedDnsAddress(address) {
        return /^(https|https\+local|h2c|h2c\+local|quic\+local):\/\//i.test(String(address || ''));
    }

    static dnsServerToForm(server) {
        const defaults = {
            address: 'localhost', port: 53, domains: [], expectedIPs: [], unexpectedIPs: [],
            queryStrategy: 'UseIP', skipFallback: false, disableCache: false, finalQuery: false,
            tag: '', clientIP: '', serveStale: false, serveExpiredTTL: 0, timeoutMs: 4000,
        };
        if (typeof server === 'string') return Object.assign(defaults, {address: server});
        if (!XraySettingsEditor.isObject(server)) return defaults;
        const form = Object.assign(defaults, XraySettingsEditor.clone(server));
        form.address = server.address || 'localhost';
        form.port = Number(server.port) || 53;
        form.domains = Array.isArray(server.domains) ? server.domains.map(String) : [];
        form.expectedIPs = (Array.isArray(server.expectedIPs) ? server.expectedIPs : server.expectIPs || []).map(String);
        form.unexpectedIPs = Array.isArray(server.unexpectedIPs) ? server.unexpectedIPs.map(String) : [];
        return form;
    }

    static dnsServerFromForm(form, original) {
        const values = XraySettingsEditor.dnsServerToForm(form);
        const domains = values.domains.map(String).map(value => value.trim()).filter(Boolean);
        const expectedIPs = values.expectedIPs.map(String).map(value => value.trim()).filter(Boolean);
        const unexpectedIPs = values.unexpectedIPs.map(String).map(value => value.trim()).filter(Boolean);
        const address = String(values.address || '').trim();
        const isPlain = domains.length === 0 && expectedIPs.length === 0 && unexpectedIPs.length === 0 &&
            Number(values.port) === 53 && values.queryStrategy === 'UseIP' && !values.skipFallback &&
            !values.disableCache && !values.finalQuery && !values.tag && !values.clientIP &&
            !values.serveStale && Number(values.serveExpiredTTL) === 0 && Number(values.timeoutMs) === 4000;
        if (isPlain) return address;

        const server = XraySettingsEditor.isObject(original) ? XraySettingsEditor.clone(original) : {};
        Object.assign(server, {
            address,
            domains,
            expectedIPs,
            unexpectedIPs,
            queryStrategy: values.queryStrategy,
            skipFallback: values.skipFallback === true,
            disableCache: values.disableCache === true,
            finalQuery: values.finalQuery === true,
            serveStale: values.serveStale === true,
            serveExpiredTTL: Math.max(0, Number(values.serveExpiredTTL) || 0),
            timeoutMs: Math.max(0, Number(values.timeoutMs) || 0),
        });
        delete server.expectIPs;
        if (XraySettingsEditor.isEncryptedDnsAddress(address)) delete server.port;
        else server.port = Math.min(65535, Math.max(1, Number(values.port) || 53));
        if (values.tag) server.tag = String(values.tag).trim(); else delete server.tag;
        if (values.clientIP) server.clientIP = String(values.clientIP).trim(); else delete server.clientIP;
        return server;
    }

    static dnsServerAddress(server) {
        if (typeof server === 'string') return server;
        if (!XraySettingsEditor.isObject(server)) return '';
        const port = server.port && !XraySettingsEditor.isEncryptedDnsAddress(server.address) ? `:${server.port}` : '';
        return `${server.address || ''}${port}`;
    }
}
