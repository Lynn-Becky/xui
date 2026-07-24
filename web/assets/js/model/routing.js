class RoutingRuleModel {
    static splitList(value) {
        if (Array.isArray(value)) {
            return value.map(item => String(item).trim()).filter(Boolean);
        }
        return String(value || '').split(/[\n,]/).map(item => item.trim()).filter(Boolean);
    }

    static toForm(rule) {
        const source = rule && typeof rule === 'object' ? rule : {};
        return {
            enabled: source.enabled !== false,
            domain: (source.domain || []).join(', '),
            ip: (source.ip || []).join(', '),
            port: source.port || '',
            sourcePort: source.sourcePort || '',
            network: source.network || '',
            sourceIP: (source.sourceIP || []).join(', '),
            user: (source.user || []).join(', '),
            inboundTag: Array.isArray(source.inboundTag) ? source.inboundTag.slice() : [],
            protocol: Array.isArray(source.protocol) ? source.protocol.slice() : [],
            outboundTag: source.outboundTag || '',
            balancerTag: source.balancerTag || '',
        };
    }

    static fromForm(form, original) {
        const rule = JSON.parse(JSON.stringify(original || {}));
        const values = form || {};
        const managed = {
            type: 'field',
            enabled: values.enabled !== false,
            domain: this.splitList(values.domain),
            ip: this.splitList(values.ip),
            port: String(values.port || '').trim(),
            sourcePort: String(values.sourcePort || '').trim(),
            network: String(values.network || '').trim(),
            sourceIP: this.splitList(values.sourceIP),
            user: this.splitList(values.user),
            inboundTag: this.splitList(values.inboundTag),
            protocol: this.splitList(values.protocol),
            outboundTag: String(values.outboundTag || '').trim(),
            balancerTag: String(values.balancerTag || '').trim(),
        };
        Object.assign(rule, managed);
        for (const key of Object.keys(rule)) {
            const value = rule[key];
            if (value === '' || value === undefined || (Array.isArray(value) && value.length === 0) ||
                (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0)) {
                delete rule[key];
            }
        }
        return rule;
    }

    static isApiRule(rule) {
        return !!rule && rule.outboundTag === 'api' && Array.isArray(rule.inboundTag) && rule.inboundTag.includes('api');
    }

    static hasMatcher(rule) {
        const ignored = new Set(['type', 'enabled', 'outboundTag', 'balancerTag']);
        return Object.keys(rule || {}).some(key => !ignored.has(key));
    }
}

class RoutingRulesEditor {
    constructor(templateText) {
        const template = JSON.parse(String(templateText || '').trim());
        if (!template || typeof template !== 'object' || Array.isArray(template)) {
            throw new Error('Xray 配置模版必须是 JSON 对象。');
        }
        if (!template.routing || typeof template.routing !== 'object' || Array.isArray(template.routing)) {
            template.routing = {};
        }
        if (!Array.isArray(template.routing.rules)) {
            template.routing.rules = [];
        }
        this.template = template;
        this.rules = template.routing.rules;
    }

    serialize() {
        return JSON.stringify(this.template, null, 2);
    }

    outboundTags() {
        return Array.from(new Set((this.template.outbounds || []).map(item => item && item.tag).filter(Boolean)));
    }

    balancerTags() {
        return Array.from(new Set((this.template.routing.balancers || []).map(item => item && item.tag).filter(Boolean)));
    }
}
