'use strict';
const crypto = require('crypto');

module.exports = Cookies;

function Cookies(ctx, secret) {
    
    return new _Cookies(ctx, secret);
}

class _Cookies {
    constructor(ctx, secret) {
        this.req = ctx.req;
        this.res = ctx.res;
        this.secret = secret;

        this.parsed = undefined;
        if (ctx.cookies) {
            this.headers = ctx.cookies.headers;
        }
        else {
            this.headers = [];
            this.res.setHeader('Set-Cookie', this.headers);
        }
    }

    get(name) {
        if (this.parsed === undefined) {
            this.parsed = {};

            const header = this.req.headers['cookie'];
            if (header !== undefined) {

                const cookies = header.split(';');
                for (const cookie of cookies) {
                    const pos = cookie.indexOf('=');
                    const name = cookie[0] === ' ' ? cookie.slice(1, pos) : cookie.slice(0, pos);
                    const value = signedCookie(cookie.slice(pos + 1), this.secret);

                    this.parsed[name] = value;
                }
            }
        }
        return this.parsed[name];
    }

    set(name, value, attrs = default_attrs) {
        if (this.res.headersSent)
            throw new Error();

        name = name || 'key';
        value = value || 'value';

        if (attrs.signed) {
            const hmac = crypto.createHmac('sha256', this.secret).update(value).digest('base64').replace(/\=+$/, '');
            value = 's:' + value + '.' + hmac;
        }

        this.headers.push(new _Cookie(name, value, attrs));
    }

    createCookie (name, value, attrs = default_attrs) {
        return new _Cookie(name, value, attrs);
    }
}

class _Cookie {
    constructor(name, value, attrs = default_attrs) {
        this.name = name;
        this.value = value;
        this.attrs = attrs;
    }

    toString() {
        let header = this.name + '=' + this.value;

        const attrs = this.attrs;
        if (attrs.expires) header += '; expires=' + attrs.expires;
        if (attrs.max_age) header += '; max-age=' + attrs.max_age;
        if (attrs.domain) header += '; domain=' + attrs.domain;
        if (attrs.path) header += '; path=' + attrs.path;
        if (attrs.secure) header += '; secure';
        if (attrs.httponly) header += '; httponly';
        if (attrs.signeg) header += '; signed';

        return header;
    }
}

const default_attrs = {
    expires: undefined, max_age: undefined,
    domain: undefined, path: undefined,
    secure: false, httponly: false, signed: false,
};

function signedCookie(str, secret) {
    if (str.substr(0, 2) !== 's:') {
        return str;
    }
    const hmac = crypto.createHmac('sha256', secret).update(str.slice(2, str.lastIndexOf('.'))).digest('base64').replace(/\=+$/, '');
    const signature = str.slice(str.lastIndexOf('.') + 1);
    const val = hmac == signature ? str.slice(2, str.lastIndexOf('.')) : false;

    if (val !== false) {
        return val;
    }
    else {
        console.log('Signature error');
        return false;
    }
}
