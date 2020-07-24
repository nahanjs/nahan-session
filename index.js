'use strict';
const crypto = require('crypto');
const uid = require('uid-safe').sync
const Cookies = require('./lib/cookies.js');

module.exports = Session;

function Session(options, sessions) {

    return async (ctx, next) => {
        let flag = false;
        const id = ctx.cookies.get('connect.sid');

        if (id && sessions[id]) {
            flag = true;
        }

        if (!flag) {
            if (ctx.session === undefined)
                ctx.session = new _Session(ctx, options);
            sessions[ctx.session.sessionID] = ctx.session;
        }
        else {
            ctx.session = sessions[ctx.cookies.get('connect.sid')];
        }

        await next();
    };
}


class _Session {
    constructor(ctx, options = default_opts) {

        this.req = ctx.req;
        this.res = ctx.res;

        this.name = options.name || 'connect.sid';
        this.sessionID = uid(24);
        this.secret = options.secret || 'secret';

        this.cookie = Cookies(ctx, this.secret);
        options.cookie.attrs = options.cookie.attrs || { signed: true };
        options.cookie.attrs.signed = true;
        this.cookie.set(this.name, this.sessionID, options.cookie.attrs);

    }

}

var default_opts = {
    name: 'connect.sid',
    secret: 'secret',
    cookies: {
        name: null,
        value: null,
        attrs: {
            path: '/',
            httponly: true,
            secure: false,
            max_age: null,
            signed: true,
        },
    },
};