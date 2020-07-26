'use strict';
const uid = require('uid-safe').sync
const cookies = require('./lib/cookies.js');
const crypto = require('crypto')

module.exports = Session;

function Session(options) {

    return async (ctx, next) => {
        if (ctx.session === undefined) {

            ctx.session = new _Session(options);

            ctx.session_cookies = cookies(ctx, options.secret || 'secret');

            const id = ctx.session_cookies.get(options.name || 'connect.sid');

            if (id && global.sessions[id]) {
                ctx.session = global.sessions[ctx.session_cookies.get('connect.sid')];
            }

            ctx.session_originHash = crypto.createHash('sha1').update(JSON.stringify(ctx.session), 'utf8').digest('hex');

            const _end = ctx.res.end;
            let ended = false;
            ctx.res.end = function end(chunk, encoding) {
                if (ended) {
                    return false;
                }

                ended = true;

                if (ctx.session.saveUninitialized) {
                    ctx.session.save(ctx);
                    global.sessions[ctx.session.sessionID] = ctx.session;
                }
                else if (ctx.session_originHash !== crypto.createHash('sha1').update(JSON.stringify(ctx.session), 'utf8').digest('hex')) {

                    ctx.session.save(ctx);
                    global.sessions[ctx.session.sessionID] = ctx.session;
                }
                else if (ctx.session.rolling && global.sessions[ctx.session.sessionID]) {
                    ctx.session.save(ctx);
                }
                else {
                }

                return _end.call(ctx.res, chunk, encoding);
            }
        }

        await next();
    };
}


class _Session {
    constructor(options = default_opts) {
        this.name = options.name || 'connect.sid';
        this.sessionID = uid(24);
        this.secret = options.secret || 'secret';
        this.rolling = Boolean(options.rolling);
        this.saveUninitialized = Boolean(options.saveUninitialized);

        options.cookie.attrs = Object.assign({}, default_opts.cookies.attrs, options.cookie.attrs);
        options.cookie.attrs.signed = true;
        //expect cookie.expires specific time
        this.cooikeinfo = options.cookie.attrs;
    }

    save(ctx) {
        ctx.session_cookies.set(this.name, this.sessionID, this.cooikeinfo);
    }
}

const default_opts = {
    name: 'connect.sid',
    secret: 'secret',
    rolling: false,
    saveUninitialized: true,
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
