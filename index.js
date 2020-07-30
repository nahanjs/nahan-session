'use strict';
const uid = require('uid-safe').sync
const MemoryStore = require('./lib/store-session');

module.exports = Session;

function Session(options) {

    let opts = {};
    opts.name = options.name || 'connect.sid';
    opts.secret = options.secret || 'secret';
    opts.cookie =  { 
        path: '/',
        httponly: true,
        secure: false,
        max_age: null,
    };
    for (let [key, value] of Object.entries(options.cookie))
        opts.cookie[key] = value;

    return async (ctx, next) => {    
        if (ctx.cookies !== undefined) {

            if (ctx.cookies.secret === opts.secret) {

                if (ctx.session === undefined) {

                    ctx.store_sessions = MemoryStore.sessions;

                    const id = ctx.cookies.get(opts.name);
        
                    if (id && ctx.store_sessions[id]) {
                        ctx.session = ctx.store_sessions[id];
                    }
                    else {
                        ctx.session = new _Session(opts);
                    }

                    ctx.session.save(ctx);
                    ctx.store_sessions[ctx.session.sessionID] = ctx.session;

                }
            }
            else {
                console.log('The secret is inconsistent');
            }
        }
        else {
            console.log("Cookies not initialized");
        }

        await next();
        //Clean up expired sessions in memory store_sessions
        for (let [key, value] of Object.entries(ctx.store_sessions)) {
            if (value.expires !== null) {
                if (new Date(value.expires) < new Date(Date.now())) {
                    delete ctx.store_sessions[key];
                }
            }
        }
    };
}

class _Session {
    constructor(options) {
        this.name = options.name;
        this.sessionID = uid(24);
        this.secret = options.secret;
        this.cookie = options.cookie;
        this.expires = this.cookie.max_age === null ? null : new Date(Date.now() + this.cookie.max_age*1000);
    };

    save(ctx) {
        ctx.cookies.set(this.name, this.sessionID, this.cookie);
    }

    deleteS(ctx) {
        if (ctx.store_sessions[ctx.session.sessionID]) {
            delete ctx.store_sessions[ctx.session.sessionID];
            console.log('delete success!');
        }
    }
}
