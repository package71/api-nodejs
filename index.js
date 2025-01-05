const EventEmitter = require("node:events");

class APIEmitter extends EventEmitter {
}

const ApiEmitter = new APIEmitter;

class API {
    constructor(e, t) {
         module.exports.enableCorsMethod = e.enableCorsMethod || false;
        e && e.auth_user || (e = t), e && (e.auth_user && "function" == typeof e.auth_user && (module.exports.user = e.auth_user), e.auth_admin && "function" == typeof e.auth_admin && (module.exports.admin = e.auth_admin), e.redis && (module.exports.redis = e.redis), e.geoipFn && (module.exports.geoipFn = e.geoipFn), e.config && (module.exports.config = e.config)), this.expressRouter = require("./modules/api/expressRouter").router, this.API = require("./modules/api/expressRouter").API, this.expressSession = require("./modules/api/expressRouter").session, this.emitter = ApiEmitter, module.exports.ApiEmitter = ApiEmitter, ApiEmitter.emit("init", {start: !0})
    }
}

module.exports = API;
