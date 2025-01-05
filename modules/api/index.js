"use strict";
const DIR_TO_ROOT = "/../../../../", config = require("../../modules/config"), path = require("node:path"),
  fs = require("node:fs");
fs.existsSync(path.normalize(__dirname + DIR_TO_ROOT + "api")) || fs.mkdirSync(path.normalize(__dirname + DIR_TO_ROOT + "api")), fs.existsSync(path.normalize(__dirname + DIR_TO_ROOT + "api_plugins")) || fs.mkdirSync(path.normalize(__dirname + DIR_TO_ROOT + "api_plugins"));
const Promise = require("bluebird"), authController = require("./auth.js"), error = require("../error/api.js"),
  TypesAPI = require("../api/Types.js"), random = require("../random"), APIConfig = require("../../index");
APIConfig.user || (APIConfig.user = (async () => ({status: !1}))), APIConfig.admin || (APIConfig.admin = (async () => ({status: !1})));
let redis = null;

function stringToRGBHash(e) {
  let r = 0;
  for (let o = 0; o < e.length; o++) r = e.charCodeAt(o) + ((r << 5) - r);
  let o = (16777215 & r).toString(16).toUpperCase();
  return "00000".substring(0, 6 - o.length) + o
}

APIConfig.redis ? redis = APIConfig.redis : (redis = null).publishAPI = ((e, r, o) => {
  redis.publish("api_notify", JSON.stringify({method: e, user: r, data: o}))
});
let iconsClass = {
  login: "uk-icon-sign-in",
  register: "uk-icon-address-card-o",
  tour: "uk-icon-road",
  logout: "uk-icon-sign-out",
  setting: "uk-icon-cog",
  config: "uk-icon-cog",
  list: "uk-icon-list",
  avatar: "uk-icon-photo",
  friend: "uk-icon-street-view",
  dialog: "uk-icon-comments",
  message: "uk-icon-comment",
  count: "uk-icon-sort-numeric-desc",
  language: "uk-icon-language",
  pay: "uk-icon-credit-card",
  favorite: "uk-icon-star",
  diploma: "uk-icon-picture-o",
  auth: "uk-icon-unlock",
  read: "uk-icon-eye",
  token: "uk-icon-key",
  mark: "uk-icon-thumb-tack",
  redis: "uk-icon-database",
  event: "uk-icon-calendar",
  test: "uk-icon-code",
  user: "uk-icon-user",
  wallet: "uk-icon-credit-card",
  transactions: "uk-icon-list-ul",
  transfer: "uk-icon-exchange",
  update: "uk-icon-pencil",
  upload: "uk-icon-upload",
  default: "uk-icon-exclamation-triangle"
}, controller = {}, aliases = {};

function merge(e) {
  let r = {};
  if (e) for (let o = 0; o < e.length; o++) if ("string" == typeof e[o] || "number" == typeof e[o] || "boolean" == typeof e[o]) r = e[o]; else for (let t in e[o]) "string" == typeof e[o][t] || "number" == typeof e[o][t] || "boolean" == typeof e[o][t] || "object" == typeof e[o][t] && Array.isArray(e[o][t]) ? r[t] = e[o][t] : r[t] = Object.assign({}, r[t], e[o][t]);
  return r
}

function parse(e, r) {
  let o = e.split("."), t = {};
  return o.length > 1 ? t[o[0]] = parse(o.slice(1).join("."), r) : "" !== o[0] ? t[o[0]] = r : t = r, t
}

const stackTrace = require("stack-trace");

function getPathAPI() {
  return stackTrace.get()[2].getFileName().replace(path.normalize(__dirname + DIR_TO_ROOT + "api/"), "").replace(".js", "")
}

function schemaParam(e, r, o) {
  let t = [];
  if ("object" != typeof e || e.type && e.type.valid && "function" == typeof e.type.valid) {
    if (e.type && "function" == typeof e.type.valid) if (void 0 !== r) {
      let n = e.type.valid(r);
      if (!n) return {
        error: {
          param_name: o,
          error_code: e.error_code,
          msg: "server error invalid param",
          type: "function"
        }
      };
      if (!n.success) return {error: {param_name: o, error_code: e.error_code, msg: n.error, type: "val"}};
      t.push(parse(o, n.value))
    } else if (e.required) return {error: {param_name: o, error_code: e.error_code, msg: "required", type: "val"}}
  } else {
    r || (r = {});
    for (let n in e) {
      let i = o;
      if ("array" === (Array.isArray(e[n]) ? "array" : typeof e[n])) {
        if (Array.isArray(r[n])) {
          let o = {};
          o[i + n] = [];
          for (let t in r[n]) {
            "" !== i && (i += ".");
            let a = schemaParam(e[n][0], r[n][t], "");
            if (a.error) return a;
            o[i + n].push(merge(a.newParams))
          }
          t = t.concat([o])
        }
        if (!r[n] || !r[n].length || 0 === r[n].length) {
          "" !== i && (i += ".");
          let r = schemaParam(e[n][0], void 0, i + n);
          if (r.error) return r;
          t = t.concat(r.newParams)
        }
      } else {
        i && "" !== i && (i += ".");
        let o = schemaParam(e[n], r[n], i + n);
        if (o.error) return o;
        t = t.concat(o.newParams)
      }
    }
  }
  return {newParams: t}
}

function validateParamsInMethod(e, r, o) {
  if (!r || "object" != typeof r) throw Error("#0001,error params in method: " + e + " - [" + o + "]");
  if (r.type && r.error_code) {
    if (!r.type.name) throw Error("#0002,error params in method: " + e + " - [" + o + "]")
  } else for (let o in r) {
    if (!r[o]) throw Error("#0003,error params in method: " + e + " - [" + o + "]");
    if (!r[o]) throw Error("#0005,error params in method: " + e + " - [" + o + "]");
    if (Array.isArray(r[o])) {
      if (!r[o][0]) throw Error("#0004,error params in method: " + e + " - [" + o + "]");
      return validateParamsInMethod(e, r[o][0], o)
    }
    if (!r[o].type && "object" == typeof r[o]) return validateParamsInMethod(e, r[o], o);
    if ("function" == typeof r[o].type) throw Error("#0008 (you need call fn type for create), error params in method: " + e + " - [" + o + "]");
    if (!r[o].type) throw Error("#0006,error params in method: " + e + " - [" + o + "]");
    if (!r[o].type.name) throw Error("#0007,error params in method: " + e + " - [" + o + "]")
  }
}

let API = {
  _props: function (e, r) {
    return "register" !== e && ("plugin" !== e && ("saveLog" !== e && ("call" !== e && ("docs" !== e && ("types" !== e && void (API[e] = type))))))
  },
  plugin: {iconsClass: iconsClass},
  saveLog(e, r, o, t, n, i, a) {
    APIConfig.ApiEmitter && APIConfig.ApiEmitter.emit("call", {
      method: e,
      user: o,
      param: t,
      error: r,
      response: n,
      request_id: a
    })
  },
  createAlias: (e, r) => {
    if (!e || "string" != typeof e) throw new Error("createAlias error aliasName is not valid");
    if (!r || "string" != typeof r) throw new Error("createAlias error aliasName is not valid");
    aliases[e] = r
  },
  redirect: (e, r) => Promise.resolve({
    mode: "REDIRECT",
    url: (r || config.get("shema") + "://" + config.get("domain")) + "" + e
  }),
  register: (e, r, o) => {
    "function" == typeof e && (o = r, r = e, e = ""), "" !== e && (e = "/" + e);
    if (e = getPathAPI() + e, o || (o = {
      level: 0,
      reqMethods: ["*"],
      title: e
    }), o.param || (o.param = {}), o.response || (o.response = []), "object" != typeof o.param) throw new Error("Error api param not Object in method: " + e);
    if (validateParamsInMethod(e, o.param), controller[e] || (controller[e] = {}), controller[e].fn = r, controller[e].level = o.level,  controller[e].cache = o.cache, controller[e].reqMethods = o.reqMethods, o.level || 0 === o.level || (controller[e].level = 3), controller[e].infoAndControl = o, o && !o.hide) {
      o.method = e, o.iconColor = stringToRGBHash(e);
      for (let r in API.plugin.iconsClass) if (-1 !== e.toLowerCase().indexOf(r)) {
        o.iconClass = API.plugin.iconsClass[r];
        break
      }
      o.iconClass || (o.iconClass = API.plugin.iconsClass.default), o.response && Array.isArray(o.response) || (o.response = []), o.response && (o.response.unshift({
        name: "success",
        type: "string",
        title: "Status request method",
        default: "true, false"
      }, {
        name: "error",
        type: "object",
        title: "Error data.(exists only in cases of error)",
        default: "{message,error_type,level,stack}"
      }, {name: "data", type: "object", title: "Result data.", default: "{}"}), o.response.push({
        name: "latency_ms",
        type: "int",
        title: "processing time of the request (milliseconds)",
        default: "78"
      })), o.code = r.toString().replace("(user, param) => {", "").replace(new RegExp("\n    }", "g"), "").replace(new RegExp("\n        ", "g"), "\n"), setTimeout(function () {
        let e = !0;
        for (let r in API.docs) API.docs[r].method === o.method && (API.docs[r] = o, e = !1);
        e && API.docs.push(o)
      }, 1)
    }
  },
  call: (e, r, o, t) => {
    let n = (new Date).getTime(), i = (new Date).getTime() + "-" + random.str(7, 7);
    return t || (t = "server"), o || (o = {}), aliases[e] && (e = aliases[e]), new Promise((re, o) => {
      if (!e || !controller.hasOwnProperty(e)) return o(error.create("method not found!", "api", {method_find: e, reqMethod:r.reqMethod}, 0, 40400, 404));
      if (APIConfig.enableCorsMethod && controller[e].reqMethods && !controller[e].reqMethods.includes(r.reqMethod) && "server" !== t) return o(error.create("method not found.", "api", {method_find: e, reqMethod:r.reqMethod}, 0, 40400, 404));
      re()
    }).then(() => Promise.props({
      user: APIConfig.user(r, e),
      admin: APIConfig.admin(r, e)
    }).catch(e => Promise.reject(e))).then(r => authController.checkAuth(controller[e].level, r).catch(e => Promise.reject(e))).then(e => {
      r.admin = e.admin, r.user = e.user
    }).then(() => 3 !== controller[e].level || "server" === t || Promise.reject(error.create("This method can not be used for REST-API", "forbidden", {
      pos: "modules/api/index.js(controller):#3",
      level: controller[e].level
    }, "server", 0, 40304, 403))).then(() => {
      if ("object" == typeof controller[e].infoAndControl.param && !Array.isArray(controller[e].infoAndControl.param)) {
        let r = schemaParam(controller[e].infoAndControl.param, o, "");
        if (r.error) return Promise.reject(error.create('param "' + r.error.param_name + '" ' + r.error.msg, "api", {}, 0, r.error.error_code || 500400404));
        o = Object.assign({}, o, merge(r.newParams))
      }
      return "ok"
    }).then(r => {
      if ("ok" === r) return "ok";
      if (!controller[e].infoAndControl.param) return !0;
      let t = {};
      if ("object" == typeof controller[e].infoAndControl.param && Array.isArray(controller[e].infoAndControl.param)) for (let r in controller[e].infoAndControl.param) if (controller[e].infoAndControl.param.hasOwnProperty(r) && controller[e].infoAndControl.param[r].name && (t[controller[e].infoAndControl.param[r].name] = controller[e].infoAndControl.param[r]), t[controller[e].infoAndControl.param[r].name].required && (void 0 === o[controller[e].infoAndControl.param[r].name] || null === o[controller[e].infoAndControl.param[r].name] || "" === o[controller[e].infoAndControl.param[r].name])) return Promise.reject(error.create('param "' + controller[e].infoAndControl.param[r].name + '" required', "api", {}, 0, controller[e].infoAndControl.param[r].error_code || 500400404));
      for (let e in o) if (o.hasOwnProperty(e) && t.hasOwnProperty(e) && t[e].type && "function" == typeof t[e].type.valid) {
        let r = t[e].type.valid(o[e]);
        if (!r) return Promise.reject(error.create('param "' + e + '" type error (function validator)', "api", {}, 0, t[e].error_code || 500400404));
        if (!r.success) return Promise.reject(error.create('param "' + e + '" error: ' + r.error, "api", {}, 0, t[e].error_code || 500400404));
        o[e] = r.value
      }
      return "ok"
    }).then(() => {
      let t = controller[e].fn(r, o);
      return t && t.then ? t.catch(API.error.validate) : (console.error(new Error('Server error: "' + e + '" - the method did not return a promise')), Promise.reject(error.create('Server error: "' + e + '" - the method did not return a promise', "api", {}, 10, 500)))
    }).then(n => (API.saveLog(e, null, r, o, n, t, i), n)).then(a => {
      if (!a) return Promise.reject("CORE API error {res} of undefined");
      let s = {success: !0, data: a, cache: controller[e].cache || undefined};
      return s.latency_ms = (new Date).getTime() - n, s.requestId = i, "REDIRECT" === a.mode && "string" == typeof a.url && (s.redirect = a.url), config.get("server:api:debug:log") && console.log("API success -> " + e + (r.ip && r.ip.ip ? " ip: "+ r.ip.ip : "") +" took: "+ s.latency_ms + "ms"), config.get("server:api:debug:successResponse") && console.log("API success - ", e, "*", t, "\n\tUser:", r, "\n\tParam:", o, "\n\tResponse:", s), s
    }).timeout(1e3 * config.get("server:api:timeout"), "API timeout").catch(n => (API.saveLog(e, n, r, o, {
      success: !1,
      result: !1
    }, t, i), Promise.reject(n))).catch(r => {
      if (r.apiError) return Promise.reject(r);
      console.error("Server Error:", e, ",", r);
      let t = "no_message";
      return r && "string" == typeof r && (t = "REST-API Error: " + r), r && r.message && "string" == typeof r.message && (t = "REST-API Error: " + r.message), Promise.reject(error.create("REST-API Error: " + t, "api", {
        pos: "modules/api/index.js(controller):#200",
        param: o,
        level: controller[e].level,
        type: "api"
      }, 0, 500))
    }).catch(a => {
      let s = {success: !1, error: a};
      if (s.latency_ms = (new Date).getTime() - n, s.requestId = i, config.get("server:api:debug:errorResponse")) {
        if (s && s.error && 40301 === s.error.errorCode) return Promise.reject(s);
        console.error("API error - ", e, "*", t, "\n\tUser:", r, "\n\tParam:", o, "\n\tResponse:", s)
      }
      return Promise.reject(s)
    })
  },
  docs: [],
  config: {secure: {http: "", api_server_key: ""}},
  error: error,
  types: TypesAPI,
  cache: {},
  proxy: {}
};
API.emit = API.call, API.on = API.register;
let API_cnt = 0;

function requireAPI(e) {
  if (API_cnt++, -1 !== e.indexOf(".js")) {
    let r = require(e);
    "function" == typeof r ? r(API, redis) : console.error("[Error] (api/" + e + ") Function is not defined:  \n\t\nmodule.exports = (API, redis) => {};\n")
  }
}

function readDirApi(e) {
  fs.readdir(e, (r, o) => {
    for (let r = 0; r < o.length; r++) fs.statSync(e + "/" + o[r]).isDirectory() ? readDirApi(e + "/" + o[r]) : requireAPI(e + "/" + o[r])
  })
}

fs.readdir(path.normalize(__dirname + DIR_TO_ROOT + "api_plugins"), (e, r) => {
  for (let e = 0; e < r.length; e++) if (fs.statSync(path.normalize(__dirname + DIR_TO_ROOT + "api_plugins/" + r[e])).isDirectory()) console.error("API Error load api_plugins:" + r[e] + "is not file"); else if (-1 !== r[e].indexOf(".js")) {
    let o = require(path.normalize(__dirname + DIR_TO_ROOT + "api_plugins/" + r[e]));
    if ("function" != typeof o) {
      API.plugin[r[e].replace(".js", "")] = o;
      continue
    }
    API.plugin[r[e].replace(".js", "")] = o(API)
  }
  readDirApi(path.normalize(__dirname + DIR_TO_ROOT + "api")), /* setTimeout(require("./export_postman"), 3e3), setTimeout(require("./export_insomnia"), 3e3),*/ setTimeout(function () {
    console.log("API running: " + API_cnt + " files\n\t Docs " + config.get("shema") + "://" + config.get("domain") + config.get("server_path") + config.get("api_path") + "docs/")
  }, 3e3)
}), module.exports.controller = controller, module.exports.API = API;
