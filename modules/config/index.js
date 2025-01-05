'use strict';
const configApi = require("../../index").config;
const cache = {};

const model = {
  get: function (param) {
    if (!param) return configApi;
    if (cache[param]) return cache[param];
    return param.split(':')
      .reduce((previous, current) => {
        if (typeof previous[current] === 'object')
          return Object.assign({}, previous[current]);
        cache[param] = previous[current]
        return previous[current]
      }, configApi);
  },
};
module.exports = model;
