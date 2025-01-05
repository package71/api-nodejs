const APIConfig = require("../../index");
module.exports = async function (ip, headers, countryCode) {
  if(APIConfig && APIConfig.geoipFn) return APIConfig.geoipFn(ip, headers, countryCode)
};
