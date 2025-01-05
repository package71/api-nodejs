const Promise = require("bluebird");
const config = require("../config");
Error.stackTraceLimit = 10;

function create_error(message, type, params, level, errorCode, statusCode) {
    let message_stack = undefined;
    if(!!config.get('server:api:debug:stack')) {
        message_stack= '';
        let stack_ = (new Error()).stack.replace(new RegExp('    ', 'g'), '').replace(new RegExp('at ', 'g'), '').replace(new RegExp('Promise.(.*).err', 'g'), 'Promise').split("\n");
        if (stack_[2] && stack_[2].indexOf('bluebird') === -1 && stack_[2].indexOf('modules/error/api') === -1) message_stack += stack_[2];
        if (stack_[3] && stack_[3].indexOf('bluebird') === -1 && stack_[3].indexOf('modules/error/api') === -1) message_stack += '\n' + stack_[3];
        if (stack_[4] && stack_[4].indexOf('bluebird') === -1 && stack_[4].indexOf('modules/error/api') === -1) message_stack += '\n' + stack_[4];
        if (stack_[5] && stack_[5].indexOf('bluebird') === -1 && stack_[5].indexOf('modules/error/api') === -1) message_stack += '\n' + stack_[5];
        if (stack_[6] && stack_[6].indexOf('bluebird') === -1 && stack_[6].indexOf('modules/error/api') === -1) message_stack += '\n' + stack_[6];
        if (stack_[7] && stack_[7].indexOf('bluebird') === -1 && stack_[7].indexOf('modules/error/api') === -1) message_stack += '\n' + stack_[7];
        if (stack_[8] && stack_[8].indexOf('bluebird') === -1 && stack_[8].indexOf('modules/error/api') === -1) message_stack += '\n' + stack_[8];
        if (stack_[9] && stack_[9].indexOf('bluebird') === -1 && stack_[9].indexOf('modules/error/api') === -1) message_stack += '\n' + stack_[9];
    }
    return {
        apiError: true,
        message,
        errorType: type,
        object: params,
        level,
        errorCode,
        stack: message_stack,
        statusCode
    }
}

/**
 *
 * @name API.error.response
 *
 * @param {string} message - response.error.message
 * @param {number} errorCode - response.error.errorCode
 * @param {object} params - response.error.object
 *
 * @returns {Promise} - REJECT for API response
 */
function init_error(message, errorCode, params) {
    if(!params || typeof params !== 'object')
        params = {};
    return Promise.reject(create_error(message, 'api', params, 0, errorCode))
}

function validate_error(err) {
    if (err.apiError) return Promise.reject(err);
    if (err.error && err.error.apiError) return Promise.reject(err.error);

    let message = 'not message';
    let stack = 'no stack';
    if (typeof err === "string") message = err;
    if (err && typeof err.message === "string") message = err.message;
    if (err && typeof err.stack === "string") stack = err.stack;
    let err_obj = {err: err, stack};
    return Promise.reject(create_error(message, 'api', err_obj, 1, 500));
}

/**
 *
 * @name API.error.soon
 *
 * @returns {Promise} - REJECT for API response (method in development)
 */
function soon() {
    let message = 'method in development';
    let stack = 'no stack';
    let err_obj = {stack};
    return Promise.reject(create_error(message, 'api', err_obj, 1, 500));
}

module.exports.create = create_error;
module.exports.response = init_error;
module.exports.validate = validate_error;
module.exports.soon = soon;
