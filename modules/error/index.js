'use strict';

function PropertyError(message, stopServer) {
    this.name = "Application Error";

    // this.property = property;
    this.message = message;

    if (Error.captureStackTrace) {
        Error.stackTraceLimit = 15;
        Error.captureStackTrace(this, PropertyError);
    } else {
        this.stack = (new Error()).stack;
    }
    console.error('\n' + this.stack);
    if (stopServer)

        setTimeout(()=> {
            process.exit(500);
        }, 100);

}


PropertyError.prototype = Object.create(Error.prototype);
module.exports = PropertyError;