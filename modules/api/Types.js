const moment = require('moment');

class _String {
  constructor(len, options) {
    this.name = 'STRING';
    this.max = len || 255;
    if (options) {
      if (options.regexp) {
        if (options.regexpFlag)
          this.regexp = new RegExp(String(options.regexp), String(options.regexpFlag))
        else
          this.regexp = new RegExp(String(options.regexp))
      }
    }
  }

  valid(v) {
    if (!v && v !== '') return {success: false, error: 'Value undefined'};
    v = String(v);
    if (typeof v !== 'string') return {success: false, error: 'Value is not string'};
    if (v.length > this.max) return {success: false, error: 'Value length > ' + this.max};
    if (this.regexp && !this.regexp.test(v)) return {success: false, error: 'Value not valid regexp'};
    return {success: true, value: v};
  }
}

class _Boolean {
  constructor() {
    this.name = 'BOOLEAN';
  }

  valid(v) {
    if (v === 1) v = true;
    if (v === 0) v = false;
    if (v === '1') v = true;
    if (v === '0') v = false;
    if (v === 'true') v = true;
    if (v === 'false') v = false;
    if (typeof v !== 'boolean') return {success: false, error: 'Value is not boolean'};
    return {success: true, value: Boolean(v)};
  }
}

class _Enum {
  constructor(values) {
    this.name = 'ENUM';
    this.enums = values;
    if (typeof this.enums !== 'object' || !Array.isArray(this.enums))
      this.enums = [];
  }

  valid(v) {
    if (this.enums.indexOf(v) === -1)
      return {success: false, error: 'Value invalid enum: ' + this.enums.join(',')};

    return {success: true, value: v};
  }
}

class _Float {
  // IEEE_754-2008 - Standard for Floating-Point Arithmetic
  constructor(length, fixed, options) {
    this.max = length || 10;
    this.name = 'FLOAT';

    this.fixed = fixed || 4;
    if (options) {
      if (options.regexp) {
        if (options.regexpFlag)
          this.regexp = new RegExp(String(options.regexp), String(options.regexpFlag))
        else
          this.regexp = new RegExp(String(options.regexp))
      }
    }
  }

  valid(v) {
    if (v === undefined) return {success: false, error: 'Value undefined'};
    v = Number(v);
    if (typeof v !== 'number') return {success: false, error: 'Value is not string'};
    if (isNaN(v)) return {success: false, error: 'Value NaN'};
    if (!isFinite(v)) return {success: false, error: 'Value Infinity'};
    if (String(v).length > this.max) return {success: false, error: 'Value length > ' + this.max};
    // Gaussovo (bank rounding)
    let d = this.fixed || 0,
      m = Math.pow(10, d),
      n = +(d ? v * m : v).toFixed(8),
      i = Math.floor(n), f = n - i,
      e = 1e-8,
      r = (f > 0.5 - e && f < 0.5 + e) ?
        ((i % 2 === 0) ? i : i + 1) : Math.round(n);

    v = d ? r / m : r;
    if (this.regexp && !this.regexp.test(v)) return {success: false, error: 'Value not valid regexp'};


    return {success: true, value: v};
  }
}

function isInteger(num) {
  return (num ^ 0) === num;
}

class _Intenger {
  constructor(length, options) {
    this.max = length || 10;
    this.name = 'INTEGER';

    this.fixed = 0;
    if (options) {
      if (options.regexp) {
        if (options.regexpFlag)
          this.regexp = new RegExp(String(options.regexp), String(options.regexpFlag))
        else
          this.regexp = new RegExp(String(options.regexp))
      }
    }
  }

  valid(v) {
    if (!v && v !== 0 && v !== '0') return {success: false, error: 'Value is required'};
    v = Number(v);
    if (typeof v !== 'number') return {success: false, error: "Value isn't number"};
    if (isNaN(v)) return {success: false, error: 'Value is NaN'};
    if (!isFinite(v)) return {success: false, error: 'Value is Infinity'};
    if (String(v).length > this.max) return {success: false, error: 'Value length > ' + this.max};
    if (!isInteger(v)) return {success: false, error: 'Value isn\'t Integer'};
    if (this.regexp && !this.regexp.test(v)) return {success: false, error: 'Value not valid regexp'};


    return {success: true, value: v};
  }
}

class _Date {
  constructor(options) {
    this.name = 'DATE';
    if (options) {
      if (options.unix)
        this.unix = options.unix;

      if (options.zone_utc && typeof options.zone_utc === 'number')
        this.zone_utc = options.zone_utc;
    }
  }

  valid(v) {
    if (!v) return {success: false, error: 'Value undefined'};

    if (typeof v !== 'string' && typeof v !== 'number') return {success: false, error: 'Value invalid typeof'};

    if (!moment(v).isValid())
      return {success: false, error: 'Value Invalid Date'};
    v = moment(v);
    if (this.zone_utc)
      v = v.utcOffset(this.zone_utc);

    return {success: true, value: v.format()};

  }
}

class _File {
  constructor() {
    this.name = 'FILE';
  }

  valid(v) {
    return {success: true, value: v};
  }
}

class _Array {
  constructor() {
    this.name = 'ARRAY';
  }

  valid(v) {
    if (typeof v === 'string')
      v = v.split(',');
    if (!Array.isArray(v))
      return {success: false, error: 'Value is not array'};

    return {success: true, value: v};
  }
}

class _Object {
  constructor() {
    this.name = 'OBJECT';
  }

  valid(v) {
    if (typeof v !== 'object')
      return {success: false, error: 'Value is not object'};
    return {success: true, value: v};
  }
}

const DATE = (length, options) => {
  return new _Date(length, options);

};

const STRING = (length, options) => {
  return new _String(length, options);
};

const FLOAT = (length, fixed, options) => {
  /*
        ┌────────── fixed (3)
     13.556 ───────── length (5)
  */
  return new _Float(length, fixed, options);

};
const INTEGER = (length, options) => {
  return new _Intenger(length, options);
};
const ENUM = (...values) => {
  return new _Enum(values);
};
const FILE = () => {
  return new _File();
};

const BOOLEAN = () => {
  return new _Boolean();
};

const ARRAY = () => {
  return new _Array();
};

const OBJECT = () => {
  return new _Object();
};


module.exports = {
  DATE,
  STRING,
  FLOAT,
  ENUM,
  INTEGER,
  BOOLEAN,
  FILE,
  ARRAY,
  OBJECT
};
