function randomInt(min, max) {
    // Generate number from min to max
    // Example: 3

    min = min || 0;
    max = max || 9;
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomStr(min, max) {
    // Generate string from min to max count letters
    // Example: 0VfE0SaA

    min = min || 3;
    max = max || 8;
    var n = randomInt(min, max);
    var s = '', abd = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', aL = abd.length;
    while (s.length < n)
        s += abd[Math.random() * aL | 0];
    return s;
}
function randomStr_(min, max) {
    // Generate string from min to max count letters
    // Example: 0vFt#0g$

    min = min || 3;
    max = max || 8;
    var n = randomInt(min, max);
    var s = '', abd = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+=', aL = abd.length;
    while (s.length < n)
        s += abd[Math.random() * aL | 0];
    return s;
}

function randomIntCount(min, max) {
    // Generate integer from min to max count number
    // Example: 32174

    min = min || 3;
    max = max || 8;
    var n = randomInt(min, max);
    var s = '', abd = '0123456789', aL = abd.length;
    while (s.length < n)
        s += abd[Math.random() * aL | 0];
    return s;
}
function randomKey(minK, minS, maxK, maxS) {
    // Generate key from minK to minS count number
    // Example: rKt7e4fL-xMBBEQjM-JM4e4Iyt-alRa7r8j

    minK = minK || 4;
    minS = minS || 8;
    maxK = maxK || minK;
    maxS = maxS || minS;
    var n = randomInt(minK, maxK);
    var s = '';
    for (var i=0;i < n;i++) {
        s += randomStr(minS, maxS);
        if(i != n-1)
            s +='-';

    }
    return s;
}

module.exports.count = randomInt;
module.exports.int = randomIntCount;
module.exports.str = randomStr;
module.exports.str_ = randomStr_;
module.exports.key = randomKey;