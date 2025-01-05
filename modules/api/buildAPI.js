const Promise = require("bluebird");
const fs = require('fs');
const path = require('path');
const pathProject = path.normalize(__dirname + '/../..');

console.log(pathProject);

function requireAPI(apiPath) {

    console.log("API start:" + apiPath);

    let file = fs.readFileSync(pathProject + '/api/' + apiPath);
    let lines = file.toString().split('\n');

    for (let number = 0; lines.length > number; number++) {
        if (lines[number].indexOf('API.register(') !== -1) {
            let str = lines[number];
            let name_method = str.substring(str.indexOf('(') + 1, str.indexOf(',')).replace(new RegExp('\'', 'g'), '');
            let spases = str.substring(0, str.indexOf('API'));

            console.log('JSdoc method:', name_method);
            if (lines[number - 1].indexOf('/**') === -1)
                lines.splice(number, 0, '\n' + spases + '/** @method ' + name_method + ' */');
            else
                lines[number - 1] = spases + '/** @method ' + name_method + ' */'
        }
    }


    let readyFile = lines.join('\n');
    fs.writeFileSync(pathProject + '/api/' + apiPath, readyFile);
}

fs.readdir(pathProject + '/api', (err, items) => {
    if (err)
        return console.error(err);
    for (let i = 0; i < items.length; i++) {
        if (fs.statSync(pathProject + '/api/' + items[i]).isDirectory())
            fs.readdir(pathProject + '/api/' + items[i], (err, items2) => {
                for (let i2 = 0; i2 < items2.length; i2++) {
                    if (!fs.statSync(pathProject + '/api/' + items[i] + '/' + items2[i2]).isDirectory())
                        requireAPI(items[i] + '/' + items2[i2]);
                    else
                        console.log("API Error load:" + items[i] + '/' + items2[i2]);

                }

            });
        else
            requireAPI(items[i]);
    }
});