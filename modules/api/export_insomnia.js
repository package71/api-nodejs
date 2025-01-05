const API = require('../api');
const config = require('../config');
const Promise = require("bluebird");
const path = require("path");
const fs = require("fs");

const config_local = {
    auth: 'test1@gmail.com:qweqwe',
    api_path: config.get('api_path'),
    server_path: config.get('server_path'),
    domain: config.get('domain'),
    project_name: config.get('project_name'),
    shema: config.get('shema') + '://'
};
let methods = {
    "_type": "export",
    "__export_format": 3,
    "__export_date": "2017-01-10T23:15:55.928Z",
    "__export_source": "insomnia.desktop.app:v4.0.13",
    "resources": [ {
        _id: "main" + '-' + (new Date().getTime()),
        created: 1517111364925,
        description: "",
        environment: {},
        metaSortKey: -1517111364925,
        modified: 1517111364925,
        name: config_local.project_name,
        parentId: null,
        _type: "request_group"
    }]
};

function findOrCreateGroup(nameGroup) {

    for (let i in methods.resources) {
        if (methods.resources.hasOwnProperty(i) && methods.resources[i].nameGroup === nameGroup)
            return methods.resources[i]._id;
    }
    let opGroup ={
        _id: 'group-' + nameGroup + '-' + (new Date().getTime()),
        created: 1517111364925,
        nameGroup: nameGroup,
        description: nameGroup,
        environment: {},
        metaSortKey: -1517111364925,
        modified: 1517111364925,
        name: nameGroup,
        parentId: methods.resources[0]._id,
        _type: "request_group"
    };
    methods.resources.push(opGroup);
    return opGroup._id;

}

function addMethod(docs) {
    if (!docs.group || docs.group === '') docs.group = 'Other API';
    let groupKey = findOrCreateGroup(docs.group);

    let method = {
        "_type": "request",
        "_id": "req-" + docs.method + '-' + (new Date().getTime()),
        "parentId": groupKey,
        "created": 1484090000356,
        "modified": 1484090000356,
        "name": docs.method + ' - ' + docs.title,
        "method": "POST",
        "url": config_local.shema + config_local.domain + config_local.server_path + config_local.api_path + "" + docs.method,
        "body": {
            "mimeType": "multipart/form-data",
            "text": "",
            "params": []
        },
        "headers": [{
            "name": "auth_data",
            "value": config_local.auth,
            "disabled": false
        }]
    };
    for (let i in  docs.param) {
        if (docs.param.hasOwnProperty(i)) {
            method.body.params.push({
                "name": docs.param[i].name,
                "value": docs.param[i].default || "",
                "description": docs.param[i].title,
                "type": docs.param[i].type === 'file' ? 'file' : 'text',
                "disabled": false
            });
        }
    }
    methods.resources.push(method);
}

module.exports = () => {
    return new Promise((resolve, reject) => {
        resolve(API.API.docs);
    }).mapSeries(el_docs => {
        addMethod(el_docs);
        return el_docs;
    }).then(all => {
        // let dateString = new Date().toISOString();
        // fs.writeFile('./_docs/history/insomnia_' + dateString + '.json', JSON.stringify(methods), (err) => {
        //     if (err)
        //         return console.error('Error save /_docs/history/insomnia_' + dateString + '.json,', err);
        // });
        fs.writeFile(path.normalize(__dirname + '/../../_docs/insomnia.json'), JSON.stringify(methods), (err) => {
            if (err)
                return console.error('Error save /_docs/insomnia.json,', err);

            // console.log('Saved exported json api for Insomnia: '+config_local.shema + config_local.domain + config_local.server_path +'api/export/insomnia')
        });
    });
};