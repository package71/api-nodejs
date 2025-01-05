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
    "variables": [],
    "info": {
        "name": config_local.project_name,
        "_postman_id": "4fae65dc-abd6-7a9e-7baa-a4ef183cb85b",
        "description": "",
        "schema": "https://schema.getpostman.com/json/collection/v2.0.0/collection.json"
    },
    "item": []
};

function findOrCreateGroup(nameGroup) {

    for (let i in methods.item) {
        if (methods.item.hasOwnProperty(i) && methods.item[i].name === nameGroup)
            return i;
    }
    let new_index = methods.item.push({
        "name": nameGroup,
        "description": "",
        "item": []
    });
    return (new_index - 1);

}

function addMethod(docs) {
    if (!docs.group || docs.group === '') docs.group = 'Other API';
    let groupIndex = findOrCreateGroup(docs.group);
    let method = {
        "name": docs.method + ' - ' + docs.title,
        "request": {
            "url": config_local.shema + config_local.domain + config_local.server_path + config_local.api_path + "" + docs.method,
            "method": "POST",
            "header": [
                {
                    "key": "auth_data",
                    "value": config_local.auth,
                    "description": "Auth developer login"
                }
            ],
            "body": {
                "mode": "formdata",
                "formdata": []
            },
            "description": docs.title
        },
        "response": []
    };

    for (let i in  docs.param) {
        if (docs.param.hasOwnProperty(i)) {
            method.request.body.formdata.push({
                "key": docs.param[i].name,
                "value": docs.param[i].default || "",
                "description": docs.param[i].title,
                "type": docs.param[i].type === 'file' ? 'file' : 'text'
            });
        }
    }
    methods.item[groupIndex].item.push(method);
}

module.exports = () => {
    return new Promise((resolve, reject) => {
        resolve(API.API.docs);
    }).mapSeries(el_docs => {
        addMethod(el_docs);
        return el_docs;
    }).then(all => {
        // let dateString = new Date().toISOString();
        // fs.writeFile('./_docs/history/postman_' + dateString + '.postman_collection', JSON.stringify(methods), (err) => {
        //     if (err)
        //         return console.error('Error save /_docs/history/postman_' + dateString + '.postman_collection,', err);
        // });
        fs.writeFile(path.normalize(__dirname + '/../../_docs/postman.postman_collection'), JSON.stringify(methods), (err) => {
            if (err)
                return console.error('Error save /_docs/postman.postman_collection,', err);

            // console.log('Saved exported json api for Postman: '+config_local.shema + config_local.domain + config_local.server_path +'api/export/postman')
        });
    });
};