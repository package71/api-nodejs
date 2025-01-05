const APIerror = require('../error/api.js');

const user = (user) => {

    return new Promise(resolve => {
        if (user.session.auth && user.session.user_id)
            resolve({status: true, user_id: user.session.user_id});
        else
            resolve({status: false})

    });
};
const admin = (user) => {
    return new Promise(resolve => {
        resolve({status: false});
    });
};

const checkAuth = (level, auth) => {
    return new Promise((resolve, reject) => {
        if (level === 1 && !auth.user.status)
            return reject(APIerror.create('You are not authorized User', 'unauthorized', {
                pos: 'modules/api/auth.js(controller):#1',
                level: level,
                type: 'user'
            }, 0, 40301, 403));

        if (level === 2 && auth.admin.NotAllowed)
          return reject(APIerror.create('You are not allowed to call this method', 'unauthorized', {
            pos: 'modules/api/auth.js(controller):#3',
            level: level,
            type: 'admin'
          }, 0, 40505, 405));
        if (level === 2 && auth.admin.InvalidIP)
          return reject(APIerror.create('Your authorization issued for other IP.', 'unauthorized', {
            pos: 'modules/api/auth.js(controller):#4',
            level: level,
            type: 'admin'
          }, 0, 40303, 403));
        if (level === 2 && auth.admin.InvalidCSRF)
          return reject(APIerror.create('Invalid CSRF token.', 'unauthorized', {
            pos: 'modules/api/auth.js(controller):#5',
            level: level,
            type: 'admin'
          }, 0, 40306, 403));
        if (level === 2 && !auth.admin.status)
            return reject(APIerror.create('You are not authorized Admin', 'unauthorized', {
                pos: 'modules/api/auth.js(controller):#2',
                level: level,
                type: 'admin'
            }, 0, 40302, 403));

        resolve(auth);
    });
};
module.exports = {admin: admin, user: user, checkAuth: checkAuth};
