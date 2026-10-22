const { handleApi } = require('../lib/api');

module.exports = (req, res) => handleApi(req, res, new URL(req.url, 'http://x'));
