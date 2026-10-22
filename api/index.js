const { handleApi } = require('../lib/api');

module.exports = (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.searchParams.get('__p');
  if (p !== null) {
    url.searchParams.delete('__p');
    url.pathname = '/api/' + p;
  }
  return handleApi(req, res, url);
};