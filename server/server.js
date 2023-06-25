const express = require('express');
const bodyParser = require('body-parser');

const PORT = 8000;

const { 
  signNft,
  signup,
  getAccessTokenC,
  verifyAccessTokenC,
  getAccessTokenA,
  verifyAccessTokenA,
  getAccountDetails,
  updateTermsSigned,
} = require('./handlers');

express()
  .use(bodyParser.json())
  .get('/api/signNft', signNft)
  .post('/api/getAccessTokenC', getAccessTokenC)
  .post('/api/verifyAccessTokenC', verifyAccessTokenC)
  .post('/api/signup', signup)
  .post('/api/getAccessTokenA', getAccessTokenA)
  .post('/api/verifyAccessTokenA', verifyAccessTokenA)
  .post('/api/getAccountDetails', getAccountDetails)
  .post('/api/updateTermsSigned', updateTermsSigned)
  .listen(PORT, () => {
    console.log(`App listening on port ${PORT}`);
  });
