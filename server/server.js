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
  getAccountNameAvalibility,
  updateProfileData,
} = require('./handlers');

express() 
  .use(bodyParser.json())
  .get('/api/signNft', signNft)
  .get('/api/getAccountNameAvalibility', getAccountNameAvalibility)
  .post('/api/getAccessTokenC', getAccessTokenC)
  .post('/api/verifyAccessTokenC', verifyAccessTokenC)
  .post('/api/signup', signup)
  .post('/api/getAccessTokenA', getAccessTokenA)
  .post('/api/verifyAccessTokenA', verifyAccessTokenA)
  .post('/api/getAccountDetails', getAccountDetails)
  .post('/api/updateTermsSigned', updateTermsSigned)
  .put('/api/updateProfileData', updateProfileData)
  .listen(PORT, () => {
    console.log(`App listening on port ${PORT}`);
  });
