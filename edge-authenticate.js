'use strict';
const https = require('https');
const crypto = require('crypto');
const functionLocation = JSON.stringify(process.env.AWS_REGION);

/*Authorization and secrets*/
const authPolicyCookieName = "x-clima-edge-authorization=";
const authPolicyEncryptionAlgorithm = 'aes-256-ctr';

/* TODO: Fetch encryption key from AWS KMS on container initiailization, instead of bundling along with the code*/
const authPolicyEncryptionKey = 'LLotVJ?jq?nhF*Q8&2f'; //KEEP THIS SECRET, anyone with access to this key can get access. 

exports.handler = (event, context, callback) => {
  console.log("service log event: " + JSON.stringify(event));
  const request = event.Records[0].cf.request;
  var queryString = require('querystring').parse(request.querystring);
  
  /*Start generating CloudFront response*/
  var response = CloudFrontResponseTemplate;
  var responseBody = htmlTemplate;

  var viewerPolicy = authorizeUserFor15Minutes(queryString);
  
  if(viewerPolicy.UserName === 'Unauthenticated') {
    responseBody = responseBody.replace('USER-NAME', 'Authentication Failed');
    responseBody = responseBody.replace('SESSION-STATUS', 'BASIC-ACCESS');
  } else {
    responseBody = responseBody.replace('USER-NAME', viewerPolicy.UserName);
    responseBody = responseBody.replace('SESSION-STATUS', 'PREMIUM-ACCESS');
  }
  
  responseBody = responseBody.replace('AUTHENTICATION-POLICY', 'Authentication Policy' + JSON.stringify(viewerPolicy, null, 4));
   
  responseBody = responseBody.replace('AWS-LOCATION',functionLocation);
  response.headers['set-cookie'] = [{
    key: 'Set-Cookie',
    value: 'x-clima-edge-authorization=' + encrypt(JSON.stringify(viewerPolicy))
  }];
  
  //For debugging, return viewer event as response header if 'x-clima-edge-debug' header is set to 'true'
  if(request.headers['x-clima-edge-debug'] && request.headers['x-clima-edge-debug'][0].value.toLowerCase() === "true") {
    response.headers['x-clima-edge-request-event'] = [{
      key: 'x-clima-edge-request-event',
      value: JSON.stringify(event)
    }];
  }
  
  response.body = responseBody;
  console.log("service log response: " + JSON.stringify(response));
  callback(null, response);
};

function authorizeUserFor15Minutes(queryString){
    var userPolicy = unauthenticatedUserPolicy;
    console.log("userPolicy:entry" + JSON.stringify(userPolicy));
    
    try{
        console.log("qs-auth" + JSON.stringify(queryString));
        var username =  queryString['user-name'], 
            passhash = queryString['password-hash'],
            region = queryString['region'];
        
        console.log("userPolicy:afterparse" + JSON.stringify(userPolicy));
        
        /*If user is authenticated, allow him PREMIUM access to APIs for the next 15 minutes*/
        if(authenticateUser(username, passhash, region)) {
            userPolicy.UserName = username;
            userPolicy.Expiration = new Date().getTime() /*Now*/ + 15 * 60 * 1000;
            userPolicy.Statement.Effect = 'PREMIUM-ACCESS';
        }
        console.log("userPolicy:afterauth" + JSON.stringify(userPolicy));
    } catch (err) {
        userPolicy = unauthenticatedUserPolicy;
        console.log("userPolicy:aftererror" + JSON.stringify(userPolicy));
        console.log("Failed to authenticate user, default to unauthenticatedPolicy" + err.message);
    }
    
    console.log("userPolicy:beforereturn" + JSON.stringify(userPolicy));
    return userPolicy;
}

/*DO NOT COPY THIS. Network calls to DynamoDB are not implemented to keep this exmaple simple.
This function authenticats requests where where passhash=md5(username)*/
function authenticateUser(username, passhash, region) {
    /* Connect to origin in the region where users is located, for exmaple, connect to
    ap-northeast-1 for JP,
    ap-southeast-1 for SIN,
    us-east-1 for IAD etc.
    */
    switch (region) {
      case 'NA':
        //TBD: For NA users, connect to DynamoDB in us-east-1, get pass-hash to validate user, and getPolicy.
        break;
      case 'EU':
        //TBD: For EU users, connect to DynamoDB in eu-west-1, get pass-hash to validate user, and getPolicy.
        break;
      case 'JP':
        //TBD: For JP users, connect to DynamoDB in ap-northeast-1.amazonaws.com, get pass-hash to validate user, and getPolicy.
        break;
    }
    
    /*DO NOT COPY THIS. Network calls to DynamoDB are not implemented to keep this exmaple simple.
    This function authenticats requests where where passhash=md5(username)*/
    var userregionhash = crypto.createHash('md5').update(JSON.stringify(username)+JSON.stringify(region)).digest("hex");
    
    console.log('passhash: ' + passhash + ', userregionhash: ' + userregionhash + ', authenticated: ' + (userregionhash == passhash));
    return (userregionhash == passhash);
}

/*Encrypt plain text to cipher text using symetric keys*/
function encrypt(text){
  var cipher = crypto.createCipher(authPolicyEncryptionAlgorithm,authPolicyEncryptionKey);
  var crypted = cipher.update(text,'utf8','base64');
  crypted += cipher.final('base64');
  return crypted;
}

/*Decrypt cipher text to plain text using symetric keys*/
function decrypt(text){
  var decipher = crypto.createDecipher(authPolicyEncryptionAlgorithm,authPolicyEncryptionKey);
  var dec = decipher.update(text,'base64','utf8');
  dec += decipher.final('utf8');
  return dec;
}

/* Template to generate response*/
const CloudFrontResponseTemplate = {
  "status": '200',
  "statusDescription": 'OK',
  "headers": {
    "vary": [{
      "key": 'Vary',
      "value": '*',
    }]
  },
  "body": '',
};

/*Not implemented here for simplicity, but like HTML template and advertisements in Lambda@Edge function 'clima-edge-forecast',
  this HTML template can be cached in CloudFront and dynamically loaded by the function at runtime. Follow that exmaple to externalize
  this template*/
const htmlTemplate = 
    '<!DOCTYPE html>' +
    '<html style="width: 100%; text-align: center;">' +
    '<head>' +
    '<title>Clima Edge - Authenticate, and Authorize</title>' +
	'<link rel="stylesheet" media="screen" href="http://d170se51itnvn3.cloudfront.net/style.css">' +
    '</head>' +
    '<body>' +
    '<h1>Clima Edge - Authenticate, and Authorize  User for 15 minutes</h1>' +
    '<h2>USER-NAME</h2>' +
    '<h3>SESSION-STATUS</h3>' +
    '<h3><pre>AUTHENTICATION-POLICY</pre></h3>' +
    '<footer>' +
    '<p>Served from an AWS location near AWS-LOCATION. Powered by Lambda@Edge.</p>' +
    '</footer>' +
    '</body>' +
    '</html>';

/*Not implemented here for simplicity, but like HTML template and advertisements in Lambda@Edge function 'clima-edge-forecast',
  this HTML template can be cached in CloudFront and dynamically loaded by the function at runtime. Follow that exmaple to externalize
  this template*/
  
/*User authentication policy template for un-authenticated user*/
const unauthenticatedUserPolicy = {
  "_comment": "Clima Edge Authorization Policy.",
   "Version": "Clima-Edge-2017-10-30",
   "UserName": "Unauthenticated",
   "Expiration": "0", //Epoc time
   "Statement": {
       "Effect": "BASIC-ACCESS", 
       /*Permissible values PREMIUM-ACCESS for premium users, and BASIC-ACCESS for basic users*/
       "Action": "GET",
       "Resource": "/api/*"
    }
};