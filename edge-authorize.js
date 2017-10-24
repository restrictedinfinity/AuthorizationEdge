'use strict';
const https = require('https');
const crypto = require('crypto');
const functionLocation = JSON.stringify(process.env.AWS_REGION);

/*Authorization and secrets*/
const authPolicyCookieName = "x-clima-edge-authorization=";
const authPolicyEncryptionAlgorithm = 'aes-256-ctr';
const authPolicyEncryptionKey = 'LLotVJ?jq?nhF*Q8&2f'; //KEEP THIS SECRET, anyone with access to this key can get access. 

exports.handler = (event, context, callback) => {
    console.log("service log event: " + JSON.stringify(event));
    const request = event.Records[0].cf.request;
  
    /*Viewer Information*/
    var viewerPolicy = getUserPolicy(request.headers);
    console.log("Policy" + JSON.stringify(viewerPolicy));
    var isPremiumUser = (viewerPolicy.Statement.Effect === 'PREMIUM-ACCESS');
    
    /*Start generating CloudFront response*/
    var response = CloudFrontResponseTemplate;
    
    /*Personalize response-body based for the viewer. Insert advertisement for non-premium/basic user*/
    var responseBody = htmlTemplate.replace('USER-NAME', 'Welcome:' + viewerPolicy.UserName);
    responseBody = responseBody.replace('AWS-LOCATION',functionLocation);
    if(isPremiumUser) {
        responseBody = responseBody.replace('SESSION-STATUS', viewerPolicy.Statement.Effect + ", expires in (s):" + (parseInt(viewerPolicy.Expiration) - (new Date()).getTime())/1000);
    } else {
        responseBody = responseBody.replace('SESSION-STATUS', viewerPolicy.Statement.Effect);
    }
    responseBody = responseBody.replace('AUTHENTICATION-POLICY', 'Authentication Policy' + JSON.stringify(viewerPolicy, null, 4));
    
    //For debugging, return viewer event as response header if 'x-clima-edge-debug' header is set to 'true'
    if(request.headers['x-clima-edge-debug'] && request.headers['x-clima-edge-debug'][0].value.toLowerCase() === "true") {
        response.headers['x-clima-edge-request-event'] = [{
          key: 'x-clima-edge-request-event',
          value: JSON.stringify(event),
        }];
    }

    response.body = responseBody;
    console.log("service log response: " + JSON.stringify(response));
    callback(null, response);
};


/*Decrypt 'x-clima-edge-authorization' cookie to identify user, and validate PREMIUM or BASIC session*/
function getUserPolicy(headers) {
    if (headers.cookie) {
        for (let cookie of headers.cookie) {
            if(cookie.value.trim().startsWith(authPolicyCookieName)) {
                try {
                    let value = cookie.value.trim().substring(authPolicyCookieName.length);
                    let viewerPolicy = JSON.parse(decrypt(value));
                    
                    if((parseInt(viewerPolicy.Expiration) < (new Date()).getTime())) {
                        //If the policy expired, override to basic access.
                        viewerPolicy.Statement.Effect = 'BASIC-ACCESS';
                    }
                    
                    console.log("Found UserPolicy" + JSON.stringify(cookie));
                    return viewerPolicy;
                } catch (err) {
                    console.log("Errored parsing cookie, defaulting to UnauthenticatedPolicy" + err.message);
                    return unauthenticatedUserPolicy;
                }
            }
        }
    }
    
    console.log("Cookie not found, defaulting to UnauthenticatedPolicy" + JSON.stringify(unauthenticatedUserPolicy));
    return unauthenticatedUserPolicy;
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
    '<title>Clima Edge - Validate User Authorization</title>' +
	'<link rel="stylesheet" media="screen" href="http://d170se51itnvn3.cloudfront.net/style.css">' +
    '</head>' +
    '<body>' +
    '<h1>Clima Edge - Validate User Authorization</h1>' +
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