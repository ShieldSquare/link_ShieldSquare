/**
* Description of the Controller and the logic it provides
*
* @module  controllers/ShieldSquare
*/

'use strict';
let Site = require('dw/system/Site').getCurrent();
let ShieldSquareHelper = require('*/cartridge/scripts/lib/ShieldSquareHelper.js');
let ssLogger = require("dw/system/Logger").getLogger("ShieldSquare","shieldsquare");
let shieldSquareAdvanceConfig = JSON.parse(Site.getCustomPreferenceValue('shieldSquareAdvanceConfig')).data;


// HINT: do not put all require statements at the top of the file
// unless you really need them for all functions

/**
* This function is sending request to Shied Square server on every page load. 
* This function will check if current user request is authenticated or not using Shield Square server API
**/
function buildRequest(){
	let requestObj  = ShieldSquareHelper.buildRequestObject(),
		configServiceReq = require('*/cartridge/scripts/services/ShieldSquareService').getSQServices(),
		configServiceObj = configServiceReq.shieldSquareRequest();
		
	let result = configServiceObj.call(requestObj);
	if(result.status == "OK") {
		let parseResult = JSON.parse(result.object);
		if(parseResult.ssresp == 0) {
			// Store the response 
			ssLogger.info("Sheildsquare Success Response: {0}", result.object);
		} else if (parseResult.ssresp == 2) {
			let sceme = shieldSquareAdvanceConfig._api_server_ssl_enabled == "True" ? 'https://' : 'http://', 
				queryString = ShieldSquareHelper.generateRedirectUrl(parseResult.ssresp),
				redirectURL = sceme + shieldSquareAdvanceConfig._redirect_domain + queryString;
			response.redirect(redirectURL);
		}		
	} else {
		ssLogger.error("Sheildsquare error Response: {0}", result.object);
	}
	
}

exports.BuildRequest = buildRequest;