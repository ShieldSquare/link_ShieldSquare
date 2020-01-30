'use strict';

/*
 * API includes
 */
const Site = require('dw/system/Site');
const Status = require('dw/system/Status');
const Logger = require('dw/system/Logger');

/**
 * Script Includes
 */
var ShieldSquare = require('int_shieldsquare_core/cartridge/controllers/ShieldSquare.js');

exports.onRequest = function () {
	
	ShieldSquare.BuildRequest();
		
	return new Status(Status.OK);
	
}