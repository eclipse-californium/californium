/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/

'use strict';

const version = "Version 0.25.0, 29. October 2024";

let timeShift = 0;

function strip(value, head) {
	if (value && value.startsWith(head)) {
		return value.slice(head.length);
	}
	return null;
}

function trunc(value, tail) {
	if (value && value.endsWith(tail)) {
		return value.slice(0, -tail.length);
	}
	return null;
}

function conv(value, hexLen) {
	if (value && value.match(/^[0-9a-fA-F]+$/)) {
		let base = 0;
		if (value.match(/^[1-9]\d*$/)) {
			base = 10
		} else if ((hexLen && value.length == hexLen) ||
			(!hexLen && (value.length & 1) == 0)) {
			base = 16;
		}
		if (base > 0) {
			return Number.parseInt(value, base);
		}
	}
	return value;
}

function getElement(page) {
	if (!(page instanceof Element)) {
		const dom = new DOMParser().parseFromString(page, 'text/html')
		return dom.activeElement.firstChild;
	} else {
		return page;
	}
}

function minOr(m, value) {
	if (value == undefined || value == null) {
		return m;
	}
	if (m == undefined || m == null) {
		return value;
	}
	if (m < value) {
		return m;
	} else {
		return value;
	}
}

function maxOr(m, value) {
	if (value == undefined || value == null) {
		return m;
	}
	if (m == undefined || m == null) {
		return value;
	}
	if (m > value) {
		return m;
	} else {
		return value;
	}
}

function compareItem(item1, item2) {
	return (item1 < item2) ? -1 : (item1 > item2) ? 1 : 0;
}

function indexItem(sortedArray, item, fn = compareItem) {
	let upper = sortedArray.length - 1;
	if (upper < 0 || fn(sortedArray[upper], item) < 0) {
		return ~(upper + 1);
	}
	let lower = 0;
	while (lower <= upper) {
		const index = (upper + lower) >> 1;
		const cmp = fn(sortedArray[index], item);
		if (cmp < 0) {
			lower = index + 1;
		} else if (cmp > 0) {
			upper = index - 1;
		} else {
			return index;
		}
	}
	return ~lower;
}

/* fn must return the distance! */
function indexNearestItem(sortedArray, item, fn) {
	let pos = indexItem(sortedArray, item, fn);
	if (pos < 0) {
		const end = sortedArray.length - 1;
		pos = ~pos;
		if (pos >= end) {
			pos = end;
		} else if (pos > 0) {
			const d1 = -fn(sortedArray[pos - 1], item);
			const d2 = fn(sortedArray[pos], item);
			if (d1 < d2) {
				--pos;
			}
		}
	}
	return pos;
}

function insertItem(sortedArray, item, fn) {
	const pos = indexItem(sortedArray, item, fn);
	if (pos < 0) {
		sortedArray.splice(~pos, 0, item);
	}
	return pos;
}

class S3Request {

	constructor(id, key, region, endpoint, login, stateHandler) {
		this.id = id.replace(/[/<>\n]/g, '');
		this.key = key;
		this.region = region ?? "us-east-1";
		this.endpoint = endpoint ?? "";
		this.login = login;
		this.stateHandler = stateHandler;
		this.startGroups = 0;
	}

	static hexDigit(c) {
		if ('0'.charCodeAt(0) <= c && c <= '9'.charCodeAt(0)) {
			return c - '0'.charCodeAt(0);
		}
		if ('a'.charCodeAt(0) <= c && c <= 'f'.charCodeAt(0)) {
			return c - 'a'.charCodeAt(0) + 10;
		}
		if ('A'.charCodeAt(0) <= c && c <= 'F'.charCodeAt(0)) {
			return c - 'A'.charCodeAt(0) + 10;
		}
		throw new Error(c + " is no hex-digit.")
	}

	static hexToBuffer(hex) {
		if (hex.length & 1) {
			throw new Error(hex.length + " is odd, must be even for hex.")
		}
		const result = new Uint8Array(hex.length / 2);
		for (let i = 0; i < hex.length; i += 2) {
			let b = (S3Request.hexDigit(hex.charCodeAt(i)) & 0xf) << 4;
			b += (S3Request.hexDigit(hex.charCodeAt(i + 1)) & 0xf);
			result[i / 2] = b;
		}
		return result;
	}

	static bufferToHex(buffer, hexChars = '0123456789ABCDEF', head) {
		let result = '';
		if (head) {
			(new Uint8Array(buffer)).forEach((v) => { result += head; result += hexChars[v >> 4] + hexChars[v & 15]; });
		} else {
			(new Uint8Array(buffer)).forEach((v) => { result += hexChars[v >> 4] + hexChars[v & 15]; });
		}
		return result;
	}

	static bufferToHexLower(buffer) {
		return S3Request.bufferToHex(buffer, '0123456789abcdef');
	}

	static async h256(data = new ArrayBuffer(0)) {
		return window.crypto.subtle.digest("SHA-256", data);
	}

	static async h256Text(data) {
		return S3Request.h256(new TextEncoder().encode(data));
	}

	static async hmac256(key, data) {
		const hmackey = await window.crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
		return window.crypto.subtle.sign("HMAC", hmackey, new TextEncoder().encode(data));
	}

	static isSignableHeader(key) {
		const unsignableHeaders = [
			'authorization',
			'content-type',
			'content-length',
			'user-agent',
			'presigned-expires',
			'expect',
			'x-amzn-trace-id'
		];
		if (key.indexOf('x-amz-') === 0) return true;
		return unsignableHeaders.indexOf(key) < 0;
	}

	static uriEncode(value, keepSlash) {
		const h = '0123456789ABCDEF';
		const encoder = new TextEncoder();
		let result = "";
		for (let i = 0; i < value.length; i++) {
			const c = value.charCodeAt(i);
			const s = value.charAt(i);
			if (c < 128) {
				if ('%' == s) {
					const hex = value.slice(i + 1, i + 3);
					if (keepSlash && (hex == "2F" || hex == "2f")) {
						result += "/";
					} else {
						result += s + hex;
					}
					i += 2;
				} else if ('a' <= s && s <= 'z') {
					result += s;
				} else if ('A' <= s && s <= 'Z') {
					result += s;
				} else if ('0' <= s && s <= '9') {
					result += s;
				} else if ('-._~'.indexOf(s) >= 0) {
					result += s;
				} else if (keepSlash && '/' == s) {
					result += s;
				} else {
					result += "%" + h[c >> 4] + h[c & 15];
				}
			} else {
				const bytes = encoder.encode(s);
				result += S3Request.bufferToHex(bytes, h, "%");
			}
		}
		return result;
	}

	static s3KeyEncode(key, keepSlash) {
		return S3Request.uriEncode(key.replaceAll("%", "%25"), keepSlash);
	}

	static uriEncodeQueryParameter(parameter) {
		let result = "";
		if (parameter instanceof URLSearchParams) {
			parameter.sort();
			parameter.forEach((value, key) => {
				result += S3Request.uriEncode(key) + "=" + S3Request.uriEncode(value) + "&";
			});
			result = result.slice(0, -1);
		}
		return result;
	}

	static uriEncodeHeader(host, headers) {
		let keys = "";
		let pairs = "";
		let canoncialHeaders = [["host", host]];

		for (const [key, value] of headers.entries()) {
			const lkey = key.toLowerCase();
			if (S3Request.isSignableHeader(lkey)) {
				let v;
				if (value instanceof Array) {
					value.map((v) => v.trim());
					v = value;
				} else {
					v = value.trim();
				}
				canoncialHeaders.push([lkey, v]);
			}
		}
		canoncialHeaders.sort((a, b) => { return a[0] < b[0] ? -1 : 1; });
		canoncialHeaders.forEach((h) => {
			pairs += h[0] + ":";
			let value = h[1];
			if (value instanceof Array) {
				for (let val of value) {
					pairs += val + ",";
				}
				pairs = pairs.slice(0, -1);
			} else {
				pairs += value;
			}
			pairs += "\n";
			keys += h[0] + ";";
		});

		keys = keys.slice(0, -1);

		return [pairs, keys];
	}

	async getSigningKey(date) {
		if (this.login) {
			const signKey = this.login[date];
			if (signKey) {
				return signKey;
			}
		}
		if (!this.key) {
			let error = null;
			if (this.login) {
				error = new Error("Session expired! Login again.");
			} else {
				error = new Error("Missing credentials!");
			}
			error.login = 0;
			throw error;
		}
		let calc = this.calculate;
		if (!calc) {
			this.calculate = new Promise((resolve) => {
				const key = new TextEncoder().encode("AWS4" + this.key);
				S3Request.hmac256(key, date).
					then((keyDate) => S3Request.hmac256(keyDate, this.region)).
					then((keyRegion) => S3Request.hmac256(keyRegion, "s3")).
					then((keyService) => S3Request.hmac256(keyService, "aws4_request")).
					then((signKey) => {
						const login = new Object();
						login[date] = signKey;
						this.login = login;
						resolve(signKey);
					});
			});
			calc = this.calculate;
		}
		const skey = await calc;
		this.calculate = null;
		return skey;
	}

	async signedRequest(request, body) {
		const uri = new URL(request.url);
		const datetime = request.headers.get('x-amz-date');
		const date = datetime.slice(0, 8);
		const scope = date + "/" + this.region + "/s3/aws4_request";
		const payloadHash = await S3Request.h256(body);
		request.headers.set('x-amz-content-sha256', S3Request.bufferToHexLower(payloadHash));

		const canonicalHeaders = S3Request.uriEncodeHeader(uri.host, request.headers);

		let value = request.method + "\n";
		value += S3Request.uriEncode(uri.pathname, true) + "\n";
		value += S3Request.uriEncodeQueryParameter(uri.searchParams) + "\n";
		value += canonicalHeaders[0] + "\n";
		value += canonicalHeaders[1] + "\n";
		value += request.headers.get('x-amz-content-sha256');

		const hash = await S3Request.h256Text(value);
		const stringToSign = 'AWS4-HMAC-SHA256\n' + datetime + "\n" + scope + "\n" + S3Request.bufferToHexLower(hash);
		const key = await this.getSigningKey(date);
		const sign = await S3Request.hmac256(key, stringToSign);
		const cred = this.id + '/' + scope + ",SignedHeaders=" + canonicalHeaders[1] + ",Signature=" + S3Request.bufferToHexLower(sign)
		request.headers.set('Authorization', 'AWS4-HMAC-SHA256 Credential=' + cred);

		return request;
	}

	async getContent(response, url, optional) {
		const stateHandler = this.stateHandler;

		//		console.log("Status: " + response.status);
		if (response.status == 200) {
			const text = await response.text();
			if (url) {
				console.log(url + ": " + text.length + " bytes");
			}
			if (stateHandler) {
				stateHandler(false, 0, 1, text.length);
			}

			return text ?? "";
		} else if (response.status == 304) {
			if (url) {
				console.log(url + ": no change");
			}
			if (stateHandler) {
				stateHandler(false, 0, 1, 0);
			}
			return "";
		} else if (optional && response.status == 404) {
			if (stateHandler) {
				stateHandler(false, 0, 1, 0);
			}
			return null;
		} else {
			if (stateHandler) {
				let errorText = await response.text();
				const ct = response.headers.get("content-type");
				if (errorText.length > 0 && ct) {
					if (ct.startsWith("text/html")) {
						const xml = new DOMParser().parseFromString(errorText, 'text/xml');
						errorText = xml.firstChild.innerHTML;
					} else if (ct.startsWith("application/xml")) {
						const xml = new DOMParser().parseFromString(errorText, 'text/xml');
						const message = xml.querySelector("Message");
						if (message) {
							errorText = message.textContent;
						}
					}
				}
				if (errorText) {
					stateHandler(false, 0, 1, 0, errorText);
				} else {
					stateHandler(false, 0, 1, 0, response.statusText);
				}
			}
			return null;
		}
	}

	async getText(response, url, optional) {
		const text = await this.getContent(response, url, optional);
		if (text != null) {
			return { status: response.status, headers: response.headers, text: text };
		} else {
			return null;
		}
	}

	async getJson(response, url, optional) {
		const text = await this.getContent(response, url, optional);
		if (text != null) {
			const json = text ? JSON.parse(text) : null;
			return { status: response.status, headers: response.headers, json: json };
		} else {
			return null;
		}
	}

	async getXml(response, url, optional) {
		const text = await this.getContent(response, url, optional);
		if (text != null) {
			const dom = text ? new DOMParser().parseFromString(text, 'text/xml') : null;
			return { status: response.status, headers: response.headers, xml: dom };
		} else {
			return null;
		}
	}

	async fetchUrl(url, now, etag) {
		const stateHandler = this.stateHandler;
		if (stateHandler) stateHandler(false, 1, 0, 0);
		try {
			if (!(now)) {
				now = new Date(Date.now() - timeShift).toISOString().replaceAll(/[-:]/g, '').replace(/\.\d+/, '');
			}
			const request = new Request(url, {
				method: 'GET',
				headers: {
					"x-amz-date": now,
				},
				mode: 'cors',
				cache: 'no-cache',
			});
			if (etag) {
				request.headers.set("If-None-Match", etag);
			}
			const s3Request = await this.signedRequest(request);
			return await fetch(s3Request);
		} catch (error) {
			if (error.message == "NetworkError when attempting to fetch resource." && this.id) {
				error = new TypeError(`NetworkError when attempting to fetch resource with user ${this.id.slice(0, 6)}...`);
			}
			console.error(error);
			if (stateHandler) {
				stateHandler(false, 0, 1, 0, error, error.login);
			}
			throw error;
		}
	}

	async fetchUrlText(url, etag, optional) {
		const response = await this.fetchUrl(url, null, etag);
		return this.getText(response, url, optional);
	}

	async fetchUrlJson(url, etag, optional) {
		const response = await this.fetchUrl(url, null, etag);
		return this.getJson(response, url, optional);
	}

	async fetchUrlXml(url, etag, optional) {
		const response = await this.fetchUrl(url, null, etag);
		return this.getXml(response, url, optional);
	}

	static xmlList(xmlList, exp) {
		let list = Array();
		if (xmlList) {
			xmlList.querySelectorAll(exp).forEach((e) => list.push(e.textContent));
		}
		return list;
	}

	static xmlLast(xmlList, exp) {
		let last = null;
		if (xmlList) {
			xmlList.querySelectorAll(exp).forEach((e) => last = maxOr(last, e.textContent));
		}
		return last;
	}

	async fetchXmlList(key, startAfterKey, maxKeys) {
		if (key) {
			let uri = this.endpoint + "?list-type=2&prefix=" + S3Request.s3KeyEncode(key) + "&delimiter=%2F";
			if (startAfterKey) {
				uri += "&start-after=" + startAfterKey;
			}
			if (maxKeys) {
				uri += "&max-keys=" + maxKeys;
			}
			return this.fetchUrlXml(uri);
		}
		return null;
	}

	async fetchXmlListNoDelimiter(key, startAfterKey, maxKeys) {
		if (key) {
			let uri = this.endpoint + "?list-type=2&prefix=" + S3Request.s3KeyEncode(key);
			if (startAfterKey) {
				uri += "&start-after=" + startAfterKey;
			}
			if (maxKeys) {
				uri += "&max-keys=" + maxKeys;
			}
			return this.fetchUrlXml(uri);
		}
		return null;
	}

	async fetchXmlListLast(key, exp, startAfterKey) {
		const xmlList = await this.fetchXmlList(key, startAfterKey);
		return S3Request.xmlLast(xmlList.xml, exp);
	}

	async fetchContent(key, etag, optional) {
		if (key) {
			return this.fetchUrlText(this.endpoint + S3Request.s3KeyEncode(key, true), etag, optional);
		} else {
			return null;
		}
	}

	async putUrl(url, body, now) {
		const stateHandler = this.stateHandler;
		if (stateHandler) stateHandler(false, 1, 0, 0);
		try {
			if (!(now)) {
				now = new Date(Date.now() - timeShift).toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '');
			}
			const request = new Request(url, {
				method: 'PUT',
				headers: {
					"x-amz-date": now,
					"content-type": "text/plain; charset=UTF-8",
				},
				mode: 'cors',
				cache: 'no-cache',
				body: body,
			});
			const s3Request = await this.signedRequest(request, body);
			return fetch(s3Request);
		} catch (error) {
			console.error(error);
			if (stateHandler) {
				stateHandler(false, 0, 1, 0, error, error.login);
			}
			throw error;
		}
	}

	async putContent(key, content, now) {
		const url = this.endpoint + S3Request.s3KeyEncode(key, true);
		const response = await this.putUrl(url, content, now);
		this.stateHandler(false, 0, 0, content.length);
		const text = await this.getContent(response, url);
		if (text != null) {
			return { headers: response.headers, text: text };
		} else {
			return null;
		}
	}

	allStarted() {
		const stateHandler = this.stateHandler;
		if (stateHandler) {
			if (this.startGroups > 0) {
				this.startGroups--;
			} else {
				stateHandler(true, 0, 0, 0);
			}
		}
	}

	ignoreResponse() {
		const stateHandler = this.stateHandler;
		if (stateHandler) stateHandler(false, 0, 1, 0);
	}
}

class ChartConfig {
	constructor(regex, units, color, min, max, scale = 1) {
		this.regex = regex;
		this.units = units;
		this.color = color;
		this.min = min;
		this.max = max;
		this.scale = scale;
	}
}

const dayInMillis = 24 * 60 * 60 * 1000;
// yyyy-mm-ddThh:mm:ss.SSSZ
const regexTimeEnding = /(\d{2,4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2})(\.\d{3})?Z$/;
const regexTimeHeader = /^(\d{2,4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2})(\.\d{3})?Z/;

const chartConfig = [
	new ChartConfig(/\s*([+-]?\d+)\smV/, "mV", "blue", 3400, 4300, 1000),
	new ChartConfig(/mV\s+([+-]?\d+(\.\d+)?)\%/, "%", "navy", 20, 100),
	new ChartConfig(/,\s*([+-]?\d+(\.\d+)?)(,([+-]?\d+(\.\d+)?))*\sC/, "°C", "red", 10, 40),
	new ChartConfig(/,\s*([+-]?\d+(\.\d+)?)(,([+-]?\d+(\.\d+)?))*\s%H/, "%H", "green", 10, 80),
	new ChartConfig(/,\s*([+-]?\d+(\.\d+)?)(,([+-]?\d+(\.\d+)?))*\shPa/, "hPa", "SkyBlue", 900, 1100),
	new ChartConfig(/,\s*([+-]?\d+(\.\d+)?)(,([+-]?\d+(\.\d+)?))*\sQ/, "IAQ", "lightblue", 0, 500),
	new ChartConfig(/,\s*RSRP:\s*([+-]?\d+(\.\d+)?)\sdBm/, "dBm", "orange", -125, -75),
	new ChartConfig(/,\s*SNR:\s*([+-]?\d+(\.\d+)?)\sdB/, "dB", "gold", -15, 15),
	new ChartConfig(/,\s*ENY:\s*([+-]?\d+(\.\d+)?)(\/([+-]?\d+(\.\d+)?))?\sm(As|C)/, "mAs", "DarkGoldenrod", 50, 400),
	new ChartConfig(/,\s*ENY0:\s*([+-]?\d+(\.\d+)?)\smAs/, "mAs0", "tomato", 50, 400),
	new ChartConfig(/,\s*CHA\s*([+-]?\d+(\.\d+)?)\skg/, "kg A", "olive", 0, 50),
	new ChartConfig(/,\s*CHB\s*([+-]?\d+(\.\d+)?)\skg/, "kg B", "teal", 0, 50),
	new ChartConfig(/,\s*Ext\.Bat\.:\s*([+-]?\d+(\.\d+)?)\smV/, "mV Ext.", "lime", 8000, 16000, 1000),
	new ChartConfig(/,\s*RETRANS:\s*(\d+)/, "Retr.", "red", 0, 3, 0),
	new ChartConfig(/,\s*RTT:\s*([+-]?\d+)\sms/, "ms", "salmon", 0, 60000, 1000),
];

function getChartConfigIndex(units) {
	return chartConfig.findIndex((cfg) => cfg.units == units);
}

function addChartConfigValue(result, values, units) {
	const i = getChartConfigIndex(units);
	if (i >= 0 && i + 1 < values.length) {
		const value = values[i + 1];
		if (value != null) {
			result.push(value + " " + chartConfig[i].units);
		}
	}
}

const defaultProviderMap = new Map();
defaultProviderMap.set("em", "EMnify");
defaultProviderMap.set("flolive.net", "Flo.Live");
defaultProviderMap.set("gigsky-02", "Flo*Live");
defaultProviderMap.set("globaldata.iot", "iBASIS");
defaultProviderMap.set("global.melita.io", "gMelita");
defaultProviderMap.set("ibasis.iot", "iBASIS");
defaultProviderMap.set("internet.m2mportal.de", "DTAG");
defaultProviderMap.set("iot.1nce.net", "1nce");
defaultProviderMap.set("iot.melita.io", "Melita");
defaultProviderMap.set("iot.truphone.com", "TruPhone");
defaultProviderMap.set("onomondo", "Ono");
defaultProviderMap.set("public4.m2minternet.com", "Spider");
defaultProviderMap.set("soracom.io", "Soracom");

const providerMap = new Map();

function providerMapInit(newProviderMap) {
	providerMap.clear();
	newProviderMap.forEach((v, k) => {
		providerMap.set(k, v);
		if (k.length > 15) {
			providerMap.set(k.slice(0, 15), v);
		}
	});

	providerMap.forEach((v, k) => {
		console.log(`'${k}' => '${v}'`);
	});
}

providerMapInit(defaultProviderMap);

const radioTypeMap = new Map();
radioTypeMap.set("CAT-M1", "M1");
radioTypeMap.set("NB-IoT", "NB");
radioTypeMap.set("NTN", "NT");
radioTypeMap.set("none", "");

class DeviceData {

	static lastDayStartKeys = new Array();

	lastInterval = null;
	lastModified = null;
	lastDayKey = null;
	lastStatusKey = null;
	lastStatusNew = false;
	updated = false;
	status = null;
	statusTime = null;
	statusKey = null;
	network = null;
	pdn = null;
	batteryLevel = null;
	uptime = null;
	allKeys = Array();
	loaded = new Map();
	allTimes = Array();
	allValues = Array();
	rangeValues = Array();

	constructor(key) {
		this.key = key;
		this.plainKey = DeviceData.label(key);
		this.label = this.plainKey;
		this.newDevice = true;
		this.fit = false;
	}

	toString() {
		return this.label;
	}

	getDetails() {
		let details = {};
		details.uptime = this.uptime ? this.uptime.toString() : "";
		details.pdn = this.pdn ?? "";
		details.batteryLevel = this.batteryLevel;
		details.plmn = "";
		details.type = "";
		details.net = "";
		details.band = "";
		if (this.network) {
			details.plmn = this.network.plmn;
			details.band = this.network.band;
			details.type = radioTypeMap.get(this.network.type) ?? this.network.type;
			if (details.plmn || details.type) {
				details.net = details.plmn + "/" + details.type;
			}
		}

		return details;
	}

	static initLastDayStartKeys() {
		const startOfService = new Date("2022-06-01").getTime();
		const now = new Date();
		const deltaInMonths = [1, 3, 6];
		DeviceData.lastDayStartKeys.length = 0;
		while (now.getTime() > startOfService) {
			let delta = deltaInMonths[0];
			if (deltaInMonths.length > 1) {
				deltaInMonths.shift();
			}
			const month = now.getUTCMonth();
			while (delta > month) {
				now.setUTCFullYear(now.getUTCFullYear() - 1);
				delta -= 12;
			}
			if (delta > 0) {
				now.setUTCMonth(month - delta);
			}
			const date = now.toISOString().slice(0, 10);
			DeviceData.lastDayStartKeys.push(date);
		}
	}

	static label(key) {
		const found = key.match(/([^\/]+)\/?$/);
		if (found && found.length > 1) {
			return found[1];
		} else {
			return key;
		}
	}

	static getISODateFromKey(key, millis) {
		const m = key.match(regexTimeEnding);
		if (m) {
			let date = m[1];
			if (millis) {
				if (m[2] && m[2].length > 0) {
					date += m[2];
				} else {
					date += ".000";
				}
			}
			return date + "Z";
		} else {
			const path = key.split('/');
			if (path.length > 2) {
				let time = path.at(-1);
				if ((time.length <= 8) && millis) {
					time += ".000";
				} else if ((time.length > 8) && !millis) {
					time = time.slice(0, 8);
				}
				return path.at(-2) + "T" + time + "Z";
			} else {
				return key;
			}
		}
	}

	static getTimeFromKey(key) {
		const date = DeviceData.getISODateFromKey(key, true);
		if (date != key) {
			return new Date(date).getTime();
		} else {
			return null;
		}
	}

	static getDev(list, key, fn) {
		let dev = null;
		const pos = indexItem(list, key, fn);
		if (pos < 0) {
			dev = new DeviceData(key);
			list.splice(~pos, 0, dev);
		} else {
			dev = list[pos];
		}
		return dev;
	}

	static async loadDeviceList(list, groups, details) {
		const xmlList = await s3.fetchXmlList("devices/");
		if (xmlList) {
			function addDevCmp(x, y) {
				return (x.key < y) ? -1 : (x.key > y) ? 1 : 0;
			}
			const allJobs = Array();
			let newDevice = false;
			DeviceData.initLastDayStartKeys();
			xmlList.xml.querySelectorAll("CommonPrefixes>Prefix").forEach((e) => {
				const dev = DeviceData.getDev(list, e.textContent, addDevCmp);
				if (groups == null || groups.includes(dev)) {
					allJobs.push(dev.readOverview(details));
				} else if (dev.newDevice) {
					newDevice = true;
					allJobs.push(dev.readOverview(details));
				}
				dev.newDevice = false;
			});
			s3.allStarted();
			const results = await Promise.allSettled(allJobs);
			let error = results.find((result) => result.reason);
			return { newDevice: newDevice, error: error ? error.reason : null };
		} else {
			return { error: "No devices found!" };
		}
	}

	findNearestValues(time) {
		const range = this.rangeValues;
		let pos = indexNearestItem(range, time, (x, y) => x[0] - y);
		return range[pos];
	}

	findNearestTime(time, delta, index) {
		const range = this.allTimes;
		if (range && range.length > 0) {
			let pos = 0;
			if (time) {
				pos = indexNearestItem(range, time, (x, y) => x[0] - y);
			} else {
				pos = indexItem(range, Date.now(), (x, y) => x[0] - y);
				if (pos < 0) {
					pos = ~pos;
					if (delta < 0 && pos == range.length) {
						--pos;
					}
				}
			}
			if (delta) {
				pos += delta;
			}
			pos = Math.max(pos, 0);
			pos = Math.min(pos, range.length - 1);
			if (index) {
				return pos;
			} else {
				return range[pos][0];
			}
		} else {
			return -1;
		}
	}

	async readOverview(details) {
		const lastMessageKey = await this.fetchLastMessageKey();
		if (lastMessageKey) {
			this.updated = this.lastStatusNew;
			if (this.updated) {
				console.info("overview: " + lastMessageKey + " (update)");
				this.lastModified = DeviceData.getISODateFromKey(lastMessageKey, false)
				if (details) {
					return this.readStatus(lastMessageKey);
				}
			} else {
				console.info("overview: " + lastMessageKey + " (no update)");
			}
		} else {
			console.info(this.key + " no last message!")
		}
	}

	async readStatus(key) {
		if (key == this.statusKey) {
			return;
		}
		this.status = null;
		this.statusKey = null;
		this.statusTime = null;
		this.network = null;
		this.pdn = null;
		this.uptime = null;
		this.batteryLevel = null;
		const status = await s3.fetchContent(key, null, true);
		if (status) {
			this.statusTime = DeviceData.getTimeFromKey(key);
			this.statusKey = key;
			this.status = status.text;
			if (this.statusTime == null) {
				const last = status.headers.get("last-modified");
				if (last) {
					this.statusTime = new Date(last).getTime();
				}
			}
			const regexBatteryLevel = /mV\s+(\d+(\.\d+)?)%/;
			const lines = status.text.split(/\r?\n/);
			const m = lines[0].match(/^\d+-/);
			if (m) {
				this.uptime = Number(m[0].slice(0, -1));
				lines.shift();
			}
			lines.forEach((l) => {
				const l2 = strip(l, "!") ?? l;
				const net = strip(l2, "Network: ");
				if (net) {
					const nets = net.split(/,/);
					this.network = {
						type: nets.shift(),
						mode: nets.shift(),
						band: "",
						plmn: "",
						tac: "",
						cell: ""
					}
					nets.forEach((f) => {
						let value = strip(f, "Band ");
						if (value) {
							this.network.band = value;
							return;
						}
						value = strip(f, "PLMN ");
						if (value) {
							this.network.plmn = value;
							return;
						}
						value = strip(f, "#PLMN ");
						if (value) {
							this.network.plmn = value;
							return;
						}
						value = strip(f, "TAC ");
						if (value) {
							this.network.tac = conv(value, 4);
							return;
						}
						value = strip(f, "Cell ");
						if (value) {
							this.network.cell = conv(value, 8);
							return;
						}
					});
				}
				const pdn = strip(l2, "PDN: ");
				if (pdn) {
					const parts = pdn.split(/,/);
					if (parts.length > 1) {
						this.pdn = providerMap.get(parts[0]) ?? parts[0];
					}
				}
				const bat = l2.match(regexBatteryLevel);
				if (bat && bat.length > 1) {
					const n = Number(bat[1]);
					if (n !== Number(n)) {
					} else {
						this.batteryLevel = n;
					}
				}
			});
		}
	}

	async fetchLastMessageKey() {
		this.lastStatusNew = false;
		let lastStatusKey = null;
		let key = null;
		if (this.lastDayKey) {
			// limit to year 2xxx, exclude "series"
			key = await s3.fetchXmlListLast(this.key + "2", "CommonPrefixes>Prefix", this.lastDayKey);
			if (key) {
				this.lastDayKey = key;
				console.log("new " + key);
			} else {
				key = this.lastDayKey;
				lastStatusKey = this.lastStatusKey;
				console.log("last " + key);
			}
		} else {
			for (let i = 0; i < DeviceData.lastDayStartKeys.length; ++i) {
				key = this.key + DeviceData.lastDayStartKeys[i];
				// limit to year 2xxx, exclude "series"
				key = await s3.fetchXmlListLast(this.key + "2", "CommonPrefixes>Prefix", key);
				if (key) {
					this.lastDayKey = key;
					console.log("found " + key);
					break;
				}
			}
		}
		if (key) {
			key = await s3.fetchXmlListLast(key, "Contents>Key", lastStatusKey);
			if (key) {
				this.lastStatusNew = true;
				this.lastStatusKey = key;
				console.log("new " + key);
			}
			return this.lastStatusKey;
		} else {
			return null;
		}
	}

	async readStatusFrom(center) {
		let statusKey = null;
		if (this.allTimes.length > 0) {
			const nearestTime = this.findNearestTime(center);
			const dateTime = new Date(nearestTime).toISOString();
			const date = dateTime.slice(0, 10);
			const time = dateTime.slice(11, -1);
			statusKey = this.key + date + "/" + time;
		} else {
			statusKey = await this.fetchLastMessageKey();
		}
		return this.readStatus(statusKey);
	}

	async readConfig() {
		let changed = false;
		const fetch = s3.fetchContent(this.key + "config", null, true);
		s3.allStarted();
		const config = await fetch;
		if (config) {
			changed = this.config != config.text;
			this.config = config.text;
			this.configTimestamp = config.headers.get("last-modified");
		} else {
			changed = this.config != null;
			this.config = null;
			this.configTimestamp = null;
		}
		return changed;
	}

	async writeConfig(newConfig) {
		const utf8Content = new TextEncoder().encode(newConfig);
		let key = this.key.replace("devices", "config")
		key = trunc(key, "/") ?? key;
		console.log("config: " + key)
		const put = s3HttpHost.putContent(key, utf8Content);
		s3HttpHost.allStarted();
		const result = await put;
		if (result && result.text == "") {
			await this.readConfig();
		}
		return result;
	}

	async downloadSeries(seriesKey, force) {
		const etag = this.loaded.get(seriesKey)
		if (etag == undefined || force) {
			const tempIndex = getChartConfigIndex("°C") + 1;
			const humIndex = getChartConfigIndex("%H") + 1;
			const presIndex = getChartConfigIndex("hPa") + 1;
			
			function isValue(value) {
				return value != null && value != 0;
			}
			function isTempValue(value) {
				// -0.6 Thingy Temperature offset.
				return value != null && value != 0 && value != -0.6;
			}
			function removeSensor(line, index) {
				if (line[index] != null) {
					line[index] = null;
					return true;
				}
				return false;
			}
			function checkSensors(line) {
				let sensors = 0;

				if (isValue(line[humIndex])) {
					++sensors;
				}
				if (isValue(line[presIndex])) {
					++sensors;
				}
				if (isTempValue(line[tempIndex])) {
					++sensors;
				}
				if (sensors == 0) {
					if (removeSensor(line, humIndex)) {
						++sensors;
					}
					if (removeSensor(line, presIndex)) {
						++sensors;
					}
					if (removeSensor(line, tempIndex)) {
						++sensors;
					}
					return sensors;
				}
				return 0;
			}

			function addLineCmp(x, y) {
				return x[0] - y[0];
			}

			const download = await s3.fetchContent(seriesKey, etag);
			download.text.split(/\r?\n/).forEach((l) => {
				const isoTime = l.match(regexTimeHeader);
				if (isoTime) {
					const time = Date.parse(isoTime[0]);
					if (time) {
						let foundValues = 0;
						const line = Array();
						line.push(time);
						chartConfig.forEach((cfg) => {
							let found = l.match(cfg.regex);
							if (found && found.length > 1) {
								const n = Number(found[1]);
								if (n !== Number(n)) {
									// NaN
									line.push(null);
								} else {
									line.push(n);
									++foundValues;
								}
							} else {
								line.push(null);
							}
						});
						const leftValues = foundValues ? foundValues - checkSensors(line) : foundValues;
						if (leftValues) {
							insertItem(this.allValues, line, addLineCmp);
						}
						insertItem(this.allTimes, line, addLineCmp);
					}
				}
			});
			const newEtag = download.headers.get("etag") ?? (etag ?? "");
			this.loaded.set(seriesKey, newEtag);
		} else {
			console.log("Cache " + seriesKey + " " + etag);
		}
	}

	async loadData(center, days, readConfig) {
		const allKeys = this.allKeys;
		const startKey = allKeys.at(-1);
		const xmlSeries = await s3.fetchXmlList(this.key + "series-2", startKey);
		if (xmlSeries) {
			// date/time
			// series-dateTtimeZ
			const allJobs = Array();
			const previousKeys = allKeys.length;
			let to = center ? (center + days * dayInMillis / 2) : Date.now();
			let from = to - days * dayInMillis;
			// fetch all series-dateTtimeZ files
			xmlSeries.xml.querySelectorAll("Contents>Key").forEach((e) => insertItem(allKeys, e.textContent));
			console.log(allKeys.length + " series (" + (allKeys.length - previousKeys) + " new)");
			if (allKeys.length > 0) {
				const lastValues = DeviceData.getTimeFromKey(allKeys.at(-1)) ?? to;
				if (lastValues + dayInMillis < to) {
					to = lastValues + dayInMillis;
					from = to - days * dayInMillis;
				}
				if (center) {
					console.log("Center " + new Date(center).toISOString())
					const firstValues = DeviceData.getTimeFromKey(allKeys.at(0)) ?? from;
					if (firstValues > from) {
						from = firstValues;
						to = from + days * dayInMillis;
					}
					center = Math.min(to, center);
					center = Math.max(from, center);
					console.log("Center *" + new Date(center).toISOString())
				}
				const start = new Date(from - dayInMillis).toISOString();
				const last = new Date(to + dayInMillis).toISOString();
				allKeys.forEach((k) => {
					const d = DeviceData.getISODateFromKey(k);
					if (start <= d && d <= last) {
						allJobs.push(this.downloadSeries(k, startKey == k));
					}
				});
				console.log(allJobs.length + " series used");
			}
			let configRequest = null;
			if (readConfig) {
				s3.startGroups++;
				configRequest = this.readConfig();
			}
			s3.allStarted();
			const results = await Promise.allSettled(allJobs);
			const numberOfSensors = chartConfig ? chartConfig.length : 1;
			const starts = Array(numberOfSensors);
			const ends = Array(numberOfSensors);
			this.rawStarts = starts;
			this.rawEnds = ends;
			console.log(this.allValues.length + " values");
			if (this.allTimes.length > 1) {
				let i = -1;
				if (center) {
					function timeCmp(x, y) {
						return x[0] - y;
					}
					i = indexNearestItem(this.allTimes, center, timeCmp);
					if (i == 0) {
						++i;
					}
				}
				const last = this.allTimes.at(i)[0];
				const before = this.allTimes.at(i - 1)[0];
				const seconds = Math.round((last - before) / 1000);
				if (seconds < 55) {
					this.lastInterval = `${seconds} sec`;
				} else {
					const minutes = Math.round(seconds / 60);
					if (minutes > 50) {
						const hours = Math.round(minutes / 60);
						this.lastInterval = `${hours} h`;
					} else {
						this.lastInterval = `${minutes} min`;
					}
				}
			}
			if (this.allValues.length > 0) {
				let rangeValues = this.allValues.filter((v) => from <= v[0] && v[0] <= to);
				if (rangeValues.length > 0) {
					starts[0] = rangeValues[0][0];
					ends[0] = rangeValues.at(-1)[0];
					this.rawStarts = starts;
					this.rawEnds = ends;
					rangeValues.forEach((v) => {
						for (let i = 1; i < v.length; ++i) {
							if (v[i] != null) {
								starts[i] = minOr(starts[i], v[i]);
								ends[i] = maxOr(ends[i], v[i]);
							}
						}
					});
				}
				this.rangeValues = rangeValues;
			} else {
				this.rangeValues = Array();
				if (this.allTimes.length == 0) {
					center = 0;
				}
			}
			await this.readStatusFrom(center);
			if (configRequest) await configRequest;
			let error = results.find((result) => result.reason);
			console.log("load data completed");
			return { device: this, error: error ? error.reason : null };
		} else {
			return { error: `No series found for ${key}!` };
		}
	}
}

class DeviceGroups {

	constructor(groups, etag) {
		this.filter = true;
		this.groups = groups;
		this.etag = etag;
		this.lastRefresh = Date.now();
	}

	toggleFilter() {
		this.filter = !this.filter;
	}

	async refresh(force) {
		let diff = false;
		const now = Date.now();
		if (force || (now - this.lastRefresh) > (1000 * 60)) {
			// check for new devices
			if (force) {
				console.log("Refresh groups forced");
			} else {
				console.log("Refresh groups");
			}
			try {
				const response = await s3HttpHost.fetchUrlJson("groups", this.etag, true);
				if (response.error) {
					console.log("Failed to update groups: " + response.error.message)
				} else if (response.status == 304) {
					this.lastRefresh = now;
				} else {
					const json = response.json;
					if (json && json.groups) {
						this.lastRefresh = now;
						this.etag = response.headers.get("etag");
						for (let prop in json.groups) {
							if (this.groups[prop] != json.groups[prop]) {
								diff = true;
								break;
							}
						}
						for (let prop in this.groups) {
							if (json.groups[prop] == undefined) {
								diff = true;
								break;
							}
						}
						if (diff) {
							this.groups = json.groups;
							console.log("groups: changed.")
						} else {
							console.log("groups: no change in response.")
						}
					}
				}
			} catch (error) {
				console.log("Failed to update groups: " + error.message)
			}
		} else {
			console.log("Groups not refreshed");
		}
		return diff;
	}

	update(allDevices) {
		allDevices.forEach((dev) => this.includes(dev));
	}

	includes(dev) {
		const label = this.groups[dev.plainKey];
		if (label == undefined) {
			return !this.filter;
		} else if (label) {
			dev.label = label;
		}
		dev.fit = true;
		return true;
	}

	reset() {
		this.groups = null;
		this.etag = null;
		this.lastRefresh = 0;
	}
}

class UiChart {

	w = 550;
	h = 300;
	chartX = 65;
	chartY = 0;
	chartW = 420;
	chartH = 270;

	daysSelectionMax = 19;

	constructor() {
		this.reset();
	}

	reset(days, signals, sensors, average, mimmax, zoom) {
		this.startTime = 0;
		this.endTime = 0;
		this.daysSelection = 10;
		this.center = 0;
		this.signals = signals;
		this.sensors = sensors;
		this.zoom = zoom;
		this.average = average ?? 1;
		this.minmax = mimmax;
		if (days) {
			for (let i = 1; i <= this.daysSelectionMax; ++i) {
				if (days <= this.getDays(i)) {
					this.daysSelection = i;
					break;
				}
			}
		}
	}

	toggle(flag) {
		this[flag] = !this[flag]
		if (this[flag]) {
			if (flag == "average") {
				this.minmax = 0;
			} else if (flag == "minmax") {
				this.average = 0;
			}
		}
	}

	removeMarker(svg) {
		const oldMarker = svg.querySelector('#marker');
		if (oldMarker) {
			oldMarker.remove();
			svg.style.cursor = 'default';
		}
	}

	viewMarker(offsetX, offsetY, svg, dev) {
		this.removeMarker(svg);
		if (offsetY < this.chartY || (this.chartY + this.chartH) < offsetY) {
			return -1;
		}
		if (offsetX < this.chartX || (this.chartX + this.chartW) < offsetX) {
			return -1;
		}

		svg.style.cursor = 'none';
		const timeInMillis = this.startTime + (this.endTime - this.startTime) *
			(offsetX - this.chartX) / this.chartW;

		const markerDateTime = new Date(timeInMillis).toISOString();
		const markerDate = markerDateTime.slice(0, 10);
		const markerTime = markerDateTime.slice(11, -8);

		const display = [markerDate, markerTime, ""];
		const values = dev.findNearestValues(timeInMillis);
		if (values) {
			if (this.signals && !this.sensors) {
				addChartConfigValue(display, values, "mV");
				display.push("");
				addChartConfigValue(display, values, "dBm");
				addChartConfigValue(display, values, "dB");
				addChartConfigValue(display, values, "mAs");
				addChartConfigValue(display, values, "mAs0");
				addChartConfigValue(display, values, "Retr.");
				addChartConfigValue(display, values, "ms");
			} else {
				addChartConfigValue(display, values, "°C");
				addChartConfigValue(display, values, "%H");
				addChartConfigValue(display, values, "hPa");
				addChartConfigValue(display, values, "kg A");
				addChartConfigValue(display, values, "kg B");
				addChartConfigValue(display, values, "mV Ext.");
			}
		}

		const y1 = Math.max(offsetY - 27, this.chartY);
		const y2 = Math.min(offsetY - 12, this.chartY + this.chartH);

		let labels = "";

		display.forEach((label) => {
			if (label == "") {
				offsetY += 5;
			} else {
				labels += `<text x='${offsetX}' y='${offsetY}' text-anchor='middle'>${label}</text>`;
				offsetY += 11;
			}
		})
		offsetY -= 5;
		const y3 = Math.min(Math.max(offsetY, this.chartY), this.chartY + this.chartH);
		const y4 = Math.min(offsetY + 15, this.chartY + this.chartH);

		const marker = `
<g id='marker'>
  <rect x='${offsetX - 30}' width='60' y='${y2}' height='${y3 - y2}' fill='white' fill-opacity='.7'/>
  ${labels}
  <path d='M ${offsetX},${y1} L ${offsetX},${y2}' stroke='grey'></path>
  <path d='M ${offsetX},${y3} L ${offsetX},${y4}' stroke='grey'></path>
</g>`;
		svg.insertAdjacentHTML('beforeend', marker);
		return timeInMillis;
	}

	setChartX(offsetX, offsetY, svg, dev) {
		const timeInMillis = this.viewMarker(offsetX, offsetY, svg, dev);
		if (timeInMillis < 0) {
			return false;
		} else if (this.center != timeInMillis) {
			this.center = timeInMillis;
			return true;
		}
		return false;
	}

	setDaysSelection(selection) {
		if (this.daysSelection != selection) {
			if (0 < selection && selection <= this.daysSelectionMax) {
				this.daysSelection = selection;
				return true;
			}
		}
		return false;
	}

	getDays(sel = this.daysSelection) {
		if (sel <= 10) {
			/* 1 - 10 */
			return sel;
		} else if (sel <= 14) {
			/* 12 - 26 */
			return 10 + Math.pow(2, (sel - 10));
		} else {
			/* 32 - ... */
			return Math.pow(2, (sel - 10));
		}
	}

	getDaysDescription(days = this.getDays()) {
		const unit = days > 1 ? "days" : "day";
		return days + " " + unit;
	}

	getCenter(reset) {
		if (reset) {
			this.center = 0;
		}
		return this.center;
	}

	getCols(days) {
		if (days <= 3) {
			return 12;
		}
		if (days <= 6) {
			return days * 2;
		}
		if (days <= 12) {
			return days;
		}
		if (days <= 24) {
			return days / 2;
		}
		return 10;
	}

	normalizeRange(starts, ends, i) {
		const cfg = chartConfig[i - 1];
		starts[i] = minOr(cfg.min, starts[i]);
		ends[i] = maxOr(cfg.max, ends[i]);
	}

	zoomRange(starts, ends, i) {
		const range = ends[i] - starts[i];
		const factor = range ? range : (Math.abs(starts[i]));
		starts[i] -= (factor / 20);
		ends[i] += (factor / 20);
	}

	alignChannels(cha, chb, starts, ends) {
		const a = getChartConfigIndex(cha) + 1;
		const b = getChartConfigIndex(chb) + 1;
		if (starts[a] != null && starts[b] != null &&
			ends[a] != null && ends[b] != null) {
			let deltaStart = Math.abs(starts[a] - starts[b]);
			let deltaEnd = Math.abs(ends[a] - ends[b]);
			let delta11 = Math.abs(ends[a] - starts[a]);
			let delta10 = Math.abs(ends[b] - starts[b]);
			let threshold = Math.min(delta11, delta10) * 8;
			if (deltaStart < threshold && deltaEnd < threshold) {
				/* align weights */
				console.log("Align " + cha + "/" + chb + ": " + threshold + ": " + deltaStart + ", " + deltaEnd);
				starts[a] = (starts[b] = Math.min(starts[a], starts[b]));
				ends[a] = (ends[b] = Math.max(ends[a], ends[b]));
			} else {
				console.log("No Align " + cha + "/" + chb + ": " + threshold + ": " + deltaStart + ", " + deltaEnd);
			}
		} else {
			console.log("No Align " + cha + "/" + chb);
		}
	}

	render(device) {
		const hist = this.average ? 3 : 1;

		const w = this.chartW;
		const h = this.chartH;
		const offX = this.chartX;
		const offY = this.chartY;

		const numberOfSensors = device.rawStarts.length;
		const deltaValues = Array(numberOfSensors);
		const starts = Array(numberOfSensors);
		const ends = Array(numberOfSensors);
		const coordinates = Array(numberOfSensors);
		const paths = Array(numberOfSensors);
		let transform = null;

		paths.fill("");

		starts[0] = device.rawStarts[0];
		ends[0] = device.rawEnds[0];
		/* time range */
		if (starts[0] != null && ends[0] != null) {
			deltaValues[0] = ends[0] - starts[0];
			if (deltaValues[0] == 0) {
				starts[0] = starts[0] - 1;
				ends[0] = ends[0] + 1;
				deltaValues[0] = ends[0] - starts[0];
			}
			this.startTime = starts[0];
			this.endTime = ends[0];
			transform = function(x) { return ((x - starts[0]) * w / deltaValues[0]) + offX; };
		}

		if (numberOfSensors > 1) {
			const gap = Array(numberOfSensors);
			const times = Array(numberOfSensors);
			const yMin = Array(numberOfSensors);
			const yMax = Array(numberOfSensors);
			const ySum = Array(numberOfSensors);
			const nSum = Array(numberOfSensors);

			gap.fill(1);
			times.fill(0);
			for (let i = 1; i < numberOfSensors; ++i) {
				coordinates[i] = Array();
				ySum[i] = [0];
				nSum[i] = [0];
			}

			device.rangeValues.forEach((v) => {
				const x = Math.round(transform(v[0]));
				for (let i = 1; i < v.length; ++i) {
					const cfg = chartConfig[i - 1];
					const minmax = this.minmax && cfg.scale;
					const valueHist = cfg.scale ? hist : 1
					const t = v[i];
					if (t != null) {
						if (minmax) {
							yMin[i] = minOr(t, yMin[i]);
							yMax[i] = maxOr(t, yMax[i]);
						} else {
							ySum[i][0] += t;
							nSum[i][0]++;
						}
						if (gap[i] == 0) {
							gap[i] = (v[0] - times[i]) > (dayInMillis + 600000) ? 1 : 0;
						}
						times[i] = v[0];

						if (coordinates[i].length == 0 || coordinates[i].at(-1)[0] < x) {
							const point = Array(minmax ? 4 : 3);
							point[0] = x;
							point[1] = gap[i];
							gap[i] = 0;
							if (minmax) {
								starts[i] = minOr(yMin[i], starts[i]);
								ends[i] = maxOr(yMax[i], ends[i]);
								point[2] = yMin[i];
								point[3] = yMax[i];
								yMin[i] = null;
								yMax[i] = null;
							} else {
								let sum = ySum[i][0];
								let n = nSum[i][0];
								const m = n > 4 ? ySum[i].length : minOr(ySum[i].length, 2);
								for (let index = 1; index < m; ++index) {
									sum += ySum[i][index];
									n += nSum[i][index];
								}
								const avg = sum / n;
								starts[i] = minOr(avg, starts[i]);
								ends[i] = maxOr(avg, ends[i]);
								point[2] = avg;
								ySum[i].unshift(0);
								nSum[i].unshift(0);
								if (ySum[i].length > valueHist) {
									ySum[i].pop();
									nSum[i].pop();
								}
							}
							coordinates[i].push(point);
						}
					}
				}
			});
			if (hist > 1) {
				const chartTimeShift = Math.floor(hist / 2);
				for (let i = 1; i < numberOfSensors; ++i) {
					const cfg = chartConfig[i - 1];
					if (cfg.scale && coordinates[i].length > chartTimeShift) {
						// new end point
						const point = Array(3);
						const last = coordinates[i].at(-1);
						point[0] = last[0];
						point[1] = 0;
						let sum = ySum[i][1];
						let n = nSum[i][1];
						const m = n > 4 ? ySum[i].length : minOr(ySum[i].length, 3);
						for (let index = 2; index < m; ++index) {
							sum += ySum[i][index];
							n += nSum[i][index];
						}
						const avg = sum / n;
						point[2] = avg;
						coordinates[i].push(point);
						// shift times
						for (let j = coordinates[i].length - 1; j >= chartTimeShift; --j) {
							const point1 = coordinates[i][j];
							const point2 = coordinates[i][j - chartTimeShift];
							point1[0] = point2[0];
							point1[1] = point2[1];
						}
						// remove first
						coordinates[i].shift();
						coordinates[i][0][1] = 1;
					}
				}
			}
		}

		this.alignChannels("mAs", "mAs0", starts, ends);
		this.alignChannels("kg A", "kg B", starts, ends);

		if (this.zoom) {
			for (let i = 1; i < numberOfSensors; ++i) {
				this.zoomRange(starts, ends, i);
			}
		} else {
			for (let i = 1; i < numberOfSensors; ++i) {
				this.normalizeRange(starts, ends, i);
			}
		}
		device.starts = starts;
		device.ends = ends;

		for (let i = 1; i < numberOfSensors; ++i) {
			if (coordinates[i].length > 0) {
				if (starts[i] != null && ends[i] != null) {
					deltaValues[i] = ends[i] - starts[i];
					let v = Math.min(Math.abs(starts[i]), Math.abs(ends[i])) / 20;
					if (!this.zoom && deltaValues[i] < v) {
						if (v < 0.01) {
							v = 0.01;
						}
						starts[i] -= (v / 2);
						ends[i] += (v / 2);
						deltaValues[i] = ends[i] - starts[i];
					}
					const start = starts[i];
					const delta = deltaValues[i];
					transform = function(x) { return (offY + h) - Math.round((x - start) * h / delta); };
					let m = 1;
					coordinates[i].forEach((p) => {
						const cmd = p[1] ? " M " : m ? " L " : " ";
						m = p[1];
						paths[i] += cmd + p[0] + "," + transform(p[2]);
						if (p.length == 4) {
							const cmd2 = m ? " L " : " ";
							paths[i] += cmd2 + p[0] + "," + transform(p[3]);
						}
					});
				}
			}
		}

		device.paths = paths;
		if (starts[0] && deltaValues[0] > 0) {
			const startDate = new Date(starts[0]);
			startDate.setUTCHours(0);
			startDate.setUTCMinutes(0);
			startDate.setUTCSeconds(0);
			startDate.setUTCMilliseconds(0);
			const offset = dayInMillis - starts[0] + startDate.getTime();
			device.offsetTime = offset;
			device.offsetX = offset * w / deltaValues[0];
		}
	}

	view(dev) {
		const deltaTime = dev.ends[0] - dev.starts[0];
		const chartDays = Math.trunc((deltaTime + dayInMillis - 3600000) / dayInMillis);
		const cols = this.getCols(chartDays);
		const w = this.w;
		const h = this.h;
		const x = this.chartX;
		const y = this.chartY;
		const cw = this.chartW;
		const ch = this.chartH;
		const gw = Math.round(cw / cols);
		const gh = gw;
		/* [0] total number, [1] current index */
		const left = [0, 0];
		const right = [0, 0];
		let s = null
		// ["ms", "mV", "%", "C", "%H", "hPa", "IAQ", dBm", "dB", "mAs", "mAs", "kg A", "kg B", "mV Ext.", "RETRANS", "ms"];
		if (this.signals && this.sensors) {
			s = [null, left, left, right, right, right, right, left, left, left, left, right, right, right, left, left];
		} else if (this.signals) {
			s = [null, left, left, null, null, null, null, right, right, left, left, null, null, null, left, right];
		} else if (this.sensors) {
			s = [null, null, null, left, left, left, right, null, null, null, null, right, right, right, null, null];
		} else {
			s = [null, left, left, right, right, right, left, null, null, left, null, right, right, right, null, right];
		}
		const side = s;

		const now = new Date(dev.statusTime).toUTCString();
		const interval = dev.lastInterval ? `Interval: ${dev.lastInterval}` : "";
		let page =
			`<tr><td colspan='4'>${now}</td><td>${interval}</td></tr>
<tr><td><input type='checkbox' id='cbsignals' onClick='ui.onClick("signals", false)' ${this.signals ? 'checked' : ''}><label for='cbsignals'>Signals</label></td>
<td><input type='checkbox' id='cbsensors' onClick='ui.onClick("sensors", false)' ${this.sensors ? 'checked' : ''}><label for='cbsensors'>Sensors</label></td>
<td><input type='checkbox' id='cbrange1' onClick='ui.onClick("average", true)' ${this.average ? 'checked' : ''}><label for='cbrange1'>Average</label></td>
<td><input type='checkbox' id='cbrange2' onClick='ui.onClick("minmax", true)' ${this.minmax ? 'checked' : ''}><label for='cbrange2'>Min/Max</label></td>
<td><input type='checkbox' id='cbzoom' onClick='ui.onClick("zoom", true)' ${this.zoom ? 'checked' : ''}><label for='cbzomm'>Zoom</label></td></tr>

<tr><td colspan='5'><svg id='devicechart' x='0' y='0' width='${w}' height='${h}' viewBox='0 0 ${w} ${h}'>
<desc>Device Charts</desc>
<defs><pattern id='grid' patternUnits='userSpaceOnUse' x='${x + dev.offsetX}' y='${y}' width='${gw}' height='${gh}'>
<path d='M0,0 v${gw} h${gh}' stroke='lightgrey' fill='none'></path></pattern></defs>
<rect id='chart' x='${x}' y='${y}' width='${cw}' height='${ch}' fill='url(#grid)' stroke='grey'></rect>\n`;

		for (let i = 1; i < dev.paths.length; ++i) {
			if (dev.paths[i].length > 0 && side[i] != null) {
				side[i][0]++;
			}
		}
		if (this.center) {
			const cx = Math.round((dev.statusTime - dev.starts[0]) * cw / (dev.ends[0] - dev.starts[0]) + x);
			page += this.centerMark(cx, y, ch);
		}
		let cha = 0;
		let chaColor = "";
		for (let i = 1; i < dev.paths.length; ++i) {
			if (dev.paths[i].length > 0 && side[i] != null) {
				const cfg = chartConfig[i - 1];
				const color = cfg.color;
				if (cfg.units == "kg A") {
					cha = i;
					chaColor = color;
				}
				page += `<path d='${dev.paths[i]}' fill='transparent' stroke='${color}'></path>\n`;
				if (cha && cfg.units == "kg B") {
					// cha with dashs over chb
					page += `<path d='${dev.paths[cha]}' fill='transparent' stroke='${chaColor}' stroke-dasharray='2'></path>\n`;
				}
				const d = (dev.ends[i] - dev.starts[i]);
				const labels = side[i][0];
				const labelIndex = ++side[i][1];
				if (cfg.scale) {
					const hl = (labels == 1) ? gh / 2 : (labels > 3) ? gh * 2 : gh;
					let yn = labelIndex * (hl / labels);
					function calc(x) { return (((y + ch - x) * d / ch) + dev.starts[i]) / cfg.scale; };
					let digits = dev.starts[i] >= 100 ? 0 : 1;
					if (d > 0) {
						const diffDigits = Math.ceil(-Math.log10(d / cfg.scale)) + 1;
						digits = Math.max(digits, isFinite(diffDigits) ? diffDigits : 0);
					}
					const u = cfg.scale == 1000 ? strip(cfg.units, "m") : cfg.units;
					for (; yn < ch; yn += hl) {
						let value = calc(yn);
						value = value.toFixed(digits);
						const v = value + " " + u;
						const l = side[i] == left;
						page += this.scala(l, color, l ? x : x + cw, l ? 0 : w, yn, v)
					}
				} else {
					//					transform = function(x) { return (y + ch) - Math.round((x - dev.starts[i]) * ch / d); };

					const hl = ch / d;
					let yn = hl;
					function calc(x) { return (((y + ch - x) * d / ch) + dev.starts[i]); };
					const u = cfg.units;
					for (; yn < ch; yn += hl) {
						let value = calc(yn);
						value = value.toFixed(0);
						const v = value + " " + u;
						if (side[i] == left) {
							page += `<text x='0' y='${yn}' fill='${color}' dominant-baseline='middle'>${v}</text>\n`;
							page += `<path d='M ${x - 5},${yn} l 5,0' stroke='${color}'></path>\n`;
						} else {
							page += `<text x='${w}' y='${yn}' fill='${color}' dominant-baseline='middle' text-anchor='end'>${v}</text>\n`;
							page += `<path d='M ${x + cw + 5},${yn} l -5,0' stroke='${color}'></path>\n`;
						}
					}
				}
			}
		}

		if (dev.starts[0]) {
			page += this.mark(dev.starts[0], x, y + ch);
			let xm = ((cols / 4) * gw) + (dev.offsetX % gw);
			page += this.mark(dev.starts[0] + (xm * deltaTime) / cw, Math.round(xm + x), y + ch);
			xm = ((cols * 2 / 4) * gw) + (dev.offsetX % gw);
			page += this.mark(dev.starts[0] + (xm * deltaTime) / cw, Math.round(xm + x), y + ch);
			xm = ((cols * 3 / 4) * gw) + (dev.offsetX % gw);
			page += this.mark(dev.starts[0] + (xm * deltaTime) / cw, Math.round(xm + x), y + ch);
			page += this.mark(dev.ends[0], x + cw, y + ch);
		}

		let desc = this.getDaysDescription();
		if (chartDays < this.getDays()) {
			desc += " / " + chartDays + " shown";
			console.log(desc);
		}
		const modeForward = this.daysSelection == 1 ? " disabled" : "";
		const modeBackward = this.daysSelection == this.daysSelectionMax ? " disabled" : "";
		page += `
</svg></td></tr>
<tr><td><label for="period" id="periodlabel">Period:</label></td>
<td colspan="3">
<button id="perioddec"'${modeForward}>\<</button>
<input id="period" type="range" value="${this.daysSelection}" min="1" max="${this.daysSelectionMax}"></input>
<button id="periodinc"'${modeBackward}>\></button>
<td><output id="periodoutput" for="period">${desc}</output></td></tr>\n`;

		return page;
	}

	scala(left, color, xm, xv, y, v) {
		const a = left ? "" : " text-anchor='end'";
		return `
	<path d='M ${xm},${y} l 5,0' stroke='${color}'></path>
	<text x='${xv}' y='${y}' fill='${color}' dominant-baseline='middle'${a}>${v}</text>\n`;
	}

	mark(dateTimeMillis, x, y) {
		const dateTime = new Date(dateTimeMillis).toISOString();
		const date = dateTime.slice(0, 10);
		const time = dateTime.slice(11, -8);
		return `
<path d='M ${x},${y} l 0,5' stroke='grey'></path>
<text x='${x}' y='${y + 15}' text-anchor='middle'>${time}</text>
<text x='${x}' y='${y + 25}' text-anchor='middle'>${date}</text>`;
	}

	centerMark(x, y1, y2) {
		return `
<path d='M ${x},${y1} L ${x},${y2}' stroke='lightgrey'></path>
<path d='M ${x},${y2} l -2 5 4 0 Z' stroke='grey' fill='none'></path>`;
	}
}

class UiList {

	devicesPerPage = 15;

	constructor() {
		this.reset();
	}

	reset() {
		this.currentList = null;
		this.previousList = null;
		this.deviceListEnd = 0;
		this.position = 0;
		this.update = true;
		this.sortDirection = new Map();
		this.currentSortFn = this.cmpLabel;
	}

	setDeviceList(list) {
		if (list) {
			this.previousList = this.currentList;
			this.currentList = list;
			if (this.currentSortFn) {
				this.currentList.sort(this.currentSortFn);
			}
			if (this.deviceListEnd > list.length) {
				this.deviceListEnd = list.length;
				if (this.position > this.deviceListEnd - this.devicesPerPage) {
					this.last();
				}
			} else {
				this.deviceListEnd = list.length;
			}
		} else {
			this.previousList = null;
			this.currentList = null;
			this.deviceListEnd = 0;
			this.position = 0;
		}
		this.update = true;
	}

	setListPosition(pos) {
		if (pos < 0 || this.deviceListEnd <= 0) {
			pos = 0;
		} else {
			const last = this.deviceListEnd - 1;
			if (pos > last) {
				pos = last;
			}
		}

		if (this.position != pos) {
			this.position = pos;
			this.update = true;
		}
		return this.update;
	}

	cmpLabel(dev1, dev2) {
		const l1 = dev1.label ? dev1.label.toLowerCase() : "";
		const l2 = dev2.label ? dev2.label.toLowerCase() : "";
		let ret = compareItem(l1, l2);
		if (ret == 0) {
			// lower case before upper case
			ret = compareItem(dev2.label, dev1.label);
		}
		return ret;
	}

	cmpLastUpdate(dev1, dev2) {
		return compareItem(dev1.lastModified, dev2.lastModified);
	}

	cmpPdn(dev1, dev2) {
		return compareItem(dev1.pdn, dev2.pdn);
	}

	cmpNetwork(dev1, dev2) {
		const plmn1 = dev1.network ? dev1.network.plmn : "";
		const plmn2 = dev2.network ? dev2.network.plmn : "";
		return compareItem(plmn1, plmn2);
	}

	cmpBand(dev1, dev2) {
		const band1 = dev1.network ? dev1.network.band : "";
		const band2 = dev2.network ? dev2.network.band : "";
		return compareItem(band1, band2);
	}

	cmpUptime(dev1, dev2) {
		return compareItem(dev1.uptime, dev2.uptime);
	}

	cmpBattery(dev1, dev2) {
		if (dev1.batteryLevel != null && dev2.batteryLevel == null) {
			return 1;
		} else if (dev1.batteryLevel == null && dev2.batteryLevel != null) {
			return -1;
		} else {
			return compareItem(dev1.batteryLevel, dev2.batteryLevel);
		}
	}

	getSortDirection(mode) {
		const dir = !(this.sortDirection.get(mode) ?? false);
		this.sortDirection.set(mode, dir);
		return dir;
	}

	sort(mode) {
		if (this.position) {
			return false;
		}
		const cmp = this[mode];
		if (this.getSortDirection(mode)) {
			this.currentSortFn = function(item1, item2) { return cmp(item2, item1); }
		} else {
			this.currentSortFn = cmp;
		}
		this.currentList.sort(this.currentSortFn);
		this.update = true;
		return this.update;
	}

	first() {
		return this.setListPosition(0);
	}

	forward() {
		return this.setListPosition(this.position - this.devicesPerPage);
	}

	backward() {
		return this.setListPosition(this.position + this.devicesPerPage);
	}

	last() {
		return this.setListPosition(this.deviceListEnd - this.devicesPerPage);
	}

	view(groups, details) {
		const previousList = this.previousList;
		const list = this.currentList;
		const now = new Date(Date.now() - timeShift).toUTCString();
		const sort = this.position ? "tb1d" : "tb1";
		const nosort = this.position ? "tb2d" : "tb2";
		let cols = 5;

		let page =
			`<div id='devicelist'>
<input type='checkbox' id='cbgroups' onClick='ui.onClickGroups()' ${groups ? 'checked' : ''}>
<label for='cbgroups'>Groups</label>&nbsp;&nbsp;${now}<br>
<table><thead><tr>
<th colspan='2'><button class='${sort}' onclick='ui.onClickSortList("cmpLabel")'>Device</button></th>
<th colspan='2'><button class='${sort}' onclick='ui.onClickSortList("cmpLastUpdate")'>Last Update</button></th>
<th width='8em'><button class='${nosort}'>&nbsp;</button></th>`;
		if (details) {
			function button(cmp, label) {
				return `<th><button class='${sort}' onclick='ui.onClickSortList("${cmp}")'>${label}</button></th>\n`;
			}
			if (details.provider) {
				++cols;
				page += button("cmpPdn", "Provider")
			}
			if (details.operator) {
				++cols;
				page += button("cmpNetwork", "Operator")
			}
			if (details.band) {
				++cols;
				page += button("cmpBand", "Bd")
			}
			if (details.uptime) {
				++cols;
				page += button("cmpUptime", "Uptime")
			}
			if (details.battery) {
				++cols;
				page += button("cmpBattery", "Bat.")
			}
		}
		page += `</tr></thead>
<tbody>
<tr><td></td></tr>\n`;
		let index = this.position;
		const end = index + this.devicesPerPage;
		const modeForward = index == 0 ? " disabled" : "";
		for (; index < list.length && index < end; ++index) {
			let item = list.at(index);
			let cls = "";
			let mark = "";
			let prev = null;
			if (previousList) {
				const prev = previousList.find((dev) => dev.key == item.key);
				if (prev) {
					if (item.updated) {
						mark = "*";
						cls = "class='changed'";
					}
				} else {
					mark = "+";
					cls = "class='new'";
				}
			}
			page += `<tr ${cls}><td colspan='2'><button class='tb1' onclick='ui.loadDeviceData("${item.key}")'>${item.label}</button></td>`;
			const lm = item.lastModified ?? "";
			page += `<td colspan='2'>${lm}</td><td>${mark}</td>`;
			if (details) {
				let info = item.getDetails();
				if (details.provider) {
					page += `<td>${info.pdn}</td>`;
				}
				if (details.operator) {
					page += `<td>${info.net}</td>`;
				}
				if (details.band) {
					page += `<td>${info.band}</td>`;
				}
				if (details.uptime) {
					let uptime = info.uptime;
					if (uptime.length > 0) uptime += " [d]";
					page += `<td>${uptime}</td>`;
				}
				if (details.battery) {
					let level = "";
					if (info.batteryLevel != null) {
						level = info.batteryLevel + "%";
					}
					page += `<td>${level}</td>`;
				}
			}
			page += `</tr>\n`;
		}
		page += `<tr><td></td></tr>`;

		page += `<tr><td colspan='2'><button onclick='ui.loadDeviceList()'>refresh</button></td>`;

		const modeBackward = index == list.length ? " disabled" : "";
		let text = "(no devices)";
		if (list.length) {
			text = `${this.position + 1} to ${index} of ${list.length}`;
		}
		page += `<td colspan='${cols - 2}'><button onclick='ui.onClickList("first")'${modeForward}>\<\<</button>
&nbsp;<button onclick='ui.onClickList("forward")'${modeForward}>\<</button>
&nbsp;${text}
&nbsp;<button onclick='ui.onClickList("backward")'${modeBackward}>\></button>
&nbsp;<button onclick='ui.onClickList("last")'${modeBackward}>\>\></button></td></tr>`;
		page += `</tbody></table></div>\n`;

		return page;
	}
}

class UiDiagnose {

	constructor(s3diagnose) {
		this.s3diagnose = s3diagnose;
		this.reset();
	}

	reset() {
		this.list = [];
		this.item = "";
		this.etag = null;
		this.diagnose = "";
		this.lines = 0;
	}

	static label(key) {
		const found = key.match(/([^\/]+)\/?$/);
		if (found && found.length > 1) {
			return found[1];
		} else {
			return key;
		}
	}

	async fetch(init, item) {
		item = item ?? this.item;
		this.reset();
		const listRequest = this.s3diagnose.fetchXmlList("diagnose/");
		if (item) {
			if (item != this.item) {
				this.etag = null;
			}
			const request = this.s3diagnose.fetchContent(item, this.etag);
			this.s3diagnose.allStarted();
			const response = await request;
			if (response.status == 304) {
				// no refresh
			} else {
				this.diagnose = response.text;
				this.etag = response.headers.get("etag");
			}
			let lines = 0;
			for (let c of this.diagnose) {
				if (c == '\n') ++lines;
			}
			this.lines = lines;
			this.item = item;
		} else if (!init) {
			this.s3diagnose.allStarted();
		}
		const response = await listRequest;
		if (response) {
			response.xml.querySelectorAll("Contents>Key").forEach((e) => insertItem(this.list, e.textContent));
		}
	}

	view() {
		const list = this.list;
		const cols = 60;
		const rows = this.lines ?? 10;

		let page =
			`<div id='diagnose'><table><tbody>
<tr><td></td></tr>\n`;
		for (let index = 0; index < list.length; ++index) {
			const item = list.at(index);
			const label = UiDiagnose.label(item);
			const cls = (this.item == item) ? "class='current'" : "";
			page += `<tr ${cls}><td><button class='tb1' onclick='ui.loadDiagnose("${item}")'>${label}</button></td></tr>\n`;
		}
		page += `<tr><td></td></tr>`;
		page += `<tr><td><button class='tb1' onclick='ui.loadDiagnose()'>refresh</button></td></tr>`;
		page += `<tr><td></td></tr>`;
		page += `<tr><td><textarea tabindex="-1" readOnly rows='${rows}' cols='${cols}'>${this.diagnose}</textarea></td></tr>\n`;
		page += `</tbody></table></div>\n`;

		return page;
	}
}

class UiLoadProgress {

	constructor() {
		this.reset("Login");
	}

	reset(mode) {
		this.start = Date.now();
		this.loadTime = 0;
		this.max = 0;
		this.current = 0;
		this.bytes = 0;
		this.set = false;
		this.ready = false;
		this.mode = mode == null ? null : (mode + ":");
	}

	setProgress(set, start, finished, bytes) {
		if (!this.ready) {
			this.max += start;
			this.current += finished;
			this.bytes += bytes;
			this.set = this.set || set;
			if (this.set) {
				if (this.current == this.max) {
					this.ready = true;
					this.loadTime = Date.now() - this.start;
				}
			}
		}
		return this.ready;
	}

	getDescription() {
		let num = this.bytes;
		let unit = "b";
		if (this.mode == null || num == 0) {
			return "";
		}
		if (num > 2048) {
			num = Math.round(num / 1024);
			unit = "kb";
		}
		if (this.ready) {
			return `${this.mode} ${num} ${unit}, ${this.loadTime} ms`
		} else {
			return `${this.mode} ${num} ${unit}`;
		}
	}
}

class UiManager {

	width = 630;

	constructor(devices) {
		this.state = {
			login: 0,
			error: null,
			allDevicesList: Array(),
			deviceList: null,
			currentDevice: null,
		};

		this.devices = devices;

		this.uiChart = new UiChart();
		this.uiList = new UiList();
		this.uiLoadProgress = new UiLoadProgress();

		this.resetConfig();

		this.titleView = document.querySelector('#title');
		this.logoView = document.querySelector('#logo');

		this.footerView = getElement(this.createFooter());
		this.progressView = this.footerView.querySelector('#loadview')
		this.errorView = this.footerView.querySelector('#error')
		this.versionView = this.footerView.querySelector('#version')

		this.view = getElement(this.createTabView());

		this.ui = document.querySelector('#app');
		this.ui.parentElement.style.maxWidth = `${this.width}px`;
		this.ui.parentElement.style.minWidth = `${this.width}px`;
		this.ui.replaceChildren(this.view);
		this.ui.insertAdjacentElement('afterend', this.footerView);

		const scripts = document.querySelectorAll("script[src]");
		if (scripts) {
			this.sources = new Map();
			scripts.forEach((s) => {
				console.log("Add URL " + s.src);
				this.sources.set(s.src, "")
			});
			this.checkSources();
		}
	}

	resetConfig() {
		if (this.deviceGroups) {
			this.deviceGroups.reset();
			this.deviceGroups = null;
		}
		this.details = null;
		this.enableDiagnose = false;
		this.enableConfig = true;
		this.enableConfigWrite = false;
		this.userTitle = null;
		this.diagnoseUi = null;
		this.showDiagnose = false;
		this.showDeviceList = false;
	}

	setState(state) {
		for (let field in state) {
			this.state[field] = state[field];
		}
		if ('deviceList' in state) {
			this.uiList.setDeviceList(state.deviceList)
			if (state.deviceList && state.deviceList.length == 1) {
				const device = state.deviceList[0];
				this.loadDeviceData(device.key);
				return;
			}
		}
		this.render();
	}

	setRequestState(set, start, finished, bytes, error, login) {
		const ready = this.uiLoadProgress.setProgress(set || error, start, finished, bytes);
		const label = this.uiLoadProgress.getDescription();
		if (this.progress && this.progressLabel) {
			if (ready || bytes) {
				this.progressLabel.innerText = label;
			}
			if (this.uiLoadProgress.set) {
				this.progress.value = this.uiLoadProgress.current;
				this.progress.max = this.uiLoadProgress.max;
				if (ready) {
					this.progress.setAttribute("class", 'ready');
				}
			}
		}
		if (error) {
			login = login == undefined ? this.state.login : login
			let newState = {
				login: login,
				error: error,
			}
			if (!newState.login) {
				s3 = null;
				this.resetConfig();
				this.uiChart.reset();
				this.uiList.reset();
			}
			this.setState(newState);
		}
	}

	resetProgress(mode) {
		this.state.error = null;
		this.errorView.innerText = "";
		this.uiLoadProgress.reset(mode);
		if (mode == null) {
			this.progressView.replaceChildren();
			this.progress = null;
			this.progressLabel = null;
		} else {
			if (this.progress == null) {
				this.progressView.insertAdjacentHTML('afterbegin', `<label id="progresstext" for="loadprogress">Load:</label><progress id='loadprogress' max='${this.uiLoadProgress.max}'></progress>\n`);
				this.progress = this.progressView.querySelector('#loadprogress');
				this.progress.style.width = `${this.width / 2}px`;
				this.progressLabel = this.progressView.querySelector('#progresstext')
			}
			this.progress.removeAttribute("class");
			this.progress.removeAttribute("value");
			this.progress.max = 0;
			this.progressLabel.innerText = this.uiLoadProgress.getDescription();
		}
	}

	async loadDeviceData(key, refresh) {
		this.resetProgress("Load");
		const dev = this.state.deviceList.find((dev) => dev.key == key);
		const days = this.uiChart.getDays();
		const center = this.uiChart.getCenter(refresh);
		const result = await dev.loadData(center, days, this.enableConfig);
		if (result.device) {
			this.uiChart.render(result.device);
			this.showDeviceList = false;
			this.showDiagnose = false;
		}
		this.setState({ currentDevice: result.device, error: result.error });
	}

	loadCurrentDeviceData() {
		const dev = this.state.currentDevice;
		if (dev) {
			this.loadDeviceData(dev.key);
		}
	}

	async loadDeviceList() {
		this.resetProgress("Load");
		this.uiChart.getCenter(true)
		const groups = this.deviceGroups;
		let allDevices = this.state.allDevicesList;
		if (groups) {
			allDevices.forEach((dev) => dev.fit = false);
		}
		const result = await DeviceData.loadDeviceList(allDevices, groups, this.details);
		if (groups) {
			if (await groups.refresh(result.newDevice)) {
				groups.update(allDevices);
			}
			if (groups.filter) {
				allDevices = allDevices.filter((dev) => dev.fit);
			}
		}
		if (allDevices === this.state.allDevicesList) {
			// copy for sorting in view
			allDevices = Array.from(allDevices);
		}
		this.showDiagnose = false;
		this.showDeviceList = true;
		this.setState({ currentDevice: null, deviceList: allDevices, error: result.error });
	}

	async loadDiagnose(item) {
		this.resetProgress("Load");
		await this.diagnoseUi.fetch(false, item);
		this.showDeviceList = false;
		this.showDiagnose = true;
		this.render();
	}

	async writeDeviceConfig() {
		if (this.enableConfigWrite) {
			try {
				const config = document.querySelector('#deviceconfig');
				const dev = this.state.currentDevice;
				if (config && dev) {
					this.showDiagnose = false;
					this.showDeviceList = false;
					const newConfig = config.value;
					const oldConfig = dev.config ?? "";
					if (oldConfig == newConfig) {
						this.setState({ error: "No change to write." });
					} else {
						this.resetProgress("Read");
						const changed = await dev.readConfig();
						if (changed) {
							if (newConfig != dev.config) {
								this.setState({ error: "Changed in the meantime." });
							} else {
								this.setState({ error: "Already changed." });
							}
						} else {
							console.log("writing ...");
							this.resetProgress("Write");
							const write = await dev.writeConfig(newConfig);
							if (write && write.text == "") {
								console.log("write succeded!");
								this.render();
							} else {
								console.log("write failed!");
							}
						}
					}
				}
			} catch (error) {
				this.setState({ error: error });
			}
		}
	}

	loginValue(json, field, def) {
		let value = def;
		const key = field.toLowerCase();
		for (let property in json) {
			if (key == property.toLowerCase()) {
				value = json[property];
				if (typeof value == 'string') {
					const textValue = value.toLowerCase();
					if (textValue == "false" || textValue == "0") {
						value = false;
					}
				}
				break;
			}
		}
		return value;
	}

	parseLoginDetails(value) {
		const details = {};
		const lower = value.toLowerCase();
		if (lower == "true" || lower == "1") {
			details.provider = true;
			details.operator = true;
			details.uptime = true;
		} else if (lower == "all") {
			details.provider = true;
			details.operator = true;
			details.band = true;
			details.uptime = true;
			details.battery = true;
		} else {
			value.split(/,/).forEach((d) => details[d] = true);
		}
		return details;
	}

	resetSession() {
		this.resetConfig();
		this.logoView.replaceChildren();
		this.uiChart.reset();
		this.uiList.reset();
		this.setState({
			login: 0,
			error: null,
			allDevicesList: Array(),
			deviceList: null,
			currentDevice: null
		});
	}

	async login() {
		window.onbeforeunload = (event) => { event.preventDefault(); return event.returnValue = ''; };
		this.resetProgress("Login");
		this.resetSession();
		const name = document.querySelector('#name');
		const pw = document.querySelector('#pw');
		if (name && pw) {
			try {
				this.uiLoadProgress.set = true;
				timeShift = 0;
				const s3login = new S3Request(name.value, pw.value, null, null, null, this.setRequestState.bind(this));
				let now = Date.now();
				let response = await s3login.fetchUrl("login");
				// now + RTT / 2
				let time = Date.now() - now;
				const amzDate = response.headers.get("x-amz-date");
				if (response.status == 401 && amzDate) {
					// retry with server time 
					s3login.ignoreResponse();
					now = Date.now();
					response = await s3login.fetchUrl("login", amzDate);
					time = Date.now() - now;
				}
				const login = await s3login.getJson(response);
				if (login) {
					if (amzDate) {
						// amz-date format:  20230528T115614Z
						const ad = amzDate
						const isoDate = `${ad.slice(0, 4)}-${ad.slice(4, 6)}-` +
							`${ad.slice(6, 11)}:${ad.slice(11, 13)}:${ad.slice(13)}`;
						// time offset 
						now += time / 2;
						now = Math.floor(now / 1000) * 1000;
						const timeOffset = new Date(isoDate).getTime() - now;
						if (Math.abs(timeOffset) > time) {
							timeShift = -timeOffset;
							console.log("timeshift " + timeShift);
						}
					}
					this.checkSources();
					console.log(login);
					const json = login.json;
					for (let item in json) {
						if (item.match(/20\d{6}/)) {
							json[item] = S3Request.hexToBuffer(json[item]);
						}
					}
					let logo = null;
					if (json.config) {
						this.enableDiagnose = this.loginValue(json.config, "diagnose", false);
						this.enableConfig = this.loginValue(json.config, "configRead", true);
						this.enableConfigWrite = this.loginValue(json.config, "configWrite", false);
						this.userTitle = this.loginValue(json.config, "title", null);
						logo = this.loginValue(json.config, "logo", null);
						const period = this.loginValue(json.config, "period", null);
						const signals = this.loginValue(json.config, "signals", false);
						const sensors = this.loginValue(json.config, "sensors", false);
						const average = this.loginValue(json.config, "average", false);
						const minmax = average ? false : this.loginValue(json.config, "minmax", false);
						const zoom = this.loginValue(json.config, "zoom", false);
						this.uiChart.reset(period, signals, sensors, average, minmax, zoom);
						let details = this.loginValue(json.config, "details", false);
						if (details) {
							this.details = this.parseLoginDetails(details);
						}
					}
					if (json.defs) {
						const providers = new Map(defaultProviderMap);
						for (let field in json.defs) {
							providers.set(field, json.defs[field]);
						}
						providerMapInit(providers);
					} else {
						providerMapInit(defaultProviderMap);
					}

					s3HttpHost = new S3Request(name.value, pw.value, null, null, null, this.setRequestState.bind(this));
					s3 = new S3Request(json.id, null, json.region, json.base, json, this.setRequestState.bind(this));
					this.state.login = 1;

					if (json.groups) {
						this.deviceGroups = new DeviceGroups(json.groups, login.headers.get("etag"));
						console.log(json.groups);
					} else {
						console.log("no groups");
					}
					/*
					const insert = document.createElement('script');
					insert.innerHTML = `function plmn(dev) {
						if (dev.network) {
							return dev.network.plmn;
						}
						return "???";
					}`;
					const body = document.querySelector('html>body');
					body.appendChild(insert);*/

					if (logo && this.logoView) {
						try {
							const logoSvg = await s3.fetchUrlXml(json.base + S3Request.s3KeyEncode(logo, true), null, true);
							if (logoSvg && logoSvg.xml) {
								const svg = logoSvg.xml.querySelector("svg");
								if (svg) {
									svg.setAttribute("id", "logosvg");
									this.logoView.replaceChildren(svg);
									console.log("logo: " + logo);
								}
							}
						} catch (error) {
							console.log("fetch logo failed: " + error.message);
						}
					}
					if (this.enableDiagnose) {
						const s3diagnose = new S3Request(name.value, pw.value, null, "proxy/", null, this.setRequestState.bind(this));
						this.diagnoseUi = new UiDiagnose(s3diagnose);
						this.diagnoseUi.fetch(true);
					}
					this.loadDeviceList();
					return;
				}
			} catch (error) {
				console.log(error.stack);
				this.setState({ error: error });
			}
		} else if (name) {
			this.setState({ error: "password missing!" });
		} else if (pw) {
			this.setState({ error: "name missing!" });
		} else {
			this.setState({ error: "name and password missing!" });
		}
		window.onbeforeunload = null;
	}

	logout() {
		this.resetProgress(null);
		this.resetSession();
		window.onbeforeunload = null;
	}

	createFooter() {
		const page =
			`<table width="${this.width}"><tbody> 
<tr><td id='error'></td></tr>
<tr><td id='loadview'></td></tr>
<tr><td id="version">${version}</td></tr>
</tbody></table>`;
		return page;
	}

	errorPageView(error) {
		const page =
			`<table><tbody>
<tr><td>${error.message}</td></tr>
<tr><td><button onclick='ui.logout()'>reload</button></td></tr>
</tbody></table>`;
		return page;
	}

	loginView() {
		const mode = this.state.login ? "" : " disabled";
		const page =
			`<form onsubmit='return false;'><table><tbody>
<tr><td><label html-for='name'>Name:</lable></td><td colspan='2'><input id='name' name='login' autofocus></input></td></tr>
<tr><td><label html-for='pw'>Password:</lable></td><td colspan='2'><input id='pw' name='login' type='password'></input></td></tr>
<tr><td><button id='login' onclick='ui.login()'>login</button></td>
<td><button id='logout' onclick='ui.logout()'${mode}>logout</button></td></tr>
</tbody></table></form>`;
		return page;
	}

	updateLoginView(view) {
		const but = view.querySelector('#logout');
		if (but) {
			if (this.state.login) {
				if (but.hasAttribute("disabled")) {
					but.removeAttribute("disabled");
					console.log("logout enabled");
				}
			} else {
				if (!but.hasAttribute("disabled")) {
					but.setAttribute("disabled", "disabled");
					console.log("logout disabled");
				}
			}
		} else {
			console.log("no logout");
		}
	}

	onClickGroups() {
		if (this.deviceGroups) {
			this.deviceGroups.toggleFilter();
		}
		this.uiList.previousList = null;
		this.uiList.currentList = null;
		this.state.deviceList = null;
		this.loadDeviceList();
	}

	onClickList(mode) {
		if (this.uiList[mode]()) {
			this.showDeviceList = true;
			this.showDiagnose = false;
			this.render();
		}
	}

	onClickSortList(mode) {
		if (this.uiList.sort(mode)) {
			this.showDeviceList = true;
			this.showDiagnose = false;
			this.render();
		}
	}

	onClickStatus(delta) {
		const center = this.uiChart.center;
		if (center == 0 && delta >= 0) {
			return;
		}
		const dev = this.state.currentDevice;
		if (dev) {
			const newCenter = dev.findNearestTime(center, delta);
			if (newCenter < 0) {

			} else if (center != newCenter) {
				this.uiChart.center = newCenter;
				this.loadDeviceData(dev.key);
			}
		}
	}

	onClick(flag, render) {
		this.uiChart.toggle(flag);
		if (render) {
			this.uiChart.render(this.state.currentDevice);
		}
		this.render();
	}

	form(value) {
		if (value && Number.isInteger(value)) {
			return value + " / 0x" + new Number(value).toString(16).toUpperCase();
		}
		return value;
	}

	deviceView(dev, pageMode) {
		const cols = 80;
		const rows = 20;
		let page = `<table>`;

		if (pageMode == 0) {
			page += `<tbody id='devicechartpage'>`;
			page += this.uiChart.view(dev);
		} else if (pageMode == 1) {
			page += `<tbody id='devicestatuspage'>`;
			if (dev.statusTime) {
				const now = new Date(dev.statusTime).toUTCString();
				const interval = dev.lastInterval ? `Interval: ${dev.lastInterval}` : "";
				page += `<tr><td colspan='3'>${now}</td><td>${interval}</td></tr>\n`;
			}
			if (dev.network) {
				const tac = this.form(dev.network.tac);
				const cell = this.form(dev.network.cell);
				page +=
					`<tr><td>Mode:</td><td>${dev.network.mode}</td></tr>
<tr><td>Type:</td><td>${dev.network.type}</td><td>Band:</td><td>${dev.network.band}</td></tr>
<tr><td>PLMN:</td><td>${dev.network.plmn}</td><td>TAC:</td><td>${tac}</td></tr>\n`;
				if (Number.isInteger(dev.network.cell)) {
					const tower = Math.floor(dev.network.cell / 256);
					const towerText = this.form(tower);
					page += `<tr><td>Cell:</td><td>${cell}</td><td>Tower:</td><td>${towerText}</td></tr>\n`;
				} else {
					page += `<tr><td>Cell:</td><td>${cell}</td></tr>\n`;
				}
			}
			const status = dev.status == null ? "" : dev.status;
			page += `<tr><td colspan='4'><textarea id='devicestatus' tabindex="-1" readOnly rows='${rows}' cols='${cols}'>${status}</textarea></td></tr>\n`;

			function buttons() {
				var div = "";
				for (const delta of arguments) {
					div += `<button onclick='ui.onClickStatus(${delta})'>`;
					if (delta < 0) {
						div += `\<${-delta}`;
					} else {
						div += `${delta}\>`;
					}
					div += `</button>&nbsp;`;
				}
				return div;
			}
			page += "<tr><td colspan='4'>";
			page += buttons(-1000, -100, -20, -10, -1, 1, 10, 20, 100, 1000);

		} else if (pageMode == 2 && this.enableConfig) {
			page += `<tbody id='deviceconfigpage'>`;
			if (dev.configTimestamp) {
				const configDate = new Date(dev.configTimestamp);
				const now = configDate.toUTCString();
				let cls = "";
				let mark = "";
				if (dev.statusTime) {
					const statusDate = new Date(dev.statusTime);
					if (statusDate.getTime() <= configDate.getTime()) {
						mark = " *";
						cls = " class='changed'";
					}
				}
				page += `<tr${cls}><td colspan='3'>${now}${mark}</td></tr>\n`;
			}
			const mode = this.enableConfigWrite ? 'tabindex="0"' : 'tabindex="-1" readOnly';
			const config = dev.config == null ? "" : dev.config;
			page += `<tr><td colspan='4'><textarea id='deviceconfig' ${mode} rows='${rows}' cols='${cols}'>${config}</textarea></td></tr>\n`;
		}
		page += `<tr><td colspan='2'><button onclick='ui.loadDeviceData("${dev.key}", true)'>refresh/most recent</button>`;
		if (pageMode == 2 && this.enableConfig) {
			const writeMode = this.enableConfigWrite && dev.fit ? "" : " disabled";
			page += ` <button onclick='ui.writeDeviceConfig()'${writeMode}>write</button>`;
		}
		page += `</td></tr>\n</tbody></table>`;
		return page;
	}

	createTabView(list, dev) {
		const withChart = dev && dev.starts[0] && dev.ends[0];
		const tab1 = this.loginView();
		const tab2 = list ? this.listView(list) : "";
		const tab3 = withChart ? this.deviceView(dev, 0) : "";
		const tab4 = dev ? this.deviceView(dev, 1) : "";
		const tab5 = (dev && this.enableConfig) ? this.deviceView(dev, 2) : "";
		const tab6 = this.enableDiagnose ? "" : "";
		const tabLogin = 'tabindex="0"';
		const tabList = list ? 'tabindex="0"' : 'tabindex="-1" aria-disabled="true"';
		const tabChart = withChart ? 'tabindex="0"' : 'tabindex="-1" aria-disabled="true"';
		const tabDevice = dev ? 'tabindex="0"' : 'tabindex="-1" aria-disabled="true"';
		const tabConfig = (dev && this.enableConfig) ? 'tabindex="0"' : 'tabindex="-1" aria-disabled="true"';
		const tabDiagnose = this.enableDiagnose ? 'tabindex="0"' : 'tabindex="-1" aria-disabled="true" aria-hidden="true"';

		const page =
			`<div>
<ul role="tablist" id="tablist">
  <li id="login-tab" data-title="Login:" role="tab" aria-controls="login-panel" aria-selected="true" ${tabLogin}">Login</li>
  <li id="list-tab" data-title="Devices:" role="tab" aria-controls="list-panel" aria-selected="false" ${tabList}">List</li>
  <li id="chart-tab" data-title="Devices:" role="tab" aria-controls="chart-panel" aria-selected="false" ${tabChart}>Chart</li>
  <li id="status-tab" data-title="Devices:" role="tab" aria-controls="status-panel" aria-selected="false" ${tabDevice}>Status</li>
  <li id="config-tab" data-title="Devices:" role="tab" aria-controls="config-panel" aria-selected="false" ${tabConfig}>Configuration</li>
  <li id="diagnose-tab" data-title="Diagnose:" role="tab" aria-controls="diagnose-panel" aria-selected="false" ${tabDiagnose}>Diagnose</li>
</ul>
<div id="tabcontent">
  <div id="login-panel" role="tabpanel" aria-labelledby="login-tab" aria-hidden="false">
    ${tab1}
  </div>
  <div id="list-panel" role="tabpanel" aria-labelledby="list-tab" aria-hidden="true">
    ${tab2}
  </div>
  <div id="chart-panel" role="tabpanel" aria-labelledby="chart-tab" aria-hidden="true">
    ${tab3}
  </div>
  <div id="status-panel" role="tabpanel" aria-labelledby="status-tab" aria-hidden="true">
    ${tab4}
  </div>
  <div id="config-panel" role="tabpanel" aria-labelledby="config-tab" aria-hidden="true">
    ${tab5}
  </div>
  <div id="diagnose-panel" role="tabpanel" aria-labelledby="diagnose-tab" aria-hidden="true">
    ${tab6}
  </div>
</div></div>`;

		const elem = getElement(page);
		const tabs = elem.querySelector('#tablist');
		tabs.addEventListener('click', this.clickHandler.bind(this));
		tabs.addEventListener('keypress', this.keyHandler.bind(this));
		this.addChartInputHandler(elem);
		this.selectDefaultTab(elem, dev);
		return elem;
	}

	addChartInputHandler(elem) {
		const timer = {
			id: null,
		};
		const period = elem.querySelector('#period');
		function update(ui, value, delay) {
			const periodOutput = elem.querySelector('#periodoutput');
			if (ui.uiChart.setDaysSelection(value)) {
				periodOutput.innerText = ui.uiChart.getDaysDescription();
				if (timer.id) {
					window.clearTimeout(timer.id);
				}
				if (delay != undefined && delay > 0) {
					timer.id = window.setTimeout(ui.loadCurrentDeviceData.bind(ui), delay);
				} else {
					ui.loadCurrentDeviceData();
				}
			}
		}
		if (period) {
			period.addEventListener('input', (ev) => update(this, Number(ev.target.value), 1000));
		}
		const dec = elem.querySelector('#perioddec');
		if (dec) {
			dec.addEventListener('click', (ev) => update(this, this.uiChart.daysSelection - 1));
		}
		const inc = elem.querySelector('#periodinc');
		if (inc) {
			inc.addEventListener('click', (ev) => update(this, this.uiChart.daysSelection + 1));
		}
		let moves = 0;
		const svg = elem.querySelector('#devicechart');
		if (svg) {
			svg.addEventListener('click', (ev) => {
				if (timer.id) {
					window.clearTimeout(timer.id);
				}
				if (this.uiChart.setChartX(ev.offsetX, ev.offsetY, svg, this.state.currentDevice)) {
					if (moves > 1) {
						this.loadCurrentDeviceData();
					} else {
						moves = 0;
						timer.id = window.setTimeout(ui.loadCurrentDeviceData.bind(ui), 2000);
					}
				}
				svg.style.cursor = 'default';
			});
			svg.addEventListener('mousemove', (ev) => {
				++moves;
				this.uiChart.viewMarker(ev.offsetX, ev.offsetY, svg, this.state.currentDevice);
			});
			svg.addEventListener('mouseleave', (ev) => {
				this.uiChart.removeMarker(svg);
			});
		}
	}

	clickHandler(elem) {
		console.log("click " + elem);
		this.selectTab(document, elem.target);
	}

	keyHandler(elem) {
		console.log("key " + elem.key);
		if (elem.key == "Enter") {
			elem.target.click();
			elem.preventDefault();
		}
	}

	selectTab(view, tab) {

		const selected = tab.getAttribute('aria-selected');
		if (selected == null) {
			console.log("no aria-target!");
			return;
		}
		let title = tab.dataset.title;
		if (title || this.userTitle) {
			title ??= "";
			if (title == "Devices:" && this.state.currentDevice) {
				title = "Device " + this.state.currentDevice.label;
			}
			if (this.userTitle) {
				title = this.userTitle + "/" + title;
			}
			this.titleView.innerText = title;
		}
		if (selected === "true") {
			console.log("already selected!");
			return;
		}
		if (tab.getAttribute('aria-disabled') === "true") {
			console.log("disabled!");
			return;
		};

		const panelId = tab.getAttribute('aria-controls');
		if (!panelId) {
			console.log("missing panel id!");
			return;
		};

		const panel = view.querySelector('#' + panelId);
		if (!panel) {
			console.log("missing panel!");
			return;
		};

		const selectedTabs = view.querySelectorAll('li[aria-selected="true"]');
		selectedTabs.forEach((t) => t.setAttribute('aria-selected', 'false'));

		const panels = view.querySelectorAll('div[aria-hidden="false"]');
		panels.forEach((p) => p.setAttribute('aria-hidden', 'true'));

		tab.setAttribute('aria-selected', 'true');
		panel.setAttribute('aria-hidden', 'false');

		if (tab.id == "login-tab") {
			const name = panel.querySelector('#name');
			if (name && !name.value) {
				name.focus();
			} else {
				const login = panel.querySelector('#login');
				if (login) {
					login.focus();
				}
			}
		}
	}

	selectDefaultTab(view, dev, withChart) {
		const tab1 = view.querySelector('#login-tab');
		const tab2 = view.querySelector('#list-tab');
		const tab3 = view.querySelector('#chart-tab');
		const tab4 = view.querySelector('#status-tab');
		const tab5 = view.querySelector('#config-tab');
		const tab6 = view.querySelector('#diagnose-tab');

		if (dev && !this.showDeviceList && !this.showDiagnose) {
			const selectedTab = view.querySelector('[aria-selected="true"]');
			if (selectedTab != tab3 && selectedTab != tab4 &&
				(!this.enableConfig || selectedTab != tab5)) {
				if (withChart) {
					this.selectTab(view, tab3);
				} else {
					this.selectTab(view, tab4);
				}
			}
		} else if (this.showDiagnose) {
			this.selectTab(view, tab6);
		} else if (this.showDeviceList) {
			this.selectTab(view, tab2);
		} else {
			this.selectTab(view, tab1);
		}
	}

	updateTabView(view, list, dev) {
		const tab2 = view.querySelector('#list-tab');
		const tab3 = view.querySelector('#chart-tab');
		const tab4 = view.querySelector('#status-tab');
		const tab5 = view.querySelector('#config-tab');
		const tab6 = view.querySelector('#diagnose-tab');

		let panel2 = null;
		let panel3 = null;
		let panel4 = null;
		let panel5 = null;
		let panel6 = null;

		this.updateLoginView(view.querySelector('#login-panel'));
		if (dev) {
			const withChart = dev.allValues.length > 0; //  dev.starts[0] && dev.ends[0];
			panel3 = withChart ? this.deviceView(dev, 0) : null;
			panel4 = this.deviceView(dev, 1);
			if (this.enableConfig) {
				panel5 = this.deviceView(dev, 2);
			}
		}
		if (this.uiList.update) {
			if (list) {
				const groups = this.deviceGroups ? this.deviceGroups.filter : false;
				panel2 = this.uiList.view(groups, this.details);
			}
			this.updateTabAndPanel(view, tab2, panel2);
			this.uiList.update = false;
		}
		this.updateTabAndPanel(view, tab3, panel3);
		if (panel3) {
			this.addChartInputHandler(view);
		}
		this.updateTabAndPanel(view, tab4, panel4);
		if (this.enableConfig) {
			this.updateTabAndPanel(view, tab5, panel5);
		}
		if (this.enableDiagnose && this.diagnoseUi) {
			panel6 = this.diagnoseUi.view();
			tab6.setAttribute('aria-hidden', 'false');
		} else {
			tab6.setAttribute('aria-hidden', 'true');
		}
		this.updateTabAndPanel(view, tab6, panel6);
		this.selectDefaultTab(view, dev, panel3);
	}

	updateTabAndPanel(view, tab, elem) {
		const panelId = tab.getAttribute('aria-controls');
		if (!panelId) {
			console.log("missing panel id!");
			return;
		}
		const panel = view.querySelector('#' + panelId);
		if (!panel) {
			console.log("missing panel!");
			return;
		}
		if (elem) {
			if (tab.hasAttribute('aria-disabled')) {
				console.log("enable " + tab.id);
				tab.removeAttribute('aria-disabled');
			}
			tab.setAttribute('tabindex', '0');
			panel.replaceChildren(getElement(elem));
		} else {
			if (!tab.hasAttribute('aria-disabled')) {
				console.log("disable " + tab.id);
				tab.setAttribute('aria-disabled', 'true');
			}
			tab.setAttribute('tabindex', '-1');
			panel.replaceChildren();
		}
	}

	render() {
		try {
			console.log(this.state);
			if (!this.state.login) {
				this.updateTabView(this.view, null, null);
			} else {
				this.updateTabView(this.view, this.state.deviceList, this.state.currentDevice)
			}
			let message = "";
			if (this.state.error) {
				message = this.state.error;
				if (this.state.error instanceof Error) {
					message = this.state.error.message;
				}
			}
			this.errorView.innerText = message;
			this.ui.replaceChildren(this.view);
		} catch (error) {
			console.error(error);
			this.resetProgress(null);
			this.titleView.innerText = "Error:";
			const view = getElement(this.errorPageView(error));
			this.ui.replaceChildren(view);
		}
	}

	async checkSources() {
		if (this.sources && this.versionView) {
			this.sources.forEach((etag, url, map) => {
				const request = new Request(url, {
					method: 'GET',
					headers: {
					},
					mode: 'cors',
					cache: 'no-cache',
				});
				if (etag) {
					request.headers.set("If-None-Match", etag);
				}
				fetch(request).then((response) => {
					const newEtag = response.headers.get("etag");
					if (newEtag) {
						if (etag) {
							if (etag != newEtag) {
								console.log("ETAG '" + etag + "' != '" + newEtag + "'");
								this.versionView.innerText = version + " (Please refresh page, update available!)"
								this.versionView = null;
							} else {
								console.log("ETAG '" + newEtag + "' not changed!");
							}
						} else {
							console.log("ETAG '" + newEtag + "' " + url)
							map.set(url, newEtag);
						}
					}
				});

			})
		}
	}
}

let s3HttpHost = null;
let s3 = null;
let ui = null;

if (document.querySelector('#app'))
	createView()
else
	document.addEventListener("DOMContentLoaded", createView);


function createView() {
	let devs = [];
	if (window.location.search) {
		devs = strip(window.location.search, "?").split("&");
	}
	console.log(devs);
	ui = new UiManager(devs);
	ui.render();
}
