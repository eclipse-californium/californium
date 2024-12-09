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

/**
 * tago.io "payload parser" for the connector.
 */

class ValuesConfig {
	constructor(regex, unit, name, group) {
		this.regex = regex;
		this.unit = unit;
		this.name = name;
	}
}

const valuesConfig = [
	new ValuesConfig(/\s*([+-]?\d+)\smV/, "mV", "voltage"),
	new ValuesConfig(/mV\s+([+-]?\d+(\.\d+)?)\%/, "%", "battery"),
	new ValuesConfig(/\s*([+-]?\d+(\.\d+)?)(,([+-]?\d+(\.\d+)?))*\sC/, "°C", "temperature"),
	new ValuesConfig(/\s*([+-]?\d+(\.\d+)?)(,([+-]?\d+(\.\d+)?))*\s%H/, "%H", "humidity"),
	new ValuesConfig(/\s*([+-]?\d+(\.\d+)?)(,([+-]?\d+(\.\d+)?))*\shPa/, "hPa", "pressure"),
	new ValuesConfig(/\s*RSRP:\s*([+-]?\d+(\.\d+)?)\sdBm/, "dBm", "RSRP"),
	new ValuesConfig(/\s*SNR:\s*([+-]?\d+(\.\d+)?)\sdB/, "dB", "SNR"),
	new ValuesConfig(/\s*RETRANS:\s*(\d+)/, "Retr.", "retransmissions"),
	new ValuesConfig(/\s*RTT:\s*([+-]?\d+)\sms/, "ms", "RTT"),
];

function conv(value, hexLen) {
	if (hexLen) {
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
	}
	const n = Number(value);
	if (n === Number(n)) {
		return n;
	}
	return undefined;
}

function parseValueSet(line, values) {
	let foundValues = 0;
	for (let i = 0; i < valuesConfig.length; ++i) {
		if (values[i] == undefined && valuesConfig[i].regex) {
			const found = line.match(valuesConfig[i].regex);
			if (found && found.length > 1) {
				const n = conv(found[1]);
				if (n !== undefined) {
					values[i] = n;
					++foundValues;
				}
			}
		}
	}
	return foundValues;
}

const values = [];
const lines = raw_payload.split(/\r?\n/);
let found = 0;
lines.map((line) => found += parseValueSet(line, values));
payload = [];
if (found > 0) {
	for (let i = 0; i < values.length; ++i) {
		if (values[i]) {
			payload.push(
				{
					"variable": valuesConfig[i].name,
					"value": values[i],
					"unit": valuesConfig[i].unit
				}
			)
		}
	}
}
