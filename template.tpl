___TERMS_OF_SERVICE___

By creating or modifying this file you agree to Google Tag Manager's Community
Template Gallery Developer Terms of Service available at
https://developers.google.com/tag-manager/gallery-tos (or such other URL as
Google may provide), as modified from time to time.


___INFO___

{
  "type": "MACRO",
  "id": "cvt_temp_public_id",
  "version": 1,
  "securityGroups": [],
  "displayName": "The IP Transformer/Anonymizer",
  "description": "Anonymize IPv4/IPv6 addresses with multiple methods including removing octets, hexets for IPV6, redacting, or replacing with a static IP.",
  "containerContexts": [
    "SERVER"
  ]
}


___TEMPLATE_PARAMETERS___

[
  {
    "type": "SELECT",
    "name": "anonymization_method",
    "displayName": "Anonymization Method",
    "macrosInSelect": false,
    "selectItems": [
      {
        "value": "last_octet",
        "displayValue": "Remove Last Octet"
      },
      {
        "value": "last_two_octets",
        "displayValue": "Remove Last Two Octets"
      },
      {
        "value": "last_three_octets",
        "displayValue": "Remove Last Three Octets"
      },
      {
        "value": "redact_ip",
        "displayValue": "Redact IP Address"
      },
      {
        "value": "static_ip",
        "displayValue": "Replace with Static IP"
      },
      {
        "value": "hash_ip",
        "displayValue": "Hash IP Address (SHA-256)"
      }
    ],
    "simpleValueType": true,
    "help": "Select your preferred IP anonymization or hashing method."
  },
  {
    "type": "TEXT",
    "name": "static_ip_address",
    "displayName": "Static IP Address",
    "simpleValueType": true,
    "enablingConditions": [
      {
        "paramName": "anonymization_method",
        "paramValue": "static_ip",
        "type": "EQUALS"
      }
    ],
    "help": "Provide the static IP address to replace the input IP."
  },
  {
    "type": "RADIO",
    "name": "ip_source",
    "displayName": "IP Address Source",
    "radioItems": [
      {
        "value": "read_from_event_data",
        "displayValue": "Read from Event Data"
      },
      {
        "value": "use_variable_value",
        "displayValue": "Variable Value",
        "subParams": [
          {
            "type": "SELECT",
            "name": "ip_address_variable",
            "displayName": "IP Address Variable",
            "macrosInSelect": true,
            "selectItems": [],
            "simpleValueType": true
          }
        ]
      }
    ],
    "simpleValueType": true,
    "help": "Specify the source of the IP address."
  },
  {
    "type": "RADIO",
    "name": "hash_encoding",
    "displayName": "Hash Output Encoding",
    "radioItems": [
      {
        "value": "hex",
        "displayValue": "Hexadecimal"
      },
      {
        "value": "base64",
        "displayValue": "Base64"
      }
    ],
    "simpleValueType": true,
    "defaultValue": "hex",
    "enablingConditions": [
      {
        "paramName": "anonymization_method",
        "paramValue": "hash_ip",
        "type": "EQUALS"
      }
    ],
    "help": "Choose the output encoding for the hashed IP address."
  }
]


___SANDBOXED_JS_FOR_SERVER___

const queryPermission = require('queryPermission');
const getEventData = require('getEventData');
const sha256Sync = require('sha256Sync');

// Retrieve parameters
const anonymizationMethod = data.anonymization_method;
const ipSource = data.ip_source;
const staticIp = data.static_ip_address;
const ipVariable = data.ip_address_variable;
const hashEncoding = data.hash_encoding || "hex"; // Default to hex

// Define regex patterns as strings
const ipv4Regex = "^(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$";
const ipv6Regex = "^[a-fA-F0-9:]+$";

// Function to validate IP address
function isValidIP(ip) {
  return ip.match(ipv4Regex) !== null || ip.match(ipv6Regex) !== null;
}

// Get the input IP address
let inputIp;
if (ipSource === "read_from_event_data" && queryPermission("read_event_data", "ip_override")) {
  inputIp = getEventData("ip_override");
} else if (ipSource === "use_variable_value") {
  inputIp = ipVariable;
} else {
  return undefined; // Invalid IP Source
}

// Ensure the input IP is defined
if (!inputIp) {
  return undefined; // Missing IP Address
}

// Strip port numbers if present
if (inputIp.indexOf(":") !== -1) {
  const lastColonIndex = inputIp.lastIndexOf(":");
  if (inputIp.slice(lastColonIndex).match("^:\\d+$")) {
    inputIp = inputIp.slice(0, lastColonIndex); // Remove port number
  }
}

// Check if the input is valid IPv4 or IPv6
const isIPv4 = inputIp.match(ipv4Regex) !== null;
const isIPv6 = inputIp.match(ipv6Regex) !== null;

// Anonymization logic for IPv4
if (isIPv4) {
  if (anonymizationMethod === "last_octet") {
    return inputIp.substring(0, inputIp.lastIndexOf(".")) + ".0";
  } else if (anonymizationMethod === "last_two_octets") {
    const segments = inputIp.split(".");
    return segments[0] + "." + segments[1] + ".0.0";
  } else if (anonymizationMethod === "last_three_octets") {
    const segments = inputIp.split(".");
    return segments[0] + ".0.0.0";
  }
}

// Anonymization logic for IPv6
if (isIPv6) {
  const segments = inputIp.split(":");

  if (anonymizationMethod === "last_three_octets") {
    // Keep the first segments, anonymize the last three hextet
    const keepSegments = segments.slice(0, segments.length - 3);
    return keepSegments.join(":") + "::";
  } else if (anonymizationMethod === "last_two_octets") {
    const keepSegments = segments.slice(0, segments.length - 2);
    return keepSegments.join(":") + "::";
  } else if (anonymizationMethod === "last_octet") {
    // Keep the first segments, anonymize the last hextet
    const keepSegments = segments.slice(0, segments.length - 1);
    return keepSegments.join(":") + "::";
  } else if (anonymizationMethod === "redact_ip") {
    return "::"; // Fully anonymized IPv6
  }
}

// Validate and process static IP
if (anonymizationMethod === "static_ip") {
  return isValidIP(staticIp) ? staticIp : undefined; // Ensure static IP is valid
}

// General anonymization
if (anonymizationMethod === "redact_ip") {
  return "0.0.0.0"; // For both IPv4 and IPv6
} else if (anonymizationMethod === "hash_ip") {
  return sha256Sync(inputIp, { outputEncoding: hashEncoding });
} else {
  return undefined; // Invalid Anonymization Method
}


___SERVER_PERMISSIONS___

[
  {
    "instance": {
      "key": {
        "publicId": "read_event_data",
        "versionId": "1"
      },
      "param": [
        {
          "key": "keyPatterns",
          "value": {
            "type": 2,
            "listItem": [
              {
                "type": 1,
                "string": "ip_override"
              }
            ]
          }
        },
        {
          "key": "eventDataAccess",
          "value": {
            "type": 1,
            "string": "specific"
          }
        }
      ]
    },
    "clientAnnotations": {
      "isEditedByUser": true
    },
    "isRequired": true
  }
]


___TESTS___

scenarios: []


___NOTES___

Created on 12/12/2024, 12:47:25 PM


