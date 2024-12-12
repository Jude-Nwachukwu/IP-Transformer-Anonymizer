# IP Transformer/Anonymizer by DumbData.co

**IP Transformer/Anonymizer** is a custom server-side Google Tag Manager (sGTM) variable template designed to transform or anonymize IP addresses with flexibility and security.

## Features

- Anonymize IPv4 and IPv6 addresses by:
  - Removing the last octet/hex.
  - Removing the last two or three octets/hexets.
  - Redacting the full IP address (e.g., `0.0.0.0`).
  - Replacing with a static IP address (customizable).
- Hash IP addresses using SHA-256 with selectable output encoding:
  - `hex`
  - `base64`

## Installation

1. Download the `template.tpl` file from this repository.
2. Navigate to your sGTM container.
3. Go to **Templates** > **Variable Templates** > **Import Template**.
4. Upload the `template.tpl` file.
5. Configure the variable according to your requirements.

## Usage

1. Add the variable to your tag configuration in the sGTM container.
2. Select the desired anonymization method or hashing preferences.
3. Save and publish your container.

## License

This project is licensed under the MIT License. See the [LICENSE](License.txt) file for details.
