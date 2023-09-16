<h1 align="center">
FalseJeySON
</h1>

<p align="center"> 
  <kbd>
<img src="https://github.com/Bang1338/FalseJeySON/assets/75790567/3f889a33-1257-4f7e-b197-e015c56f0e5e">
  </kbd>
</p>

<h3 align="center">
a JSON protection program, powered by AES-256
</h3>

<p align="center">
  <img src="https://img.shields.io/badge/language:-c++-F34B7D">
  <img src="https://img.shields.io/github/languages/top/Bang1338/FalseJeySON">
  <img src="https://img.shields.io/badge/version-0.1.00-yellow">
</p>

## Why?
* When you're using JSON for some application with base64, hacker/cracker can easily look into the pattern called `ey` and already know this is JSON without even decoding it.

## Requirement:
* Visual Studio 2022
* vcpkg
* [nlohmann/json](github.com/nlohmann/json) - 32bit
* openssl_x86-windows-static

## How to compile?
* Install vcpkg
* Install two of them with:
`vcpkg install nlohmann-json` and `vcpkg install openssl:x86-windows-static`
* Compile them in VS2022

# How to use?
```
Usage: FalseJeySON [-e|-d] -i input.json -o output.json [-k key.fjkey]
-e : Encrypt mode
-d : Decrypt mode
-i : Input
-o : Output (encrypt mode only)
-k : Keyfile (decrypt mode only)
```
Note: Encrypted output and keyfile alway have timestamp to save time when finding them.

* Example for encrypt:
```
FalseJeySON -e -i transright.json -o 4trans.json
{
  "trans":"right"
}
Encryption complete. Encrypted JSON saved to 4trans_15-09-23-21-17-47.json
Key file saved as key_15-09-23-21-17-47.FJKEY
DO NOT LOSE THE KEYFILE
```

* Example for decrypt:
```
FalseJeySON -d -i 4trans_15-09-23-21-17-47.json -k key_15-09-23-21-17-47.FJKEY
{
  "trans":"right"
}
```
Note: To output while decrypt, use `FalseJeySON -d -i 4trans_15-09-23-21-17-47.json -k key_15-09-23-21-17-47.FJKEY > trans-decrypted.json`

## TODO
#### Encrypt:
* Reuse keyfile
* Encrypt compressed
* Encrypt decompressed

#### Decrypt:
* Read last to first on the keyfile
* Return as compressed
* Return as decompressed

#### CMD/all:
* Other mode
```
-org: Stay original data (useful when encrypt not just JSON, just don't be ransomware)
-cm:  Compressed
-dcm: Decompressed
-db:  Debug
```

## Credit
- No one, really :(

## Bonus
![image](https://github.com/Bang1338/FalseJeySON/assets/75790567/23b27322-803d-4228-b4da-0da765f985f0)
