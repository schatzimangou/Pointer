# Pointer
A tool to massively analyze malware samples with the aid of VirusTotal.

Part of my master's thesis found here:
http://dione.lib.unipi.gr/xmlui/handle/unipi/11878

The tool was developped to facilitate and automate the process of analyzing massive collections of malware samples using the VirusTotal free API service.

![image](https://user-images.githubusercontent.com/24633258/65831495-d82ef680-e2c2-11e9-95b5-2f29b0109f76.png)

## Example

```
python pointer.py -p virustotal -s gitstore -vtkey 1111111111111111111111111111111111111111111111111111111111111111
 -vtdir malware-samples\2019-08-Trickbot -vtfmt txt
```

![image](https://user-images.githubusercontent.com/24633258/65831646-a4ed6700-e2c4-11e9-98c3-2aad9bf341db.png)


## Generating a VirusTotal API key

Instructions to generate your API key can be found here:

https://developers.virustotal.com/reference#getting-started
