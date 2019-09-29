# Pointer
A tool to massively analyze malware samples with the aid of VirusTotal.

Part of my master's thesis found here:
http://dione.lib.unipi.gr/xmlui/handle/unipi/11878

The tool was developped to facilitate and automate the process of analyzing massive collections of malware samples using the VirusTotal free API service.

The tool automatically uploads files on VirusTotal from a directory and polls for results. Once all results are fetched the tool will generate a report with the results and aggregate the information into some intresting graphs.

![image](https://user-images.githubusercontent.com/24633258/65831495-d82ef680-e2c2-11e9-95b5-2f29b0109f76.png)

## Example Execution

```
python pointer.py -p virustotal -s gitstore -vtkey 1111111111111111111111111111111111111111111111111111111111111111
 -vtdir malware-samples\2019-08-Trickbot -vtfmt txt
```
![image](https://user-images.githubusercontent.com/24633258/65831658-d82ff600-e2c4-11e9-8414-f766ed16967d.png)

##Example Report

![image](https://user-images.githubusercontent.com/24633258/65831700-66a47780-e2c5-11e9-9c5e-4aa9a979570c.png)

![image](https://user-images.githubusercontent.com/24633258/65831704-8176ec00-e2c5-11e9-999e-9086ea42bbec.png)

![image](https://user-images.githubusercontent.com/24633258/65831708-9b183380-e2c5-11e9-9e6e-2e6b610b34d1.png)

![image](https://user-images.githubusercontent.com/24633258/65831716-ba16c580-e2c5-11e9-8211-1f661ef0bc85.png)

## Generating a VirusTotal API key

Instructions to generate your API key can be found here:

https://developers.virustotal.com/reference#getting-started
