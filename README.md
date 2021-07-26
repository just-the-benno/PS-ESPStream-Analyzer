# Powershell-ESPStream-Analyzer

This Powershell scripts uses [Wireshark](https://www.wireshark.org/) to anlyse the ESP streams within .pcap files. 
It outputs the stream ids, source and destionation addresses and packet loss.

```
Source      Destination     SpiAsHex   PacketLoss Total         Percentage
------      -----------     --------   ---------- -----         ----------
z.z.z.z     y.y.y.y         0x2F57E301         68  2264   3,00353356890459
z.z.z.z     y.y.y.y         0xCA7DC6D7          2    71    2,8169014084507
z.z.z.z     y.y.y.y         0x46B43034        197  8036   2,45146839223494
z.z.z.z     y.y.y.y         0xAB6919D6         17 13058  0,130188390258845
y.y.y.y     z.z.z.z         0x38C72309         14 15154 0,0923848488847829
b.b.b.b     z.z.z.z         0x2929C14E          0    30                  0
y.y.y.y     a.a.a.a         0x2A4F883           0    26                  0
z.z.z.z     b.b.b.b         0x8B61EF4C          0    32                  0
y.y.y.y     b.b.b.b         0x1709869           0    11                  0
b.b.b.b     y.y.y.y         0xD090CD31          0    30                  0
```   

## Prerequisite

This scripts runs everywhere where Wireshark and Powershell can be executed. This scripts uses the command line tool (tshark) which is part of the installation of wireshark. 

## ESP Streams

Encapsulating Security Payload (ESP) is one protocal that is used to encapsulate data that is sent over an IPSec tunnel. IPSec tunnel are frequently used for VPN either site-to-site or remote access. The data within an ESP packet is encrypted. However, to do the packet loss analyses, this tool relies on the sequence number and service identifier, which are part of ESP packet header. The payload is never inspected. 

Each stream is identified by a unique Security Parameters Index (SPI). This is the anchor for the analyses. The output will have an item for each found SPI. 

## The analyzing capabilities

This scripts watches only packet loss. Each packet within an ESP stream has a sequence number. This number is increased for each packet. If the scripts detects, that there is a gap, it is considered as packet loss. The amount of lost packets is the difference between the expected and the actual received sequence number

Assume, the stream consits of theses sequence numbers

``
511
512
513
515
520
``

There is a gap between ``513`` and ``515``. One packet is lost. Another gap is between ``515`` and ``520``. Here are 4 packets lost. The total loss are 5 packets. There have been 10 packets in total sent. So, this stream would have a loss ratio of 50%. 

## How to use it

1. Copy the content of the file [esp-anlyser.ps1](/esp-anlyser.ps1) into a new powershell file (.ps1) and name it ``esp-anaylzer.ps1``
The script don't run but provide the Command ``Test-ESPStream`` and hence, it needs to loaded into an existing powerhsell section.
2. Open a new Powershell instance
3. Use the [. (dot sourcing operator)](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-7#dot-sourcing-operator-)  to load the file. If you opened the shell in the same directory as the file created in step 1. 
`` . .\esp-anaylzer.ps1  `` would be the right syntax
4. Run ``Test-ESPStream``

## Parameter

The script has 4 input paramters

### TsharkPath

``-TsharkPath <PathToTshark>`` let you specifiy the path where the script will find the tshark executable. 
The default value is ``C:\Program Files\Wireshark\tshark.exe`` and pointed to the default instllation path for Wireshark under Windows

### Input

``-Input <PathToPcapFiles>`` Let you specify where the .pcap files that should be anaylzed can be found. If nothing is specified the current directionary is used. 

### ErspanId

``-ErspanId <ErspanID>`` let you specifiy that only packets that received via ERSPAN and have a certain ERSPAN-Id should be anaulzed. 
If nothing is spefifeid, no filtering based on ERSPAN occured.

### PrintOutputResult

``PrintOutputResult`` <$true|$false> controls if output should be wirrten to the console. If true the result will be displayed in the console. 
In both cases, the return value of the Command is an error of 

## Output

The output of the script is an array where each element represent an ESP Stream.

An item has the following properties

+ Spi (Id of the stream as unsigned int)
+ SpiAsHex formatted as hex string starting with a 0x
+ PacketLoss: the number of lost packets
+ Total: The total number of packets
+ Percentage: the percentage of lost packets in relation with total
+ Source: the source address for this stream
+ Destination: the destionation address for this stream

