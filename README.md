<div align="center" style="display:grid;place-items:center;">
<p>
    <img src="https://github.com/ANDRVV/gapcast/blob/main/images/gapcast-t.png?raw=true" alt="Gapcast logo">
</p>
    
[Ask me](mailto:vaccaro.andrea45@gmail.com) | [Wiki](https://github.com/ANDRVV/gapcast/wiki) | [Features](https://github.com/ANDRVV/gapcast#features)

<p align="center"><strong>Gapcast</strong> is an IEEE 802.11 packet injection and analyzer software 📡</p>
<p align="center">Use it with <a href="https://github.com/ANDRVV/gapcast/wiki#-radar">RadarRSSI</a>!</p>

<div align="center" style="display:grid;place-items:center;">

[![Go](https://github.com/ANDRVV/gapcast/actions/workflows/go.yml/badge.svg)](https://github.com/ANDRVV/gapcast/actions/workflows/go.yml) [![CodeQL](https://github.com/ANDRVV/gapcast/actions/workflows/codeql.yml/badge.svg)](https://github.com/ANDRVV/gapcast/actions/workflows/codeql.yml) [![Codacy Security Scan](https://github.com/ANDRVV/gapcast/actions/workflows/codacy.yml/badge.svg)](https://github.com/ANDRVV/gapcast/actions/workflows/codacy.yml)
</div>
<h1 align="center">How to run Gapcast</h1>
<p><strong>Requirements</strong></p>
<p><code><a href="https://github.com/golang/go">Go</a> 1.21.1+</code></p>
<p><code><a href="https://github.com/aircrack-ng/aircrack-ng">Aircrack-ng</a> (Airmon-ng) only for <strong>GNU/Linux</strong></code></p>
<p><code><a href="https://github.com/nmap/npcap">Npcap</a> (Wlanhelper) only for <strong>Windows 8.1+</strong></code></p>
</div>

<p align="center">For <strong>GNU/Linux</strong></p>

```bash
git clone https://github.com/ANDRVV/gapcast.git
cd gapcast
go build -buildvcs=false
./gapcast -i <interface>
```
<p align="center">For <strong>Windows 8.1+</strong></p>

```bash
git clone https://github.com/ANDRVV/gapcast.git
cd gapcast
go build
gapcast.exe -i <interface>
```
![](https://github.com/ANDRVV/gapcast/blob/main/images/gapcast-scan.png?raw=true)

<h1 align="center">Injection Table</h1>

<a align="right" href="https://github.com/ANDRVV/gapcast/wiki/Injection-Table"><img src="https://github.com/ANDRVV/gapcast/blob/main/images/injtype-selection.png?raw=true" alt="Table Injection Example" align="right" width="475"></a>
<p align="left">The Injection table is a table where you can insert data and perform an injection even <i>without specifying the channel or BSSID</i>. For more info <a href="https://github.com/ANDRVV/gapcast/wiki/Injection-Table">click here</a>.</p>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>

<h1 align="center">Parameter techniques</h1>
<h3>Usage</h3>

<p>Check out the <a href="https://github.com/ANDRVV/gapcast/wiki">wiki</a>!</p>

<h3>Single deep scanning</h3>

```bash
./gapcast -i <iface> -sc 03:e9:58:65:2a:86 -2.4+5g
```
> **Note**
> With the `-sc <mac>` parameter scans the target in depth, using this method however discards all the other parameters, except for `-i <iface>` and the band selection such as `-5g` or `-2.4+5g`.

<div align="center" style="display:grid;place-items:center;"> 
    <p>
        <a href="https://github.com/ANDRVV/gapcast/wiki/Single-deep-scanning"><img src="https://github.com/ANDRVV/gapcast/blob/main/images/sc.png?raw=true" alt="Single deep scanning output example"></a>
    </p>
</div>

<h3>SCAN-ALL-FOR-LONG-TIME</h3>

```bash
./gapcast -i <iface> -2.4+5g -d
```
> **Note**
> Scans all 2.4/5 Ghz channels disabling shifting of inactive devices.

<h3>SCAN-ALL-FREQ-OF-ONE-AP</h3>

```bash
./gapcast -i <iface> -2.4+5g -c 10,36 -p 03:e9:58:65:2a:8
```
> **Note**
> *Access Point* that have 5 Ghz and 2.4 Ghz transmit via 2 different addresses, the address for 5 Ghz and the one for 2.4 Ghz. In most cases these 2 addresses have a Mac address with a very similar prefix:
> 
> In this case of selecting channel 10 for 2.4 Ghz and channel 36 for 5 Ghz with ```-c <channel>``` uses 2 channels with different bands, using ```-2.4+5g```. Taking into consideration an *Access Point* that has the 5 Ghz address *03:e9:58:65:2a:8e* and the 2.4 Ghz address *03:e9:58:65:2a:86*, the **common prefix** is *03:e9:58:65:2a:8*, which is set via ```-p <mac-prefix>```.
> With this parameter **only devices with that specified prefix will be displayed**.

<h3>SCAN-ALL-RANGE</h3>

```bash
./gapcast -i <iface> -2.4+5g -radar
```
> **Note**
>
> Scan all 2.4/5 Ghz channels showing the approximate radius of the location in meters with the ```-radar``` parameter using the [RadarRSSI library](https://github.com/ANDRVV/RadarRSSI), [more info](https://github.com/ANDRVV/gapcast/wiki#-radar).

<h3>SCAN-2.4G</h3>

```bash
./gapcast -i <iface>
```
> **Note**
> Scans all 2.4 channels.

<h3>SCAN-5G</h3>

```bash
./gapcast -i <iface> -5g
```
> **Note**
> Scans all 5 Ghz channels adding ```-5g``` parameter.

<h3>SCAN-ALL-RECORDING</h3>

```bash
./gapcast -i <iface> -2.4+5g -w out.pcap
```
> **Note**
> Scans all 2.4/5 Ghz channels, recording it and saving to a pcap file. Registration can be done by adding the ```-w <file>.pcap``` parameter.

<h3>SCAN-AP-DEAUTH-AND-REC-EAPOL</h3>

```bash
./gapcast -i <iface> -c 11 -b a3:65:1b:56:7e:3c -w out.pcap
```
> **Note**
> Scan only channel 11 to get the best WPA 4-Way Handshake, To deauthenticate you need to open the gapcast injection table by pressing **[CTRL-P]**, then select the De-Auth type, enter the required information and start the attack by pressing **CTRL-D** key for a few seconds (check that clients are present via the light-blue bar), as soon as the **CTRL-D** key is deactivated, the clients that reconnect to the *Access Point*:
> 
> Will **send and receive EAPOL packets** which you will record and save with the ```-w <file>.pcap``` parameter.

<h3>RESTORE-DATA</h3>

```bash
./gapcast -l out.pcap
```
> **Note**
> If you want to restore data from a previous scan, done with [gapcast](https://github.com/ANDRVV/gapcast), [wireshark](https://github.com/wireshark/wireshark) or other tools and load them on the [gapcast](https://github.com/ANDRVV/gapcast) table to better analyze the data, just insert the ```-l <file>.pcap``` parameter, if you want to restore the data and continue the scan you must add the ```-i <iface>``` parameter and/or add other additional parameters.

<h3>SCAN-ALL-AP</h3>

```bash
./gapcast -i <iface> -2.4+5g -beacon 
```
> **Note**
> If you want to show or record only the *Access Points* you must enter the ```-beacon``` parameter. For this technique, where we show all *Access Points* of all channels it is necessary to add the parameter ```-2.4+5g```.

<p align="center">Obviously there are many other techniques, happy hacking!</p>

<h1 align="center">Monitor mode handler</h1>

<p>For each driver there is a correct <strong>sequence of commands to start the network card correctly in monitor mode</strong>. <strong>Drivers supported by gapcast can also have a txpower modification, bug fixing etc</strong>, as in the case of the RTL8812AU chipset which can be increased to a txpower of 30 dBm. If the driver is not supported, it will start monitor mode directly with Airmon-ng.</p>
<p>Supported drivers:</p>
<ul>
    <li><code>RTL88XXAU</code> mon+txpower</li>
    <li><code>R8187</code> mon+bugfix</li>
    <li><code>RTL8812CU</code> mon</li>
    <li><code>RTL8821CU</code> mon</li>
</ul>

> **Note**
> If your driver is not supported or if you would like to boot into monitor mode with your changes, just do so before starting gapcast. **If gapcast recognizes that the interface has already set monitor mode, it will not make any changes or even try to restart monitor mode**.

> **Warning**
> This function is only available for GNU/Linux systems.

<h1 align="center">Future features</h1>
<ul>
<li>Customizable dBi & dBm for radar + new command that get the localization info</li>
</ul>
