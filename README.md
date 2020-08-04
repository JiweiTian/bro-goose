# GOOSE Traffic Analysis and Attack Detection
### Setup

1. Download and extract Bro source code, [version 2.5.4](https://download.zeek.org/)
2. Apply the patch `bro/goose_analyzer_patch.txt`
   1. Note: this patch is based on the GOOSE analyzer proposed in [1] and its [codebase](https://github.com/zeek/zeek/pull/76/files).
3. [Install](https://docs.zeek.org/en/current/install/install.html) Bro from source
4. [Configure](https://docs.zeek.org/en/current/quickstart/index.html) Bro
5. Copy `scripts/*` to directory `/usr/local/bro/share/bro/site`
6. Run Bro with the above script and some input traffic (included in `traces` directory). Two modes are supported:
   1. Direct input: `bro -r <input trace> /usr/local/bro/share/bro/site/process-goose.bro > tmp.txt`
   2. Live traffic:
      1. Deploy Bro: `sudo /usr/local/bro/bin/broctl` and then at BroControl CLI: `deploy`
      2. In another terminal window, replay an exiting trace file to the interface monitored by Bro (configured in step 4): `sudo tcpreplay -i <interface> <input trace>`
      3. Analyze logs (step 7)
      4. Stop Bro: BroControl CLI: `stop`
7. In either case, the output will consist of several Bro logs. The logs of our interest are `goose.log`, `goose_stats.log`, and if any attacks detected, `notice.log`. For direct input case, the logs are written to the directry from which Bro was run. For live traffic option, the logs are written to `/usr/local/bro/logs/current/`



### References

* [1] M. Kabir-Querrec, “Cyber security of smart-grid control systems: Intrusion detection in IEC 61850 communication networks,” Ph.D. dissertation, Universite Grenoble Alpes, 2017. [Online]. Available: https://tel.archives-ouvertes.fr/tel-01609230v2