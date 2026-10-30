# SIP Black Belt lab

The lab of the **SIP Black Belt** course on [voip.school](https://voip.school): one Debian 13 box with OpenSIPS 4.0,
rtpengine, SIPp, baresip, sngrep, tcpdump and tshark. Every trace in the course comes from these scripts, and you can
make the same traces yourself.

## Build the box

1. Create a Debian 13 x64 machine (1 vCPU, 1 GB RAM is enough) at any cloud provider that accepts cloud-init
   user data.
2. Edit `cloud-init.yaml`: replace the `ssh-ed25519 AAAA...` line with **your own public key**.
3. Paste the file into the provider's *user data* field and create the machine.
4. Log in as `lab` with your key and check the build:

   ```
   cloud-init status          # status: done
   sudo ufw status            # only 22/tcp
   /usr/sbin/opensips -V      # version: opensips 4.0.x
   ```

The build clones this repository into `/home/lab/lab`. The firewall allows SSH only: the lab's phones and server talk
over documentation addresses (192.0.2.x) on dummy interfaces inside the box, so nothing needs to be open to the internet.

## Run a take

```
cd ~/lab
sudo ./take.sh s1-call            # register two phones, make a call, save captures/s1-call.pcap
sudo python3 pcap_messages.py captures/s1-call.pcap   # writes captures/s1-call.messages.txt: every SIP message as text
```

Each `take-*.sh` script starts OpenSIPS with `opensips/lab.cfg`, captures on the loopback, plays one case with SIPp
scenarios (`scenarios/`) or baresip phones, and leaves nothing running. The header of each script lists its cases:

| Script | Course section |
|---|---|
| `take.sh`, `take-reg.sh`, `take-expires.sh`, `take-badpass*.sh`, `take-wrong*.sh`, `take-authloop*.sh`, `take-location*.sh` | 1. Fundamentals, the lab and registration |
| `take-call.sh`, `take-drop.sh`, `take-route.sh` | 2. Calls, transactions and routing |
| `take-media.sh`, `take-wireshark.sh` (+ `scenarios/load-*.xml`) | 3. SDP, media and Wireshark |
| `take-errors.sh` (+ `sipsend.py`, `requests/`), `take-nat.sh` (+ `nat.sh`) | 4. Errors, extensions, overload and NAT |
| `take-callctl.sh` (baresip + pjsua 2.17), `take-services.sh` (+ SIPp scenarios) | 5. Call control: hold, transfer and services |
| `take-trunks.sh` (+ `opensips/carrier.cfg`, `opensips/verifier.cfg`), `take-qosfax.sh` | 6. Trunks, identity, interconnect, QoS and fax |

Addresses: OpenSIPS (`lab.sip`) 192.0.2.10; phones 2001, 2002, 2003 at 192.0.2.21, .22, .23 (`net.sh`).
Open the pcaps in Wireshark on your laptop, or read them on the box with sngrep and tshark.
