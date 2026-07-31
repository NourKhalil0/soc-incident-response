# Wireshark / TShark Filters for Incident Response

## 1. C2 & Beaconing
- `http.request.method == "POST" and http.content_length > 1000`
- `dns.flags.response == 0 and dns.qry.name.len > 40`

## 2. Lateral Movement
- `smb2.cmd == 1 && ip.dst == 10.0.0.0/8` (SMB file share staging)
- `tcp.port == 3389 and tcp.flags.syn == 1`

## 3. Data Exfiltration
- Large outbound TCP streams: `tcp.len > 1460 and ip.dst != 10.0.0.0/8`
