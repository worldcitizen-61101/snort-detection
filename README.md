# snort-detection
A list of 10 Snort personalised rules.
Just add the following to your '/etc/snort/snort.conf' in the "7) Customize your rule set" step (In Debian, line 578).


# Detection rules by 61101

alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"SSH-"; depth:5; detection_filter: track by_src, count 5, seconds 60; sid:100001;)

alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection Attempt"; flow:to_server,established; content:"SELECT"; nocase; http_uri; content:"UNION"; nocase; http_uri; sid:100002;)

alert udp $HOME_NET any -> any 53 (msg:"DNS Tunneling Detected"; content:"|00 00 FF|"; offset:12; depth:3; sid:100004;)

alert tcp $EXTERNAL_NET any -> $FTP_SERVERS 21 (msg:"FTP Brute Force Attempt"; flow:to_server,established; content:"530 Login incorrect"; sid:100005;)

alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB Reconnaissance Activity"; flow:to_server,established; content:"|FF|SMB"; offset:4; depth:4; sid:100006;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Port Scanning Detected"; flags:S; detection_filter: track by_src, count 5, seconds 60; sid:100008;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Suspicious PowerShell Usage"; flow:to_server,established; content:"powershell"; http_header; sid:100009;)

alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"DNS Zone Transfer Attempt"; flow:to_server; content:"|00 06|"; depth:2; content:"|00 00 10|"; distance:2; within:3; sid:100010;)

alert tcp any any -> $HOME_NET any (msg:"Lateral Movement Attempt"; flow:to_server,established; content:"NET USE"; content:"/USER"; content:"/PASSWORD"; sid:100100;)

alert tcp $HOME_NET any -> any $HTTP_PORTS (msg:"Potential Ransomware C&C Communication"; flow:to_server,established; content:"key_transfer"; content:"encrypted_files"; http_method; sid:100101;)
