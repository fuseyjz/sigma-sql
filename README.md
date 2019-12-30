# sigma-sql
Documentation for usage of Sigma SQL format

https://github.com/Neo23x0/sigma

PR: https://github.com/Neo23x0/sigma/pull/573

This is applicable if you have any system that uses SQL and wish to apply rules on it for filtering.

## Note:
* Aggregations not implemented for this backend.
* This is still a beta and will continue to contribute to this parser when there are more use-cases that required additional formatting.
* The converted output should be piped to the `WHERE` condition.

## Examples:

1) Sigma rule with multiple `OR` conditions with asterisk `*`

```
title: Rundll32 Internet Connection
status: experimental
description: Detects a rundll32 that communicates with public IP addresses
references:
    - https://www.hybrid-analysis.com/sample/759fb4c0091a78c5ee035715afe3084686a8493f39014aea72dae36869de9ff6?environmentId=100
author: Florian Roth
date: 2017/11/04
tags:
    - attack.t1085
    - attack.defense_evasion
    - attack.execution
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        Image: '*\rundll32.exe'
    filter:
        DestinationIp: 
            - '10.*'
            - '192.168.*'
            - '172.16.*'
            - '172.17.*'
            - '172.18.*'
            - '172.19.*'
            - '172.20.*'
            - '172.21.*'
            - '172.22.*'
            - '172.23.*'
            - '172.24.*'
            - '172.25.*'
            - '172.26.*'
            - '172.27.*'
            - '172.28.*'
            - '172.29.*'
            - '172.30.*'
            - '172.31.*'
            - '127.*'
    condition: selection and not filter
falsepositives:
    - Communication to other corporate systems that use IP addresses from public address spaces
level: medium
```

✗ ./sigma/converter/tools/sigmac -t sql sigma/rules/windows/sysmon/sysmon_rundll32_net_connections.yml
```
((EventID = "3" AND Image LIKE "%\rundll32.exe") AND NOT ((DestinationIp LIKE "10.%" OR DestinationIp LIKE "192.168.%" OR DestinationIp LIKE "172.16.%" OR DestinationIp LIKE "172.17.%" OR DestinationIp LIKE "172.18.%" OR DestinationIp LIKE "172.19.%" OR DestinationIp LIKE "172.20.%" OR DestinationIp LIKE "172.21.%" OR DestinationIp LIKE "172.22.%" OR DestinationIp LIKE "172.23.%" OR DestinationIp LIKE "172.24.%" OR DestinationIp LIKE "172.25.%" OR DestinationIp LIKE "172.26.%" OR DestinationIp LIKE "172.27.%" OR DestinationIp LIKE "172.28.%" OR DestinationIp LIKE "172.29.%" OR DestinationIp LIKE "172.30.%" OR DestinationIp LIKE "172.31.%" OR DestinationIp LIKE "127.%")))
```

Formatting into SQL:
```
SELECT * FROM tempTable WHERE
((EventID = "3" AND Image LIKE "%\rundll32.exe") AND NOT ((DestinationIp LIKE "10.%" OR DestinationIp LIKE "192.168.%" OR DestinationIp LIKE "172.16.%" OR DestinationIp LIKE "172.17.%" OR DestinationIp LIKE "172.18.%" OR DestinationIp LIKE "172.19.%" OR DestinationIp LIKE "172.20.%" OR DestinationIp LIKE "172.21.%" OR DestinationIp LIKE "172.22.%" OR DestinationIp LIKE "172.23.%" OR DestinationIp LIKE "172.24.%" OR DestinationIp LIKE "172.25.%" OR DestinationIp LIKE "172.26.%" OR DestinationIp LIKE "172.27.%" OR DestinationIp LIKE "172.28.%" OR DestinationIp LIKE "172.29.%" OR DestinationIp LIKE "172.30.%" OR DestinationIp LIKE "172.31.%" OR DestinationIp LIKE "127.%")))
```

2) Sigma rule with multiple `OR` conditions without asterisk `*`
```
title: Security Support Provider (SSP) added to LSA configuration
status: experimental
description: Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows. 
references:
    - https://attack.mitre.org/techniques/T1101/
    - https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/
tags:
    - attack.persistence
    - attack.t1011
author: iwillkeepwatch
date: 2019/01/18
logsource:
    product: windows
    service: sysmon
detection:
    selection_registry:
        EventID: 13
        TargetObject: 
            - 'HKLM\System\CurrentControlSet\Control\Lsa\Security Packages'
            - 'HKLM\System\CurrentControlSet\Control\Lsa\OSConfig\Security Packages'
    exclusion_images:
        - Image: C:\Windows\system32\msiexec.exe
        - Image: C:\Windows\syswow64\MsiExec.exe
    condition: selection_registry and not exclusion_images
falsepositives:
    - Unlikely
level: critical
```

✗ ./sigma/converter/tools/sigmac -t sql sigma/rules/windows/sysmon/sysmon_ssp_added_lsa_config.yml
```
((EventID = "13" AND TargetObject IN ("HKLM\System\CurrentControlSet\Control\Lsa\Security Packages", "HKLM\System\CurrentControlSet\Control\Lsa\OSConfig\Security Packages")) AND NOT (Image = "C:\Windows\system32\msiexec.exe" OR Image = "C:\Windows\syswow64\MsiExec.exe"))
```

Formatting into SQL:
```
SELECT * FROM tempTable WHERE
((EventID = "13" AND TargetObject IN ("HKLM\System\CurrentControlSet\Control\Lsa\Security Packages", "HKLM\System\CurrentControlSet\Control\Lsa\OSConfig\Security Packages")) AND NOT (Image = "C:\Windows\system32\msiexec.exe" OR Image = "C:\Windows\syswow64\MsiExec.exe"))
```

Notice that, with asterisk `*`; we are making use of `LIKE` condition and replacing all asterisk `*` with percentage `%` sign.

When there are no asterisk `*` in the Sigma rule, we can group them into the `IN` condition.

3) Sigma rule with a condition of counting the length of a value
```
title: opendns_long_TXT
description: Detects very long TXT records in DNS logs.
author: Jayden Zheng
logsource:
  product: opendns
  service: dns
detection:
    selection:
        query_type: "TXT"
        LENGTH(domain): "> 50"
    filter1:
        domain:
          - '*.sophosxl.net'
          - '*.googleapis.com'
    condition: 
        - selection and not filter1
level: high
```

✗ ./sigma/converter/tools/sigmac -t sql sigma/rules/openDNS/opendns_long_TXT.yaml
```
((query_type = "TXT" AND (LENGTH(domain) > 50)) AND NOT ((domain LIKE "%.sophosxl.net" OR domain LIKE "%.googleapis.com")))
```

Formatting into SQL:
```
SELECT * FROM tempTable WHERE
((query_type = "TXT" AND (LENGTH(domain) > 50)) AND NOT ((domain LIKE "%.sophosxl.net" OR domain LIKE "%.googleapis.com")))
```



