# alive-ip-finder
this tool can fin all ips  alive in range without ips and ids  catch you  can bypass most  waf 


# as redteam or penetration tatser after  do information gathring and osint and find range of ips here the tools can help you to find all alive ips in company wihout get detect and block by IDS or IPS:

Usage Examples:
1_put all the ip/range in file  --> ip-range.txt
ex ::
182.xx.xx.x/24
167.xx.xx.x/20
...
...

 Basic usage
$python3 Adv-redteam-ip-scanner.py -f ip-range.txt -o alive-ips.txt

 With more threads and verbose output
$python3 Adv-redteam-ip-scanner.py -f ip-range.txt -o alive-ips.txt -t 100 -v

 Faster scan with less evasion
$python3 Adv-redteam-ip-scanner.py -f ip-range.txt -o alive-ips.txt --no-jitter -x 1

Conservative scan with maximum evasion
$python3 Adv-redteam-ip-scanner.py -f ip-range.txt -o alive-ips.txt -t 20 -x 3 -v

