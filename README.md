
# ADFSpray

ADFSpray is a python3 tool to perform password spray attack against Microsoft ADFS.
ALWAYS VERIFY THE LOCKOUT POLICY TO PREVENT LOCKING USERS.


## How to use it
First, install the needed dependencies:
```
pip3 install -r requirements.txt
```
Run the tool with the needed flags:
```
python3 ADFSpray.py -u [USERNAME] -p [PASSWORD] -t [TARGET URL] [METHOD] -x [PROXY] -V [VERBOSE]
```

## Options to consider
* adfs|autodiscover|basicauth
  * the method of authentication to use, autodiscover uses NTLM, adfs is MicrosoftForm and basic auth is well...basic authentication
  * suggested targets:
    * NTLM - https://autodiscover.[COMPANY].com/autodiscover/autodiscover.xml
	* basicauth - https://reports.office365.com/ecp/reportingwebservice/reporting.svc
	* adfs - https://[SSO-SUBDOMAIN].[COMPANY].com (without /adfs/ls/)
* -p\\-P
  * single password or file with passwords (one each line)
* -t\\-T
  * single target or file with targets (one each line)
* -u\\-U
  * single username or file with usernames (one each line)  
* -o
  * output file name (csv)
* -s
  * throttling time (in seconds) between attempts
* -r
  * random throttling time between attempts (based on user input for min and max values)
* -d
  * (Optional) Domain to prepend to usernames (e.g., -d CONTOSO).
* -x
  * (Optional) Proxy URL for interception (e.g., -x http://127.0.0.1:8080).

## Key Enhancements in this Version
- **Proxy Support (`-x`):** Seamless integration with Burp Suite or other intercepting proxies.
- **Domain Prepending (`-d`):** Automatically prepends domains (e.g., `DOMAIN\user`) as required by many ADFS configurations.
- **Stealth Timing (`-r`):** Randomized delays between attempts to evade basic pattern-based detection.
- **Advanced Logging:** 
    - Color-coded console output: **Green** for success, **Blue** for failed attempts (in verbose mode).
    - Persistent Success Log: Successful logins are automatically recorded with timestamps in `[output]_success.log`.

## Output Files

- [output].csv: Structured data for reporting.
- [output]_success.log: A human-readable log with timestamps of every successful login.

### Credit
Inspired by:
  * https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py
  * https://github.com/Mr-Un1k0d3r/RedTeamScripts/raw/master/password-spray.py
  * https://danielchronlund.com/2020/03/17/azure-ad-password-spray-attacks-with-powershell-and-how-to-defend-your-tenant/

### Issues, bugs and other code-issues
Yeah, I know, this code isn't the best. I'm fine with it as I'm not a developer and this is part of my learning process.
If there is an option to do some of it better, please, let me know.

_Not how many, but where._
