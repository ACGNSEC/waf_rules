log4j-scan：
https://github.com/fullhunt/log4j-scan

规则说明：  
正常jdni流量只包含rmi://和ldap://。  
恶意流量通过规则拦截：  
  ${jndi:ldap://  
  ${jndi:rmi://  
可能出现在各种请求任何地方，query/header/post body  
规则上线先开启log记录模式，观察日志是否有业务正常的流量匹配到该规则，以误拦截正常请求。  
如果有误拦截情况，可以针对业务域名粒度的特征，不匹配该规则。  

crs规则:

This is a stricter sibling of rule 932130.  
It applies the same regular expression to the  
User-Agent and Referer HTTP headers.  
Unlike the sibling rule, this rule runs in phase 1.  

SecRule REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer "@rx (?:\$(?:\((?:\(.*\)|.*)\)|\{.*})|[<>]\(.*\))" \  
    "id:932131,\  
    phase:1,\  
    block,\  
    capture,\  
    t:none,t:cmdLine,\  
    msg:'Remote Command Execution: Unix Shell Expression Found',\  
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\  
    tag:'application-multi',\  
    tag:'language-shell',\  
    tag:'platform-unix',\  
    tag:'attack-rce',\  
    tag:'paranoia-level/2',\  
    tag:'OWASP_CRS',\  
    tag:'capec/1000/152/248/88',\  
    tag:'PCI/6.5.2',\  
    ctl:auditLogParts=+E,\  
    ver:'OWASP_CRS/3.4.0-dev',\  
    severity:'CRITICAL',\  
    setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',\  
    setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'"  


SecRule REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer "@rx (?:\$(?:\((?:\(.*\)|.*)\)|\{.*})|[<>]\(.*\))" \  
    "id:932131,\  
    phase:1,\  
    block,\  
    capture,\  
    t:none,t:cmdLine,\  
    msg:'Remote Command Execution: Unix Shell Expression Found',\  
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\  
    tag:'application-multi',\  
    tag:'language-shell',\  
    tag:'platform-unix',\  
    tag:'attack-rce',\  
    tag:'paranoia-level/2',\  
    tag:'OWASP_CRS',\  
    tag:'capec/1000/152/248/88',\  
    tag:'PCI/6.5.2',\  
    ctl:auditLogParts=+E,\  
    ver:'OWASP_CRS/3.4.0-dev',\  
    severity:'CRITICAL',\  
    setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',\  
    setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'"  

Log4J / Log4Shell Defense  
This addresses exploits against the Log4J library described in several CVEs:  
* CVE-2021-44228  
* CVE-2021-44832  
* CVE-2021-45046  
* CVE-2021-45105  
See https://coreruleset.org/20211213/crs-and-log4j-log4shell-cve-2021-44228/    
Rule attempts to detect two things:  
* Nested use of ${  
* use of ${jndi:... without the closing bracket  
Rule 932130 is also essential for defense since there are certain  
bypasses of the log4j rules that can be caught by 932130.  
The payload is not displayed in the alert message since log4j could  
potentially be executed on the logviewer.  
This rule has a stricter sibling: 944141 (PL3)  

SecRule REQUEST_LINE|ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|XML:/*|XML://@* "@rx (?:\${[^}]{0,15}\${|\${(?:jndi|ctx))" \  
    "id:944140,\  
    phase:2,\  
    block,\  
    t:none,t: urlDecodeUni,t:cmdLine,\  
    log,\  
    msg:'Potential Remote Command Execution: Log4j / Log4shell', \  
    tag:'application-multi',\  
    tag:'language-java',\  
    tag:'platform-multi',\  
    tag:'attack-rce',\  
    tag:'OWASP_CRS',\  
    tag:'capec/1000/152/137/6',\  
    tag:'PCI/6.5.2',\  
    tag:'paranoia-level/1',\  
    ver:'OWASP_CRS/3.4.0-dev',\  
    severity:'CRITICAL',\  
    setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',\  
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"  

This is a stricter sibling of 944140.  
It is a re-iteration of said rule without the curly bracket distance limiter  
between the nested "${". This is prone to backtracking and therefore a potential  
DoS problem, but it also avoids evasions that fill the space between the nested  
elements with arbitrary data.  

SecRule REQUEST_LINE|ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|XML:/*|XML://@* "@rx (?:\${[^}]*\${|\${(?:jndi|ctx))" \  
    "id:944141,\  
    phase:2,\  
    block,\  
    t:none,t:urlDecodeUni,t:cmdLine,\  
    log,\  
    msg:'Potential Remote Command Execution: Log4j / Log4shell', \  
    tag:'application-multi',\  
    tag:'language-java',\  
    tag:'platform-multi',\  
    tag:'attack-rce',\  
    tag:'OWASP_CRS',\  
    tag:'capec/1000/152/137/6',\  
    tag:'PCI/6.5.2',\  
    tag:'paranoia-level/3',\  
    ver:'OWASP_CRS/3.4.0-dev',\  
    severity:'CRITICAL',\  
    setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',\  
    setvar:'tx.anomaly_score_pl3=+%{tx.critical_anomaly_score}'"  
