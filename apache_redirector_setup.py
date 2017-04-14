#!/bin/python

import sys,os,argparse,subprocess,re #native

help = '''Apache Redirector Setup Script -
Configures a host to perform mod_rewrite redirection based on provided parameters

Parameters:

    --h                         Display's this menu
    --silent                    Prevent all standard output
    --teamserver				IP Address of the teamserver

    --block_url					URL or file to redirect/proxy blocked requests to
    --block_mode				proxy or redirect blocked requests (it's recommended you only proxy to resources you control)\

    --allow_url					URL or file to redirect/proxy allowed requests to
    --allow_mode				proxy or redirect allowed requests (it's recommended you only proxy to resources you control)

    --ip_blacklist				block provided IPs or CIDR ranges. Semicolon separate (ie 1.1.1.1;2.2.2.2/8)
    --ir						block common IR user agents (wget;curl;HTTrack;crawl;google;bot;b\-o\-t;spider;baidu;python)
    --block_ua					block provided user agents

    --mobile_url				URL to redirect mobile users to
    --mobile_mode				proxy or redirect mobile users to URL

    --valid_uris				Semicolon-seperated list of valid URIs, all other requests are blocked

    --malleable 				Cobalt Strike Malleable C2 profile to allow. Blocks all other requests.
    --staging_uri               Uri of the stager being used in cobalt strike

    --backup				 	Backs up current apache2 config and the html folder with the .bak extension.
    
    Order of processing

        1: Malleable C2

        or

        1: IR Blacklisting
        2: IP Blacklisting
        3: UA Blacklisting
        4: URI Blacklisting
        5: Mobile Proxy/Redirect
        6: Allow Clause


Usage Examples:
    Setting up a Malleable C2 Redirector:
        python apache_redirector_setup.py --malleable="<Path to C2 Profile>" --block_url="https://google.com" --block_mode="redirect" --allow_url="Teamserver Address" --allow_mode="proxy"
    
    Setting up a Malleable C2 Redirector w/ Staging:
        python apache_redirector_setup.py --malleable="<Path to C2 Profile" --staging_uri="/updates/" --block_url="https://google.com" --block_mode="redirect" --allow_url="<Teamserver Address>" --allow_mode="proxy" 
    
    Setting up Mobile user redirection:
        python apache_redirector_setup.py --mobile_url="<Mobile Payload>" --teamserver="<IP ADDRESS/DNS NAME>" --mobile_mode=proxy --allow_url="<Teamserver Address>" --allow_mode="proxy"
    
    Setting up IR Blacklisting:
        python apache_redirector_setup.py --ir --block_mode=redirect --block_url="https://google.com" --allow_url="<Teamserver Address>" --allow_mode="proxy"
    
    Setting up IP Blacklisting:
        python apache_redirector_setup.py --ip_blacklist="<IP ADDRESS>" --block_mode="redirect" --block_url="https://google.com" --teamserver="<TEAMSERVER IP/DNS NAME>"

    Setting up Mobile Redirection, IR Blacklisting, and IP Blacklisting:
        python apache_redirector_setup.py --ip_blacklist="<IP ADDRESS>" --ip_blacklist="<IP ADDRESS>" --mobile_url="<Mobile Payload>" --teamserver="<IP ADDRESS/DNS NAME>" --mobile_mode=proxy --allow_url="<Teamserver Address>" --allow_mode="proxy"
'''


redirection_options = {}
green = '\x1b[6;30;42m'
red = '\x1b[2;30;41m'
yellow = '\x1b[0;30;43m'
colorEnd = '\x1b[0m'

#default agent strings
mobile_string = 'android|blackberry|googlebot-mobile|iemobile|ipad|iphone|ipod|opera mobile|palmos|webos'
ir_string = 'wget;curl;HTTrack;crawl;google;bot;b\-o\-t;spider;baidu;python'

def htaccessCheck(silent,server_root="/var/www/"):
    if os.path.isfile((server_root + "html/.htaccess")):
        if not silent:
            print red + "An .htaccess file was found in the "+ server_root +" webroot!  This file will be overwritten with a new ruleset with this tool if you continue!" + colorEnd
            prompt = raw_input(yellow + "Would you like to backup this file before continuing?(Y/N):" + colorEnd + " ")
            if (prompt.lower() == ("y")) or (prompt.lower() == ("yes")):
                backupConfig(silent,server_root)
            elif (prompt.lower() == ("n")) or (prompt.lower() == ("no")):
                print yellow + ".htaccess file removed without saving a backup" + colorEnd
            else:
                print red + "You didn't enter Y or N, so I don't know what you want!  I am going to exit now feel free to try again" + colorEnd
                sys.exit()
        os.remove(server_root + "html/.htaccess")

def backupFile(filename):
    f = open(filename, 'r')
    lines = []
    for line in f:
        lines.append(line)
    f.close()
    out = filename + ".bak"
    o = open(out, 'w')
    for line in lines:
        o.write(line)
    o.close()

def checkSetup(silent,server_root="/var/www/"):
    try:
        if not silent:
            print green + "Checking if Apache Server is Configured Correctly" + colorEnd
        setup = False
        config = open("/etc/apache2/apache2.conf", "r")
        apache2config = config.readlines()
        config.close()
        configLineNumber = 0
        configEditLineNumber = 0
        directory = "<Directory %s>" % server_root
        for lines in apache2config:
            if directory in lines:
                configEditLineNumber = configLineNumber
            configLineNumber += 1
        if "AllowOverride All" in apache2config[configEditLineNumber + 2]:
            setup = True
            if not silent:
                print green + "Mod_rewrite is enabled for the "+ server_root +" webroot" + colorEnd
                print green + "Apache Server Configured Correctly!" + colorEnd +"\n" 
            return setup
        else:
            if not silent:
                print yellow + "Mod_rewrite is not enabled for the "+ server_root +" webroot" + colorEnd
                print yellow + "Configuring the "+ server_root +" for Apache Mod-Rewrite!"
            setup = False
            return setup
    except IOError:
        if not silent:
            print yellow + "Apache2 is not installed,  Installing Apache2 and configuring Mod-Rewrite Now" + colorEnd
        setup = False
        return setup

def backupConfig(silent,server_root="/var/www/"):
    if os.path.isfile("/etc/apache2/apache2.conf"):
        backupFile("/etc/apache2/apache2.conf")
        if not silent:
            print green + "Apache2 Configuration backed up" + colorEnd
    if os.path.isfile((server_root + "html/.htaccess")):
        backupFile((server_root + "html/.htaccess"))
        if not silent:
            print green + ".htaccess file located at " + (server_root + "html/.htaccess") + " has been saved at " + (server_root + "html/.htaccess.bak") + colorEnd

def firstTimeSetup(silent,server_root="/var/www/"):
    subprocess.call(["apt-get","install","apache2","-y","-qq"])
    subprocess.call(["a2enmod", "rewrite", "proxy", "proxy_http"])
    apache2config = open("/etc/apache2/apache2.conf", "r")
    configLineNumber = 0
    configEditLineNumber = 0
    oldconfig = apache2config.readlines()
    directory = "<Directory %s>" % server_root
    for lines in oldconfig:
        if directory in lines:
            configEditLineNumber = configLineNumber
        configLineNumber += 1
    oldconfig[configEditLineNumber + 2] = "\tAllowOverride All\n"
    apache2config.close()
    apache2config = open("/etc/apache2/apache2.conf","w")
    for line in oldconfig:
        apache2config.write(line)
    apache2config.close()
    subprocess.call(["service","apache2","restart"])
    subprocess.call(["service","apache2","status"])
    if not silent:
        print green + "Configuration Complete!" + colorEnd

def mobile_rule(mobile_URL,mobile_mode,server_root="/var/www/"):

    if os.path.isfile((server_root + "html/.htaccess")):
        old = open((server_root + "html/.htaccess"),"r")
        oldRules = []
        for line in old:
            oldRules.append(line)
        old.close()
        rule = '\nRewriteCond %{HTTP_USER_AGENT} "android|blackberry|googlebot-mobile|iemobile|ipad|iphone|ipod|opera mobile|palmos|webos" [NC]\n'

        if mobile_mode == "redirect":
            rule = rule + 'RewriteRule ^.*$ %s [L,R=302]\n' % mobile_URL
        elif mobile_mode == "proxy":
            rule = rule + 'RewriteRule ^.*$ %s [P]\n' % mobile_URL
        ruleFile = open((server_root + "html/.htaccess"), "w")
        for oldRule in oldRules:
            ruleFile.write(oldRule)
        ruleFile.write(rule)
        ruleFile.close()

    else:
        rule = "RewriteEngine On\n"
        rule = rule + 'RewriteCond %{HTTP_USER_AGENT} "android|blackberry|googlebot-mobile|iemobile|ipad|iphone|ipod|opera mobile|palmos|webos" [NC]\n'
        rule = rule + 'RewriteRule ^.*$ %s [P]\n' % mobile_URL
        rule = rule + 'RewriteRule ^.*$ http://' + str(teamserverIP) + '%{REQUEST_URI} [P]'

        ruleFile = open((server_root + "html/.htaccess"), "w")
        ruleFile.write(rule)
        ruleFile.close()

def irSetup(block_url,block_mode,server_root="/var/www/"):
    if os.path.isfile((server_root + "html/.htaccess")):
        old = open((server_root + "html/.htaccess"),"r")
        oldRules = []
        for line in old:
            if "RewriteEngine On" not in line:
                oldRules.append(line)
        old.close()
        rule = "RewriteEngine On\n"
        rule = rule + 'RewriteCond %{HTTP_USER_AGENT} "wget|curl|HTTrack|crawl|google|bot|b\-o\-t|spider|baidu" [NC,OR]\n'
        rule = rule + 'RewriteCond %{HTTP_USER_AGENT} =""\n'
        if block_mode == "redirect":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [L,R=302]\n'
        elif block_mode == "proxy":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [P]\n'
        ruleFile = open((server_root + "html/.htaccess"), "w")
        ruleFile.write(rule)
        for oldRule in oldRules:
            ruleFile.write(oldRule)
        ruleFile.close()
    else:
        rule = "RewriteEngine On\n"
        rule = rule + 'RewriteCond %{HTTP_USER_AGENT} "wget|curl|HTTrack|crawl|google|bot|b\-o\-t|spider|baidu" [NC,OR]\n'
        rule = rule + 'RewriteCond %{HTTP_USER_AGENT} =""\n'
        if block_mode == "redirect":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [L,R=302]\n'
        elif block_mode == "proxy":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [P]\n'
        ruleFile = open((server_root + "html/.htaccess"), "w")
        ruleFile.write(rule)
        ruleFile.close()

def ipBlacklisting(ips,teamserverIP,block_url,block_mode,server_root="/var/www/"):
    if os.path.isfile((server_root + "html/.htaccess")):
        old = open((server_root + "html/.htaccess"),"r")
        oldRules = []
        counter = 0
        for line in old:
            oldRules.append(line)
        old.close()
        for ip in ips:
            if ip == ips[-1]:
                finalIP= ''
                for char in ip:
                    if char == ".":
                        finalIP += "\\."
                    else:
                        finalIP += char
                rule = 'RewriteCond %{REMOTE_ADDR} ^' + finalIP + "\n"
            else:
                finalIP= ''
                for char in ip:
                    if char == ".":
                        finalIP += "\\."
                    else:
                        finalIP += char
                rule = 'RewriteCond %{REMOTE_ADDR} ^' + finalIP + ' [OR]\n'

        if block_mode == "redirect":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [L,R=302]\n'
        elif block_mode == "proxy":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [P]\n'
        ruleFile = open((server_root + "html/.htaccess"), "w")
        for oldRule in oldRules:
            ruleFile.write(oldRule)
        ruleFile.write(rule)
        ruleFile.close()

    else:
        rule = "RewriteEngine On\n"
        for ip in ips:
            if ip == ips[-1]:
                finalIP= ''
                for char in ip:
                    if char == ".":
                        finalIP += "\."
                    else:
                        finalIP += char
                rule = rule + 'RewriteCond %{REMOTE_ADDR} ^' + finalIP + "\n"
            else:
                finalIP= ''
                for char in ip:
                    if char == ".":
                        finalIP += "\."
                    else:
                        finalIP += char
                rule = rule + 'RewriteCond %{REMOTE_ADDR} ^' + finalIP + ' [OR]\n'

        if block_mode == "redirect":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [L,R=302]\n'
        elif block_mode == "proxy":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [P]\n'
        rule = rule + 'RewriteRule ^.*$ http://' + str(teamserverIP) + '%{REQUEST_URI} [P]\n'
        ruleFile = open("/var/www/html/.htaccess", "w")
        ruleFile.write(rule)
        ruleFile.close()

def validURI(uris, block_url, block_mode,server_root='/var/www/'):
    if os.path.isfile((server_root + "html/.htaccess")):
        old = open((server_root + "html/.htaccess"),"r")
        oldRules = []
        finalURI = ''
        for line in old:
            oldRules.append(line)
        old.close()
        if len(uris) == 1:
            finalURI = uris[0]
            rule = 'RewriteCond %{REQUEST_URI} !^' + finalURI + '?$ [NC]\n'
        else:
            for uri in uris:
                if uri == uris[len(uris)-1]:
                    finalURI += uri
                else:
                    finalURI += uri + "|"

            rule = 'RewriteCond %{REQUEST_URI} !^/(' + finalURI + ')/?$ [NC]\n'
        if block_mode == "redirect":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [L,R=302]\n'
        elif block_mode == "proxy":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [P]\n'
        else:
            pass
        ruleFile = open((server_root + "html/.htaccess"), "w")
        for oldRule in oldRules:
            ruleFile.write(oldRule)
        ruleFile.write(rule)
        ruleFile.close()

    else:
        finalURI = ''
        if len(uris) == 1:
            finalURI = uris[0]
        else:
            for uri in uris:
                if uri == uris[len(uris)-1]:
                    finalURI += uri
                else:
                    finalURI += uri + "|"

        rule = "RewriteEngine On\n"
        rule += 'RewriteCond %{REQUEST_URI} !^/(' + finalURI + ')/?$ [NC]'
        if block_mode == "redirect":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [L,R=302]\n'
        elif block_mode == "proxy":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [P]\n'
        else:
            pass
        ruleFile = open((server_root + "html/.htaccess"), "w")
        ruleFile.write(rule)
        ruleFile.close()

def invalidURI(uris, block_url, block_mode,server_root='/var/www/'):
    if os.path.isfile((server_root + "html/.htaccess")):
        old = open((server_root + "html/.htaccess"),"r")
        oldRules = []
        finalURI = ''
        for line in old:
            oldRules.append(line)
        old.close()
        if len(uris) == 1:
            finalURI = uris[0]
            rule = 'RewriteCond %{REQUEST_URI} ^' + finalURI + '?$ [NC]\n'
        else:
            for uri in uris:
                if uri == uris[len(uris)-1]:
                    finalURI += uri
                else:
                    finalURI += uri + "|"

            rule = 'RewriteCond %{REQUEST_URI} ^/(' + finalURI + ')/?$ [NC]\n'
        if block_mode == "redirect":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [L,R=302]\n'
        elif block_mode == "proxy":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [P]\n'
        else:
            pass
        ruleFile = open((server_root + "html/.htaccess"), "w")
        for oldRule in oldRules:
            ruleFile.write(oldRule)
        ruleFile.write(rule)
        ruleFile.close()

    else:
        finalURI = ''
        if len(uris) == 1:
            finalURI = uris[0]
            rule = 'RewriteEngine On\n'
            rule += 'RewriteCond %{REQUEST_URI} ^' + finalURI + '?$ [NC]\n'
        else:
            for uri in uris:
                if uri == uris[len(uris)-1]:
                    finalURI += uri
                else:
                    finalURI += uri + "|"

            rule = "RewriteEngine On\n"
            rule += 'RewriteCond %{REQUEST_URI} ^/(' + finalURI + ')/?$ [NC]'
        if block_mode == "redirect":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [L,R=302]\n'
        elif block_mode == "proxy":
            rule = rule + 'RewriteRule ^.*$ ' + block_url + '/? [P]\n'
        else:
            pass
        ruleFile = open((server_root + "html/.htaccess"), "w")
        ruleFile.write(rule)
        ruleFile.close()


def blockUA(ua, block_url,block_mode,server_root="/var/www/"):
    if os.path.isfile((server_root + "html/.htaccess")):
        old = open((server_root + "html/.htaccess"),"r")
        oldRules = []
        for line in old:
            oldRules.append(line)
        old.close()
        finalUA = re.escape(ua)
        rule = 'RewriteCond %{HTTP_USER_AGENT} ^' + finalUA + ' [NC]\n'
        if block_mode == "redirect":
            rule += 'RewriteRule ^.*$ ' + block_url + '/? [L,R=302]\n'
        elif block_mode == "proxy":
            rule += 'RewriteRule ^.*$ ' + block_url + '/? [P]\n'
        else:
            pass
        ruleFile = open((server_root + "html/.htaccess"), "w")
        for oldRule in oldRules:
            ruleFile.write(oldRule)
        ruleFile.write(rule)
        ruleFile.close()
    else:

        finalUA = re.escape(ua)
        rule = "RewriteEngine On\n"
        rule += 'RewriteCond %{HTTP_USER_AGENT} ^' + finalUA + ' [NC]\n'
        if block_mode == "redirect":
            rule += 'RewriteRule ^.*$ ' + block_url + '/? [L,R=302]\n'
        elif block_mode == "proxy":
            rule += 'RewriteRule ^.*$ ' + block_url + '/? [P]\n'
        else:
            pass
        ruleFile = open((server_root + "html/.htaccess"), "w")
        ruleFile.write(rule)
        ruleFile.close()

def allowUA(ua, block_url,block_mode,server_root="/var/www/"):
    if os.path.isfile((server_root + "html/.htaccess")):
        old = open((server_root + "html/.htaccess"),"r")
        oldRules = []
        for line in old:
            oldRules.append(line)
        old.close()
        if ua == " ":
            rule = 'RewriteCond %{HTTP_USER_AGENT} ^$ [NC]\n'
        else:
            finalUA = re.escape(ua)
            rule = 'RewriteCond %{HTTP_USER_AGENT} !^' + finalUA + ' [NC]\n'
        if block_mode == "redirect":
            rule += 'RewriteRule ^.*$ ' + block_url + '/? [L,R=302]\n'
        elif block_mode == "proxy":
            rule += 'RewriteRule ^.*$ ' + block_url + '/? [P]\n'
        else:
            pass
        ruleFile = open((server_root + "html/.htaccess"), "w")
        for oldRule in oldRules:
            ruleFile.write(oldRule)
        ruleFile.write(rule)
        ruleFile.close()
    else:
        finalUA = re.escape(ua)
        rule = "RewriteEngine On\n"
        rule += 'RewriteCond %{HTTP_USER_AGENT} !^' + finalUA + ' [NC]\n'
        if block_mode == "redirect":
            rule += 'RewriteRule ^.*$ ' + block_url + '/? [L,R=302]\n'
        elif block_mode == "proxy":
            rule += 'RewriteRule ^.*$ ' + block_url + '/? [P]\n'
        else:
            pass
        ruleFile = open((server_root + "html/.htaccess"), "w")
        ruleFile.write(rule)
        ruleFile.close()
def malleableC2(profile, block_url, block_mode,server_root="/var/www/"):
    c2profile = open(profile,'r')
    uris = []
    for line in c2profile:
        if "set uri" in line:
            uri = line[line.index('"')+1:line.index(';')-2]
            uris.append(uri)
        if "set useragent" in line:
            userAgent = line[line.index('"') + 1:line.index('";')]
    c2profile.close()
    allowUA(userAgent,block_url,block_mode,server_root)
    validURI(uris,block_url,block_mode,server_root)

def Staging(profile, block_url, block_mode, allow_url, allow_mode, stagingURI="/updates/",server_root="/var/www/"):
    c2profile = open(profile,'r')
    uris = []
    for line in c2profile:
        if "set uri" in line:
            uri = line[line.index('"')+1:line.index(';')-2]
            uris.append(uri)
        if "set useragent" in line:
            userAgent = line[line.index('"') + 1:line.index('";')]
    c2profile.close()
    stagingURIS = [stagingURI]
    stagingURIS2 = ["/.../"]
    invalidURI(stagingURIS," "," ",server_root)
    allowUA(" "," "," ",server_root)
    allowClause(allow_url,allow_mode)
    invalidURI(stagingURIS2," "," ",server_root)
    blockUA(userAgent," "," ",server_root)
    allowClause(allow_url,allow_mode)
    validURI(uris,block_url,block_mode,server_root)
    allowUA(userAgent,block_url,block_mode,server_root)

def allowClause(allow_url,allow_mode,server_root="/var/www/"):
    if os.path.isfile((server_root + "html/.htaccess")):
        old = open((server_root + "html/.htaccess"),"r")
        oldRules = []
        for line in old:
            oldRules.append(line)
        old.close()
        if allow_mode == "redirect":
            rule = 'RewriteRule ^.*$ ' + allow_url + '%{REQUEST_URI} [L,R=302]\n'
        elif allow_mode == "proxy":
            rule = 'RewriteRule ^.*$ ' + allow_url + '%{REQUEST_URI} [P]\n'
        ruleFile = open((server_root + "html/.htaccess"), "w")
        for oldRule in oldRules:
            ruleFile.write(oldRule)
        ruleFile.write(rule)
        ruleFile.close()
    else:
        print "No rules to allow"

def readRules(silent,server_root="/var/www/"):
    if not silent:
        print (green + ("Here is a print out of the rules written to " + (server_root + "html/.htaccess") + colorEnd))
        rules = open((server_root + "html/.htaccess"),"r")
        for rule in rules:
            print rule.strip("\n")
        print "\n\n"
def processing(redirection_options):
    #Order of processing

    # If Malleable C2 Then it will do it all in that function

    # Else
    # 1: IR Blacklisting
    # 2: IP Blacklisting
    # 3: UA Blacklisting
    # 4: URI Blacklisting
    # 5: Mobile Proxy/Redirect
    # 6: Allow Clause
    #Check if mod_rewrite is enabled
    htaccessCheck(redirection_options['silent'],redirection_options['server_root'])
    setup = checkSetup(redirection_options['silent'],redirection_options['server_root'])
    if setup == False:
        firstTimeSetup(redirection_options['silent'],redirection_options['server_root'])

    if redirection_options['malleable'] != None:
        if (redirection_options['block_url'] != None) and (redirection_options['block_mode'] != None) and (redirection_options['staging_uri'] == None):
            malleableC2(redirection_options['malleable'],redirection_options['block_url'],redirection_options['block_mode'],redirection_options['server_root'])
        elif redirection_options['staging_uri'] != None:
            if (redirection_options['block_url'] != None) and (redirection_options['block_mode'] != None) and (redirection_options['allow_url'] != None) and (redirection_options['allow_mode'] != None):
                Staging(redirection_options['malleable'],redirection_options['block_url'],redirection_options['block_mode'], redirection_options['allow_url'],redirection_options['allow_mode'],redirection_options['staging_uri'], redirection_options['server_root'])
            else:
                print "In order to setup malleable C2 with staging support use the following flags, --malleable --staging_uri --block_url --block_mode --allow_url, --allow_mode"
        else:
            print "In order to use malleable C2, --malleable --block_url and --block_mode must be used"
    
    if redirection_options['ir'] != None:
        if (redirection_options['block_url'] != None) and (redirection_options['block_mode'] != None):
            irSetup(redirection_options['block_url'],redirection_options['block_mode'],redirection_options['server_root'])
        else:
            print "In order to set IR Blocking, --block_url and --block_mode must be used"

    if redirection_options['ip_blacklist'] != None:
        if (redirection_options['block_url'] != None) and (redirection_options['teamserver'] != None) and (redirection_options['block_mode'] != None):
            ipBlacklisting(redirection_options['ip_blacklist'],redirection_options['teamserver'],redirection_options['block_url'],redirection_options['block_mode'],redirection_options['server_root'])
        else:
            print "In order to set IP Blocking, --block_url, --block_mode, --ip_blacklist, and --teamserver must be used"

    if redirection_options['block_ua']!= None:
        if (redirection_options['block_mode'] != None) & (redirection_options['block_url'] != None):
            blockUA(redirection_options['block_ua'],redirection_options['block_url'],redirection_options['block_mode'],redirection_options['server_root'])
        else:
            print "In order to block a specific useragent use, --block_ua, --block_mode and --block_url must be used"
    
    if redirection_options['valid_uris']!= None:
        if (redirection_options['block_url'] != None) & (redirection_options['block_mode'] != None):
            validURI(redirection_options['valid_uris'],redirection_options['block_url'],redirection_options['block_mode'],redirection_options['server_root'])
        else:
            print "In order to set URI whitelisting use, --valid_uris, --block_url and --block_mode must be used"

    if redirection_options['mobile_url']!= None:
        if (redirection_options['mobile_mode'] != None) & (redirection_options['teamserver'] != None):
            mobile_rule(redirection_options['teamserver'],redirection_options['mobile_url'],redirection_options['mobile_mode'],redirection_options['server_root'])
        else:
            print "In order to set mobile redirection use, --mobile_url, --mobile_mode and --teamserver must be used"




    if redirection_options['allow_url']!= None:
        if redirection_options['allow_mode'] !=None:
            allowClause(redirection_options['allow_url'],redirection_options['allow_mode'],redirection_options['server_root'])
        else:
            print "In order to set an allow rule use,  --allow_url, and --allow_mode"
    
    if os.path.isfile((redirection_options['server_root'] + "html/.htaccess")):
        readRules(redirection_options['silent'],redirection_options['server_root'])



if __name__ == '__main__':

    if not os.geteuid() == 0:
        sys.exit('Script must be run as root')

    parser = argparse.ArgumentParser(description='''apache_redirector_setup.py -- configure Apache to perform mod_rewrite redirection based on provided parameters.
        You can use %REQUEST_URI% and %QUERY_STRING% to pass the original request's URI or Query String to the redirected URL.
        Order of processing: block IPs, block IR, block, useragents, mobile redirection, 404, allow others''')
    parser.add_argument('--h',help="prints the help menu",action='store_true')
    parser.add_argument('--silent', help='Prevent all standard output',action='store_true')
    parser.add_argument('--teamserver', help='The IP Address of your teamserver')
    parser.add_argument('--block_url', help='URL or file to redirect/proxy blocked requests to')
    parser.add_argument('--block_mode', help='PROXY or REDIRECT blocked requests (it is recommended you only proxy to resources you control)')
    parser.add_argument('--allow_url', help='URL or file to redirect/proxy allowed requests to')
    parser.add_argument('--allow_mode', help='PROXY or REDIRECT allowed requests (it is recommended you only proxy to resources you control)')
    parser.add_argument('--ip_blacklist', help='block provided IPs or regex ranges. Semicolon separate and escape periods (ie 1.1.1.1;2\.1\..*)')
    parser.add_argument('--ir', help='block common IR user agents (wget;curl;HTTrack;crawl;google;bot;b\-o\-t;spider;baidu)',action='store_true')
    parser.add_argument('--block_ua', help='block provided user agents. supports regex. spaces and special characters [,.\ ()[]$%!^*] must be escaped')
    parser.add_argument('--mobile_url', help='URL or file to redirect mobile users to')
    parser.add_argument('--mobile_mode', help='proxy or redirect mobile users to URL')
    parser.add_argument('--valid_uris', help='Semicolon-seperated list of valid URIs, all other requests are blocked')
    parser.add_argument('--server_root', help='path to the server root (default: /var/www/')
    parser.add_argument('--invalid_uri', help='URL or file to redirect 404 requests to (default: block_url value)')
    parser.add_argument('--malleable', help='path to the Cobalt Strike Malleable C2 profile to allow.')
    parser.add_argument('--staging_uri', help='Uri of the stager being used in cobalt strike')
    parser.add_argument('--backup', help='Backs up current apache2 config and the html folder with the .bak extension.',action='store_true')

    args = parser.parse_args()


    if args.h != None:
        print help
        sys.exit()
    
    if args.silent != None:
        redirection_options['silent'] = args.silent
    else:
        redirection_options['silent'] = False
    
    if args.block_mode != None:
        if args.block_mode.lower() in ['proxy','redirect']:
            redirection_options['block_mode'] = args.block_mode.lower()
        else:
            parser.error('--block_mode must be "proxy" or "redirect"')

    if args.block_url != None:
        redirection_options['block_url'] = args.block_url
    else:
        redirection_options['block_url'] = None

    if args.allow_mode != None:
        if args.allow_mode.lower() in ['proxy','redirect']:
            redirection_options['allow_mode'] = args.allow_mode.lower()
        else:
            parser.error('--allow_mode must be "proxy" or "redirect"')
    else:
        redirection_options['allow_mode'] = None
    if args.allow_url != None:
        redirection_options['allow_url'] = args.allow_url
    else:
        redirection_options['allow_url'] = None

    if args.ip_blacklist != None:
        redirection_options['ip_blacklist'] = args.ip_blacklist.split(';')
    else:
        redirection_options['ip_blacklist'] = None
    if args.ir == True:
        redirection_options['ir'] = 'wget;curl;HTTrack;crawl;google;bot;b\-o\-t;spider;baidu'
    else:
        redirection_options['ir'] = None

    if args.block_ua != None:
        redirection_options['block_ua'] = args.block_ua
    else:
        redirection_options['block_ua'] = None
    
    if args.mobile_mode != None:
        redirection_options['mobile_mode'] = args.mobile_mode
    else:
        redirection_options['mobile_mode'] = None
   
    if args.mobile_url != None:
        redirection_options['mobile_url'] = args.mobile_url
    else:
        redirection_options['mobile_url'] = None

    if args.teamserver != None:
        redirection_options['teamserver'] = args.teamserver
    else:
        redirection_options['teamserver'] = None
    
    if args.valid_uris != None:
        redirection_options['valid_uris'] = args.valid_uris.split(';')
    else:
        redirection_options['valid_uris'] = None
   
    if args.server_root != None:
        redirection_options['server_root'] = args.server_root
    else:
        redirection_options['server_root'] = "/var/www/"
    
    if args.invalid_uri != None:
        redirection_options['invalid_uri'] = args.invalid_uri
    else:
        redirection_options['invalid_uri'] = None
   
    if args.malleable != None:
        redirection_options['malleable'] = args.malleable
    else:
        redirection_options['malleable'] = None

    if args.staging_uri != None:
        redirection_options['staging_uri'] = args.staging_uri
    else:
        redirection_options['staging_uri'] = None

    if args.backup == True:
        backupConfig(redirection_options['silent'],redirection_options['server_root'])

    processing(redirection_options)
