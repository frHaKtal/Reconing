#!/bin/bash




while getopts ":d:" input;do
        case "$input" in
                d) domain=${OPTARG}
                        ;;
                esac
        done
if [ -z "$domain" ]
        then
                echo "Please give a domain like \"-d domain.com or www.domain.com (for 1 domain)\"" | lolcat
                exit 1
fi


echo " "
echo "
  ____  _____ ____ ___  _   _ ___ _   _  ____ 
 |  _ \| ____/ ___/ _ \| \ | |_ _| \ | |/ ___|
 | |_) |  _|| |  | | | |  \| || ||  \| | |  _ 
 |  _ <| |__| |__| |_| | |\  || || |\  | |_| |
 |_| \_\_____\____\___/|_| \_|___|_| \_|\____|" | lolcat
echo "                                 by _frHaKtal_" | lolcat
echo " "
mkdir results/$domain

#echo "Some Text" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols)


domain_enum(){
echo "- Domain Enumeration -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
echo ". with subfinder ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
subfinder -all -d $domain -o results/$domain/domain_list.txt
echo ". with assetfinder ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
assetfinder --subs-only $domain | tee -a results/$domain/domain_list.txt
###
echo ". with amass passive mode ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
amass enum -passive -d $domain | tee -a results/$domain/domain_list.txt
echo ". with amass active mode ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
amass enum -active -d $domain -ip | tee -a results/$domain/domain_ips.txt
echo "- Domain Enumeration Ending -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
cat results/$domain/domain_ips.txt | awk '{print $1}' | tee -a results/$domain/domain_list.txt
cat results/$domain/domain_list.txt | sort -u | tee -a results/$domain/all.txt
echo "- Alive subdomain test -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
cat results/$domain/all.txt | httprobe -t 3000 | tee -a results/$domain/domain_alive2.txt
cat results/$domain/domain_alive2.txt | sort -u | tee -a results/$domain/domain_alive.txt
}


all_subdomain_test(){

echo "- Spf record scan (spoofing mail) -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
curl -s https://www.kitterman.com/spf/getspf3.py\?serial\=fred12\&domain\=$domain | grep --color=auto "No valid SPF record found." && echo "" || echo "SPF RECORD VALID"

echo "- Scan for sourcemap -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
gau --subs $domain | grep [.]js | sed 's/[.]js/.js.map/' | httpx -silent -mc 200 | xargs -I @ scripts/vuln/sourcemapper/sourcemapper -url @ -output results/$domain/sourcemap


for i in $(cat results/$domain/domain_alive.txt)
	do
		echo "- Domain fast vuln test for "+ $i + " -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
		echo "- Scan source disclosure -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
		echo ". for git ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
		curl -s $i/.git/ | grep --color=auto "Index of /.git" && echo ".GIT FIND" > results/$domain/GIT || echo "NOT FOUND"

		echo ". for svn ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
		curl -s $i/.svn/ | grep --color=auto "Index of /.svn" && echo ".SVN FIND" > results/$domain/SVN || echo "NOT FOUND"

		echo ". for hg ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
		curl -s $i/.hg/ | grep --color=auto "Index of /.hg" && echo ".HG FIND" > results/$domain/HG || echo "NOT FOUND"

		echo ". for bzr ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
		curl -s $i/.bzr/ | grep --color=auto "Index of /.bzr" && echo ".BZR FIND" >results/$domain/BZR || echo "NOT FOUND"

		ii=$(echo $i | sed -e 's|^[^/]*//||' -e 's|/.*$||')
		mkdir results/$domain/$ii
		echo "- Javascript -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
		echo ". Find the subdomains hidden inside JavaScipt files ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
		python3 scripts/vuln/js/JSFinder/JSFinder.py -u $i -ou results/$domain/$ii/jsfinder_links.txt -os results/$domain/$ii/jsfinder_subdomains.txt
		echo ". Find the hidden directory path from JavaScript files ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
		echo $i | python3 scripts/vuln/js/JSA/jsa.py | anew results/$domain/$ii/jsa_links.txt
		#echo ". Find secrets, sensitive information from JavaScript files ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
		#python3 scripts/vuln/js/JSScanner/JSScanner.py -u $i -d $domain -t 40  | anew  results/$domain/$ii/JScanner_results.txt
		#echo ". Findsecret in js file ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
		#echo $i | gau | grep "\.js" | uniq | sort | xargs -I@ findsecret/findsecret -i @ -o results/$domain/$ii/find_secret_js.txt


	done
}



domain_enum
all_subdomain_test


echo "- Massdns resolvers -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
massdns -r resolvers.txt -q -t A -o S -w results/$domain/massdns.raw results/$domain/all.txt
cat results/$domain/massdns.raw | grep -e ' A ' |  cut -d 'A' -f 2 | tr -d ' ' > results/$domain/massdns.txt
cat results/$domain/massdns.txt | sort -V | uniq > results/$domain/final-ips.txt
echo ". Resolving ending, result in results/$domain/massdns.txt ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat

echo "- Heartbleed scan with Nmap -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
nmap -p 443 --script ssl-heartbleed -oN results/$domain/hearbleed.txt -iL results/$domain/final-ips.txt

echo "- Cors misconfiguration test -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
python3 Corsy/corsy.py -i results/$domain/domain_alive.txt -t 40 | tee -a results/$domain/corsy_domain.txt

echo "- Takeover test -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
python3 takeover/takeover.py -l results/$domain/domain_alive.txt | tee -a results/$domain/takeover.txt

echo "- Amazon S3 bucket test with nuclei -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
nuclei -l results/$domain/domain_alive.txt -t cent-nuclei-templates/s3-detect.yaml -o results/$domain/S3-bucket.txt

#echo "- Param Spider -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
#python3 ParamSpider/paramspider.py --domain $domain --exclude woff,png,svg,php,jpg --output ~/pentest/results/$domain/param_spider.txt

#echo "- Get Javascript url with getJS -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
#getjs --input results/$domain/domain_alive.txt --output results/$domain/js_link.txt
#curl results/$domain/js_link.txt | grep -Eo "(http|https://[a-zA-Z0-9./?=_-]*"*

echo "- Test ssti vulnerability -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
var=$( cat scripts/vuln/ssti/payload )
gau $domain | gf ssti | qsreplace $var | urldedupe | tee -a results/$domain/ssti.txt
for D in $(cat results/$domain/ssti.txt); do echo "[*] Testing $D"; curl --max-time 5 --connect-timeout 5 -sk $D | grep -q "49" && echo -e "\e[1;31m VULNERABLE !!\e[0m" ; echo $D >> results/$domain/ssti_find ; done

echo "- Test lfi vulnerability -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
gau $domain | gf lfi | qsreplace "/etc/passwd" | tee -a results/$domain/lfi.txt
for D in $(cat results/$domain/lfi.txt); do echo "[*] Testing $D"; curl --max-time 5 --connect-timeout 5 -sk $D | grep -q "root:x" && echo -e "\e[1;31m VULNERABLE !!\e[0m" ; echo $D >> results/$domain/lfi_find ; done

echo "- Test open redirection vulnerability -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
gau $domain | gf redirect | qsreplace "https://www.google.fr" | tee -a results/$domain/open_redir.txt
for D in $(cat results/$domain/open_redir.txt); do echo "[*] Testing $D"; curl --max-time 5 --connect-timeout 5 -sk $D | grep -q "Location: https://www.google.fr" && echo -e "\e[1;31m VULNERABLE !!\e[0m" ; echo $D >> results/$domain/open_redir_find ; done


#gauu testphp.vulnweb.com | tee -a archive 1>/dev/null && gff redirect archive | cut -f 3- -d ':' | qsreplace "https://evil.com" | httpx -silent -status-code -location


#xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: https://www.google.fr" && echo "VULN! %"' && tee -a results/$domain/openredir_vuln.txt

echo "- Get interesting parameters with gf -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
echo ". Ssrf ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
mkdir results/$domain/gf
echo $domain | gau | gf ssrf > results/$domain/gf/ssrf.txt

echo ". Xss ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
echo $domain | gau | gf xss > results/$domain/gf/xss.txt

echo ". Redirect ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
echo $domain | gau | gf redirect > results/$domain/gf/redirect.txt

echo ". Rce ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
echo $domain | gau | gf rce > results/$domain/gf/rce.txt

echo ". Idor ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
echo $domain | gau | gf idor > results/$domain/gf/idor.txt

echo ". Sqli ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
echo $domain | gau | gf sqli > results/$domain/gf/sqli.txt

echo ". Lfi ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
echo $domain | gau | gf lfi > results/$domain/gf/lfi.txt

echo ". Ssti ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
echo $domain | gau | gf ssti > results/$domain/gf/ssti.txt

#echo "- Masscan (slow) -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
#echo ". Giveme sudo password or touchid for Scan ." | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
#sudo masscan -p1-65535 -iL results/$domain/final-ips.txt --max-rate 1800 -oG results/$domain/masscan.txt

echo "- Naabu scan -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
naabu -l results/$domain/final-ips.txt -o results/$domain/naabu_scan_ip.txt
cat results/$domain/all.txt | unfurl --unique domains > results/$domain/domain_unique.txt
naabu -l results/$domain/domain_unique.txt -o results/$domain/naabu_scan_domain.txt

#echo "- Looking Http request smuggling (slow) -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
#cat results/$domain/domain_alive.txt | python3 smuggler/smuggler.py -l results/$domain/smuggler_domain.txt

echo "- Screenshot subdomains press a key -" | sed  -e :a -e "s/^.\{1,$(tput cols)\}$/ & /;ta" | tr -d '\n' | head -c $(tput cols) | lolcat
read
#cd results/$domain
#cat domain_alive.txt | aquatone
#python3 ~/pentest/EyeWitness/Python/EyeWitness.py -f results/$domain/domain_alive.txt --no-prompt --web
eyewitness --no-prompt -f results/$domain/domain_alive.txt --prepend-https -d /var/www/html
sudo service apache2 start
echo "-- Apache started..."
echo "-- screnshot in http://localhost:8080/report.html"
sudo firefox http://localhost:8080/report.html
read touche
echo "-- Apache stoped..."
sudo service apache2 stop
rm -rf /var/www/html/*
