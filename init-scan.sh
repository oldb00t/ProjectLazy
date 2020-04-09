q="nmap -T4 -Pn -n -oA nmap-scans/init -sV INSERTIPADDRESS --reason --version-light"
echo $q
nmap -T4 -Pn -n -oA nmap-scans/init -sVC INSERTIPADDRESS --reason --version-light 

f="nmap -T4 -Pn -n -oA nmap-scans/full -sVC INSERTIPADDRESS -p- --reason "
echo $f
nmap -T4 -Pn -n -oA nmap-scans/full -sVC INSERTIPADDRESS -p- --reason


u="nmap -T4 -Pn -n -oA nmap-scans/udp -sU INSERTIPADDRESS -F- --reason"
echo $u
nmap -T4 -Pn -n -oA nmap-scans/udp -sU INSERTIPADDRESS -F- --reason

xsltproc nmap-scans/full.xml -o nmap-scans/full.html
xsltproc nmap-scans/udp.xml -o nmap-scans/udp.html
firefox nmap-scans/full.html &
firefox nmap-scans/udp.html &
