# cipherBrute.pl
Bruteforce supported SSL/TLS cipher suites and extract useful SSL Certificate information

**Note:** This tool uses the installed version of OpenSSL on the machine from which it is run as a basis for determining which cipher suites to test. This tool performs a full handshake in order to determine whether a cipher suite is supported much in the same way as the Nmap ssl-enum-ciphers script.

**Note:** This tool will work perfectly when run from Kali, but requires one Perl module to be installed (Crypt::X509). 
To install Crypt::X509 run the following command: **cpanm install Crypt::X509** 

# Why...?

* To quickly determine the supported SSL/TLS cipher suites and present results in a clear/concise manner
* To quickly extract useful information from SSL Certificates and present results in a clear/concise manner

# How to use

##### To check what SSL/TLS cipher suites are supported

`perl cipherBrute.pl -f lisofipaddressesorhostnames.txt`

# Example usage

##### To help demonstrate how this tool works and what it is useful for follow these steps:

**1 -** Create a text file called **listofipaddressesorhostnames.txt** using your favourite editor (vi/pico/nano).  
**2 -** Copy and paste the following sample data into the new text file:

```
www.yourdomaintotest.com
www.yourdomaintotest.com:443
test.idontexist.com
iptotest.iptotest.iptotest.iptotest
maps.yourdomaintotest.org.uk:4444
```
**3 -** Run the following command and select option **1** at the menu:

`perl cipherBrute.pl -f lisofipaddressesorhostnames.txt`

**4 -** Alternatively, to extract useful SSL Certificate information (eg Valid from, Expires on...) run the following command and select option **2** at the menu:

`perl cipherBrute.pl -f lisofipaddressesorhostnames.txt`




