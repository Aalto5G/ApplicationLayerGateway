Application Layer Gateway (ALG) is designed to handle web traffic over HTTP and HTTPS protocol. It uses the technique of light Deep Packet Inspection (DPI) 
for protocol detection and hostname detection of the requested web server behind a NAT network based on the initial request sent by the client.


Dependencies:

It has been developed using Python 3.5 and built for Linux OS Ubuntu (16.04) environment. It uses the YaLe parser-lexer developed by Juha-Matti for its operations available at:
https://github.com/Aalto5G/yale

File Structure:

.
├── config.d
├── src
├── test_scripts
├── database
├── LICENSE

A brief description of the file structure:

config.d: It contains the configuration file to run ALG. Some sample hostnames have been added in the file that should be modified to match the web servers behind the NAT.

src: It contains the source code for ALG in addition to the script for creating a system service for ALG.

test_scripts: Scripts that can be run from the public client to test the performance of ALG. It assumes the host machine running ALG having an IP address of 100.64.1.130 while 
the public client having multiple IP addresses in the 100.64.0.1/24 network.

database: This contains a python script for converting the ALG configuration policies to JSON for integrating it with Security Policy Management (SPM) developed by Hassaan Mohsin. 
Instructions on starting the SPM are available at:
https://github.com/Aalto5G/SecurityPolicyManagement

Note: By default, SPM runs with pre-defined policies loaded from the Databases_Backup folder mentioned in installation.sh script. For running SPM with a sample of ALG 
and Realm Gateway (RGW) policies, a backup of database can be found in the database folder of ALG.



Running the ALG as a stand-alone component:

1. Run the ALG by cloning into the repository

$ git clone https://version.aalto.fi/gitlab/riazm3/applicationlayergateway.git

2. Run the dependencies.sh script in the src directory

$ cd ApplicationLayerGateway/src

$ sudo bash installation.sh

3. Run the system_service.py script as a root user to create a system service for ALG
 
$ sudo python3 system_service.py


Running the ALG with Realm Gateway:

ALG was originally developed to be integrated with Realm Gateway developed by Jesus Llorente Santos. A forked repository that supports integration with ALG is available at:
https://github.com/Maria-Riaz/RealmGateway/tree/ldpsynproxy


1. After cloning the repository checkout to the branch ldpsynproxy.

2. Run the lxc orchestration_ environment available at:
https://github.com/Maria-Riaz/RealmGateway/tree/ldpsynproxy/orchestration/lxc

3. Stop the NGINX server in the 'gwa' container by typing:
$ sudo service nginx stop

Note: Install the SPM repository before running the RGW otherwise, it would result in an error. 

4. ALG can be installed by following the instructions on the section 'Running the ALG as a stand-alone component'.

Note: In case of not running SPM, clone the original Github repository of RGW and then install ALG.



