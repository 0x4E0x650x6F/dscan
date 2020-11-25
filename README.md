# Distributed Nmap Scanner.

The main goal of this project is to provide a wrapper around nmap, 
and distribute scans across several hosts.
 
# Install
```
% git clone https://github.com/0x4E0x650x6F/dscan.git
% cd dscan
% pip install .
% dscan
[*]\tDistribuited scan
usage: Distributed scanner [-h] --name NAME {srv,agent,config} ...
Distributed scanner: error: the following arguments are required: --name, cmd

```

# Uninstall

```
%pip uninstall dscan
```

## Generate self-sign certificate. 

The following command generates a self sign certificate a private key, and two
configuration files agent.conf and dscan.conf with default settings for the
 agent and for the server.
  
```
./bin/dscan --name <project-name> config -email mail@dscan.org -cn dscan \
-c pt -l earth -st nrw -o dscan -ou it -days 365
 ls -a fubar

agent.conf	
certfile.crt	
dscan.conf	
keyfile.key
```


## Server output example

The following command starts the server, the --name is the name of the
 folder where the project files will be stored, this directory should
  contain the dscan.conf and the certificate private key generated from the
   previous command, the last argument is a **existing** file with a list of
    ip or networks to scan. 
```
./bin/dscan --name <project-name> srv --config <path-to-dscan.conf> \
<path-file-with-targets-toscan>.txt

Distributed Scan Status
=======================

---------	----------------	------------
Nº Stages	Nº Pending Tasks	Completion %
---------	----------------	------------
4        	0               	0.00%       

---------	----------	-----------	------------
Stage    	Nº Targets	Nº Finished	Completion %
---------	----------	-----------	------------
discovery	1         	0          	0.00%       

---------------	---------	-----------	------------
Agent          	Stage    	Task Status	Target Ip   
---------------	---------	-----------	------------
127.0.0.1:53281	discovery	DOWNLOADING	127.0.0.1/32
```

## Agent output example 
The following starts the agent, the --name is the name of the folder were
 the work files will be stores should contain a copy of the certficate, and
  the agent.conf file. 

```
./bin/dscan --name <agent-project-name> agent --config <path-to-agent.conf> \ 
-s <server-ip-address> -p <server-port>

 Distributed Scan Status
=======================

------------	------------------	------
Target      	Nª completed Scans	Status
------------	------------------	------
127.0.0.1/32	5                 	100   

```

