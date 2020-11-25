# Distributed Nmap Scanner.

The main goal of this project is to provide a wrapper around nmap, 
and distribute scans across several hosts.
 
 
 ## Generate self-sign certificate. 

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

