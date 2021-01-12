# Distributed Nmap Scanner.

The main goal of this project is to provide a wrapper around nmap, and
 distribute scans across several hosts.
 
 PIP package published at 

[pip3 url](https://pypi.org/project/dscan-4E656F/) 

[Documentation](https://dscan.readthedocs.io/en/0.1.1/)


[Demo Video](https://www.youtube.com/watch?v=3wY6gpH_8rE).

## Install

```bash
% git clone https://github.com/0x4E0x650x6F/dscan.git
% cd dscan
% pip install .
% dscan
[*]\tDistribuited scan
usage: Distributed scanner [-h] --name NAME {srv,agent,config} ...
Distributed scanner: error: the following arguments are required: --name, cmd
```

## Uninstall

```bash
% pip uninstall dscan
```

## Generate self-sign certificate. 

The following command generates a self sign certificate a private key, and two
configuration files agent.conf and dscan.conf with default settings for the
agent and for the server.

```bash
dscan --name <project-name> config -email mail@dscan.org -cn dscan \
-c pt -l earth -st nrw -o dscan -ou it -days 365
ls -a fubar
- agent.conf	
- certfile.crt	
- dscan.conf	
- keyfile.key
```

## Server output example

The following command starts the server, the --name is the name of the
folder where the project files will be stored, this directory should
contain the dscan.conf and the certificate private key generated from the
previous command, the last argument is a existing file with a list of
ip or networks to scan.

````bash

%dscan --name project name srv --config dscan.conf targets.txt
    
    Distributed Scan Status
    ========================
    
    ---------	----------------	------------
    N Stages	N  Pending Tasks	Completion %
    ---------	----------------	------------
    4        	0               	0.00%       
    
    ---------	----------	-----------	------------
    Stage    	N Targets	N Finished	Completion %
    ---------	----------	-----------	------------
    discovery	1         	0          	0.00%       
    
    ---------------	---------	-----------	------------
    Agent          	Stage    	Task Status	Target Ip   
    ---------------	---------	-----------	------------
    127.0.0.1:53281	discovery	DOWNLOADING	127.0.0.1/32
````

## Agent output example

The following starts the agent, the --name is the name of the folder were
the work files will be stores should contain a copy of the certificate, and
the agent.conf file. 

```bash
dscan --name <agent-project-name> agent --config <path-to-agent.conf> \ 
-s <server-ip-address> -p <server-port>

Distributed Scan Status
========================

------------	------------------	------
Target      	Nª completed Scans	Status
------------	------------------	------
127.0.0.1/32	5                 	100   

```

