# Android SSL Analyzer Service

Upload APKs (for x86 architecture) to be analysed for common SSL-related vulnerabilities in Android.\
Vulnerabilities include
* Custom Trustmanager accepting all certificates (with valid hostname)
* Custom HostnameVerifier accepting all hostnames
* Custom WebViewClient.onSSLErrorReceived accepting all certificates
* Apps not using certificate pinning
* Apps implementing certificate pinning erroneously (getPeerCertificates bug)
* Other vulnerabilities for which you can check by configuring your own scenario and MITM proxy certificate settings

## How to run locally

Run `sudo xhost +` to enable displaying emulator UI.\
Run `docker-compose -f docker-compose-local.yml up --build`. The initial building of the docker images might take some time (~ 1 hour).\
You can access the web service on `http://0.0.0.0:5000/index`

See docker-compose configuration files for customization options.

## How to run on multiple machines

Specify the IP of the manager machine in the URLs in `config.py`.\
Run `docker-compose -f docker-compose-manager.yml up --build` on the manager machine.\
Run `sudo xhost +` and `docker-compose -f docker-compose-workers.yml up --build` on each of the worker machines
(including the manager machine if it should also run workers).\
Make sure that the ports of the docker-compose configuration files are not already in use (e.g. by a local RabbitMQ server).\
You can access the web service on the IP of the manager machine on port 5000 at /index.

See docker-compose configuration files for customization options.

The service can currently not be run in swarm mode, since after the latest Android emulator update the emulator just 
starts with a black screen when not using GPU acceleration.
GPU acceleration requires docker privileged mode which is not supported in swarm mode.