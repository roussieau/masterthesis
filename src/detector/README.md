# Detector
## How to launch it
Create the docker
``` 
Docker build -t detector:latest .
```
Launch the docker
```
docker run -it -v "$(pwd)/malwares:/malwares" detector:latest /bin/bash

usage: detector.py [-h] [--date DATE] [--verbose] [--auto] [--features]
                   [--save]
                   path

Packer detector

positional arguments:
  path           Path to the malware

optional arguments:
  -h, --help     show this help message and exit
  --date DATE    Date with the following structure YYYYMMDD
  --verbose, -v  Verbose
  --auto         Auto scan
  --features     Extract feature values
  --save         Save to db
```
