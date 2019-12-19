# Detector
## How to launch it
Create the docker
``` 
Docker build -t detector:latest .
```
Launch the docker
```
docker run -it -v "$(pwd)/malwares:/malwares" docker:latest /bin/bash
python3 detector.py -h
```
