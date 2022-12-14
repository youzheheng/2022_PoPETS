# Requirement
The code has been tested on:
- Ubuntu 20.04
- Python 3.8.10

Additionally, the following packages are used: 
- Networkx 1.10 **(It's important that the version of Networkx is not too high)**
- sklearn 0.23.2

# Dataset
The dataset is contained in 'Codes/data'.
Additionally, they can also be downloaded from [here](https://github.com/youzheheng/2022_PoPETS/tree/main/Codes/data).
# Docker
This requires [Docker](https://www.docker.com/). First, ensure you have downloaded it. To initialize the experiments, simply run:
```docker
docker build -t myimage1:1.0 .

docker run myimage1:1.0
```
All the code files and data are already included in it.

# Example Call
The codes can be run on terminal, typing the following:
```python
python3 graph-attack-pprl-origin.py data/euro-census.csv 0 , True [1,2,3,4,5] 2000 data/euro-census.csv 0 , 
True [1,2,3,4,5] 2000 2 False dice True bf rh 15 500 clk none [] 100 500 5 dice
```

# License
All our code is licensed as free software, under the GPLv3 license.
 
# Important Notes
The codes here were originated from Anushka Vidanage and Peter Christen, which could be requested via email: anushka.vidanage@anu.edu.au
