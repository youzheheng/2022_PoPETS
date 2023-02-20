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

# Usage 
        python graph-attack-pprl.py [encode_data_set_name] [encode_ent_id_col]
                                    [encode_col_sep_char] [encode_header_line_flag]
                                    [encode_attr_list] [encode_num_rec]
                                    [plain_data_set_name] [plain_ent_id_col]
                                    [plain_col_sep_char] [plain_header_line_flag]
                                    [plain_attr_list] [plain_num_rec]
                                    [q] [padded_flag]
                                    [plain_sim_funct_name]
                                    [sim_diff_adjust_flag]
                                    [encode_sim_funct_name]
                                    [encode_method] {encode_method_param}
                                    
 where:

        encode_data_set_name     is the name of the CSV file to be encoded into BFs.
        encode_ent_id_col        is the column in the CSV file containing entity
                                  identifiers.
        encode_col_sep_char      is the character to be used to separate fields in
                                  the encode input file.
        encode_header_line_flag  is a flag, set to True if the file has a header
                                 line with attribute (field) names.
        encode_attr_list         is the list of attributes to encode and use for
                                 the linkage.
        encode_num_rec           is the number of records to be loaded from the data
                                 set, if -1 then all records will be loaded,
                                 otherwise the specified number of records (>= 1).

        plain_data_set_name      is the name of the CSV file to use plain text
                                 values from.
        plain_ent_id_col         is the column in the CSV file containing entity
                                 identifiers.
        plain_col_sep_char       is the character to be used to separate fields in
                                 the plain text input file.
        plain_header_line_flag   is a flag, set to True if the file has a header
                                 line with attribute (field) names.
        plain_attr_list          is the list of attributes to get values from to
                                 guess if they can be re-identified.
        plain_num_rec            is the number of records to be loaded from the data
                                 set, if -1 then all records will be loaded,
                                 otherwise the specified number of records (>= 1).
        q                        is the length of q-grams to use when converting
                                 values into q-gram set.
        padded_flag              if set to True then attribute values will be padded
                                 at the beginning and end, otherwise not.

        plain_sim_funct_name     is the function to be used to calculate similarities
                                 between plain-text q-gram sets. Possible values are
                                 'dice' and 'jacc'.
        sim_diff_adjust_flag     is a flag, if set to True then the encoded
                                 similarities will be adjusted based on calculated
                                 similarity differences of true matching edges
                                 between plain-text and encoded similarities.
        
        encode_method            is the method to be used to encode values from the
                                 encoded data set (assuming these have been converted
                                 into q-gram sets). Possible are: 'bf' (Bloom filter
                                 encoding) or 'tmh' (tabulation min hash encoding) or
                                '2sh' (two-step hash encoding).
        encode_method_param      A set of parameters that depend upon the encoding
                                 method.
        For Bloom filters, these are:
        - bf_hash_type       is either DH (double-hashing)
                            or RH (random hashing).
        - bf_num_hash_funct  is a positive number or 'opt'
                             (to fill BF 50%).
        - bf_len             is the length of Bloom filters.
        - bf_encode          is the Bloom filter encoding method.
                             can be 'clk', 'abf', 'rbf-s', or
                             'rbf-d'
        - bf_harden          is either None, 'balance' or
                                               or 'fold' for different BF
                                               hardening techniques.
        - bf_enc_param       parameters for Bloom filter encoding
                                               method 
         overlap                  The overlap rate of two databases, it's computed as overlap = 2*common records
                                  input vary from 0 to 100 (%)                                  -----------------
                                                                                               len(D_1)+ len(D_2)
                                                                                                D: database
        diffusion_len            The length of the final output
        diffusion_num            The number of diffusion bits. It means that each final 
                                 output bit is determined by how many BF bits
        encode_sim_funct_name    is the function to be used to calculate similarities
                                 between encoded values (such as bit-arrays).
                                 Possible values are 'dice', 'hamm', and 'jacc'.

# Example Call
The codes can be run on terminal, typing the following:
```python
python3 graph-attack-pprl-origin.py data/euro-census.csv 0 , True [1,2,3,4,5] 2000 data/euro-census.csv 0 , 
True [1,2,3,4,5] 2000 2 False dice True bf rh 5 1000 clk none [] 100 1000 20 dice
```
```python
python3 graph-attack-pprl-origin.py data/euro-census.csv 0 , True [1,2,3,4,5] 2000 data/euro-census.csv 0 , 
True [1,2,3,4,5] 2000 2 False dice True bf rh 10 500 clk none [] 95 500 10 dice
```
```python
python3 graph-attack-pprl-origin.py data/euro-census.csv 0 , True [1,2,3,4,5] 2000 data/euro-census.csv 0 , 
True [1,2,3,4,5] 2000 2 False dice True bf rh 5 500 clk none [] 100 500 1 dice
```
# Explanation of the output(s)
When one call/command is executed, roughly 78 different re-identification numbers will be recorded using different parameters of the three matching algorithms. The detailed results will be recorded into one file and the overall results will be recorded into another file.

In total, there should be two result files. One is named by result_(nr. records)_(nr. records) and the other one is named by the date of the experiment. The second file should be in the folder named 'results' and that's the most important result file. The second and third column of this file is the maximum re-identification when executing one command and the average re-identification.

# Link of results with the paper
The command of the first example run shows the experiment using 'bf length 1000, 5 hash functions, 100% overlap rate and 20 diffusion bits'. The second result file shows
```
Correlation          Max re-id    Avg. re-id     Encode_method   overlap    Hash functions   Length of encoding           Diffusion bits
0.308292534025985	83	31.6923076923077	ran	   100	         5	               1000	               20
```
Correlation as well as (Max re-id/1000 * 100%) are shown in the paper in Figure 8. 
![You can also see it here](https://github.com/youzheheng/2022_PoPETS/edit/main/Codes/result_link.jpg?raw=true)

# License
All our code is licensed as free software, under the GPLv3 license.
 
# Important Notes
The codes here were originated from Anushka Vidanage and Peter Christen, which could be requested via email: anushka.vidanage@anu.edu.au
