import math
import hashing
import encoding
import hashlib
import time
import bitarray
import simcalc
import numpy as np
import string
import random
import hardening
random_coefficient_inf = 30             # [2,100]
from random import seed, randint, sample ,  shuffle
from pylfsr import LFSR
BF_HASH_FUNCT1 = hashlib.sha1
BF_HASH_FUNCT2 = hashlib.md5
map_sup = 1                           
map_inf = 30
# -----------------------------------------------------------------------------
def encode_bf(encode_method, bf_num_hash_funct,encode_q_gram_dict, 
              bf_hash_type,bf_encode, encode_attr_list,bf_len,
              plain_rec_attr_val_dict, q, padded_flag, encode_rec_attr_val_dict,
              bf_harden): 
  """
  """
    
  start_time = time.time()

  if (encode_method == 'bf'): # Bloom filter encoding

    if (bf_num_hash_funct == 'opt'):
      bf_num_hash_funct_str = 'opt'

      # Get the average number of q-grams in the string values
      #
      total_num_q_gram = 0
      total_num_val =    0

      for q_gram_set in encode_q_gram_dict.values():
        total_num_q_gram += len(q_gram_set)
        total_num_val +=    1

      avrg_num_q_gram = float(total_num_q_gram) / total_num_val

      # Set number of hash functions to have in average 50% of bits set to 1
      #
      bf_num_hash_funct = int(round(math.log(2.0)*float(bf_len) / \
                              avrg_num_q_gram))

      print(' Set optimal number of BF hash functions to: %d' % \
            (bf_num_hash_funct))
      print()

    else:
      bf_num_hash_funct_str = str(bf_num_hash_funct)

    # Set up the Bloom filter hashing
    #
    if (bf_hash_type == 'dh'):
      BF_hashing = hashing.DoubleHashing(BF_HASH_FUNCT1, BF_HASH_FUNCT2,
                                         bf_len, bf_num_hash_funct)
    elif (bf_hash_type == 'rh'):
      BF_hashing = hashing.RandomHashing(BF_HASH_FUNCT1, bf_len,
                                         bf_num_hash_funct)
    else:
      raise Exception('This should not happen')
    
    
    # Check the BF encoding method
    #
    if(bf_encode == 'clk'): # Cryptographic Long-term Key
      rec_tuple_list = []
      
      for att_num in range(len(encode_attr_list)):
        rec_tuple_list.append([att_num, q, padded_flag, BF_hashing])
    
      BF_Encoding = encoding.CryptoLongtermKeyBFEncoding(rec_tuple_list)
      
      #-------------------------------------------------------------------------
      # Define hardening method
      #
      if(bf_harden == 'balance'): # Bloom filter Balancing
        #input_random_seed = harden_param_list[0]
    
      #if(input_random_seed):
        rand_seed = randint(1,100)
        #BFHard = hardening.Balancing(True, rand_seed)
      #else:
        BFHard = hardening.Balancing(False, rand_seed)
    
    elif(bf_encode.startswith('rbf')): # Record-level Bloom filter
      
      num_bits_list = bf_enc_param # List of percentages of number of bits
      
      rec_tuple_list = []
      
      for att_num in range(len(encode_attr_list)):
        rec_tuple_list.append([att_num, q, padded_flag, BF_hashing, 
                               int(num_bits_list[att_num]*bf_len)])
      
      BF_Encoding = encoding.RecordBFEncoding(rec_tuple_list)
      
      if(bf_encode == 'rbf-d'): # AFB length set to dynamic
        
        rec_val_list = list(encode_rec_attr_val_dict.values())
        avr_num_q_gram_dict = BF_Encoding.get_avr_num_q_grams(rec_val_list)
        abf_len_dict = BF_Encoding.get_dynamic_abf_len(avr_num_q_gram_dict, 
                                                      bf_num_hash_funct)
        BF_Encoding.set_abf_len(abf_len_dict)
    

    encode_hash_dict = {}  # Generate one bit-array hash code per record

    # Keep the generated BF for each q-gram set so we only generate it once
    #
    bf_hash_cache_dict = {}

    num_enc = 0  # Count number of encodings, print progress report
    
    for (ent_id, q_gram_set) in encode_q_gram_dict.items():
      
      attr_val_list = encode_rec_attr_val_dict[ent_id]
      
      num_enc += 1
      if (num_enc % 10000 == 0):
        time_used = time.time() - start_time
        print('  Encoded %d of %d q-gram sets in %d sec (%.2f msec average)' \
              % (num_enc, len(encode_q_gram_dict), time_used,
                 1000.0*time_used/num_enc))
        print('   ', auxiliary.get_memory_usage())
      
      q_gram_str = ''.join(sorted(q_gram_set))
      
      #if(bf_harden in ['balance', 'fold']):
       # rec_bf, q_gram_pos_dict = ENC_METHOD.encode(attr_val_list)
       # rec_bf, nw_q_gram_pos_dict = BFHard.harden_bf(rec_bf, q_gram_pos_dict)
       # q_gram_pos_dict = nw_q_gram_pos_dict.copy()
       # del nw_q_gram_pos_dict
      
      if (q_gram_str in bf_hash_cache_dict):
        q_gram_str_bf = bf_hash_cache_dict[q_gram_str]
      else:
        if bf_harden == 'balance':
          q_gram_str_bf = BF_Encoding.encode(attr_val_list)
          q_gram_str_bf = BFHard.harden_bf(q_gram_str_bf)
        #print(attr_val_list)
        else:
          q_gram_str_bf = BF_Encoding.encode(attr_val_list)
        q_gram_str_bf_test = BF_hashing.hash_q_gram_set(q_gram_set)
        #print(q_gram_set)
        
        #if(bf_encode == 'clk'):
          #assert q_gram_str_bf == q_gram_str_bf_test
        
        bf_hash_cache_dict[q_gram_str] = q_gram_str_bf
      encode_hash_dict[ent_id] = q_gram_str_bf

    print()
    print('  Encoded %d unique Bloom filters for %d q-gram sets' % \
          (len(bf_hash_cache_dict), len(encode_hash_dict)))

    bf_hash_cache_dict.clear()  # Not needed anymore

  elif (encode_method == 'tmh'):  # Tabulation min-hash encoding

    if (tmh_hash_funct == 'md5'):
      tmh_hash_funct_obj = hashlib.md5
    elif (tmh_hash_funct == 'sha1'):
      tmh_hash_funct_obj = hashlib.sha1
    elif (tmh_hash_funct == 'sha2'):
      tmh_hash_funct_obj = hashlib.sha256
    else:
      raise Exception('This should not happen')

    TMH_hashing = tabminhash.TabMinHashEncoding(tmh_num_hash_bits,
                                                tmh_num_tables, tmh_key_len,
                                                tmh_val_len, tmh_hash_funct_obj)

    encode_hash_dict = {}  # Generate one bit-array hash code per record

      # Keep the generated BA for each q-gram set so we only generate it once
      #
    ba_hash_cache_dict = {}

    num_enc = 0  # Count number of encodings, print progress report

    for (ent_id, q_gram_set) in encode_q_gram_dict.items():

      num_enc += 1
      if (num_enc % 10000 == 0):
        time_used = time.time() - start_time
        print('  Encoded %d of %d q-gram sets in %d sec (%.2f msec average)' \
              % (num_enc, len(encode_q_gram_dict), time_used,
                 1000.0*time_used/num_enc))
        print('   ', auxiliary.get_memory_usage())

      q_gram_str = ''.join(sorted(q_gram_set))
      if (q_gram_str in ba_hash_cache_dict):
        q_gram_str_ba = ba_hash_cache_dict[q_gram_str]
      else:
        q_gram_str_ba = TMH_hashing.encode_q_gram_set(q_gram_set)
        ba_hash_cache_dict[q_gram_str] = q_gram_str_ba
      encode_hash_dict[ent_id] = q_gram_str_ba

    print()
    print('  Encoded %d unique bit-arrays for %d q-gram sets' % \
          (len(ba_hash_cache_dict), len(encode_hash_dict)))

    ba_hash_cache_dict.clear()  # Not needed anymore

  elif(encode_method == '2sh'): # Two-step hash encoding             
    
    CMH_hashing = colminhash.ColMinHashEncoding(cmh_num_hash_funct,
                                                cmh_num_hash_col)
    
    encode_hash_dict = {}  # Generate one column hash code per record
    
    # Keep the generated column hash codes for each q-gram set so we only generate it once
    #
    col_hash_cache_dict = {}

    num_enc = 0  # Count number of encodings, print progress report
    
    for (ent_id, q_gram_set) in encode_q_gram_dict.items():
      
      num_enc += 1
      if (num_enc % 10000 == 0):
        time_used = time.time() - start_time
        print('  Encoded %d of %d q-gram sets in %d sec (%.2f msec average)' \
              % (num_enc, len(encode_q_gram_dict), time_used,
                 1000.0*time_used/num_enc))
        print('   ', auxiliary.get_memory_usage())

      q_gram_str = ''.join(sorted(q_gram_set))
      if (q_gram_str in col_hash_cache_dict):
        q_gram_str_col_hash_set = col_hash_cache_dict[q_gram_str]
      else:
        q_gram_str_col_hash_set = CMH_hashing.encode_q_gram_set(q_gram_set)
        col_hash_cache_dict[q_gram_str] = q_gram_str_col_hash_set
      encode_hash_dict[ent_id] = q_gram_str_col_hash_set

    print()
    print('  Encoded %d unique col hash sets for %d q-gram sets' % \
          (len(col_hash_cache_dict), len(encode_hash_dict)))
    
    col_hash_cache_dict.clear()  # Not needed anymore  
  
  else:
    raise Exception('This should not happen')

  hashing_time = time.time() - start_time

  print()
  print('Time for hashing the encode data set: %.2f sec' % (hashing_time))
  print('  Number of records hashed:', len(encode_hash_dict))
  print()

  # Check which entity identifiers occur in both data sets
  #
  common_ent_id_set = set(plain_rec_attr_val_dict.keys()) & \
                      set(encode_hash_dict.keys())
  common_num_ent = len(common_ent_id_set)

  plain_num_ent =  len(plain_rec_attr_val_dict)
  encode_num_ent = len(encode_hash_dict)

  print('  Number of entities in the two data sets (plain-text / encoded): ' \
        + '%d / %d' % (plain_num_ent, encode_num_ent))
  print('    Number of entities that occur in both data sets: %d' % \
        (common_num_ent))
  print()
  return encode_hash_dict, hashing_time, plain_num_ent,  encode_num_ent, common_num_ent
#------------------------------------------------------------------------------ 
  
def gen_indices(num_ind, bf_len, out_len):
  '''
  '''
  list_1 = [1]*bf_len#100#bf_len
  out_list = []
  list_2 = [0]*bf_len
  for i in range(out_len):
    mid_list = []
    #for j in range(num_ind):
    count = 0
    if num_ind > bf_len + 1:
      print('Parameter wrong: random selection is larger than bf_len!')
      break
    while(count < num_ind ):
      a = randint(0, bf_len - 1)#99)#bf_len - 1)
      if (list_1[a] > 0) and (a not in mid_list):
        mid_list.append(a)
        count += 1
        list_1[a] -= 1
      if list_1 == list_2:
        list_1 = [1]*bf_len
    #print(list_1)  
    out_list.append(mid_list)
    
  return out_list
# -----------------------------------------------------------------------------  
def gen_indices_1(num_ind, bf_len, out_len):
  '''
  '''
  #bf_len = 100
  list_1 = [1]*bf_len
  out_list = []
  list_2 = [0]*bf_len
  list_3 = list(range(bf_len))

  for i in range(out_len):
    mid_list = []
    count = 0
    if num_ind > bf_len + 1:
      print('Parameter wrong: random selection is larger than bf_len!')
      break
    shuffle(list_3)
    while(count < num_ind ):
      a = list_3[0]
      #if (a not in mid_list):
      mid_list.append(a)
      count += 1
      list_1[a] -= 1
      list_3.remove(a)
      if list_1 == list_2:
        #mid_list = []
        list_1 = [1]*bf_len
        list_3 = list(range(bf_len))
    #print(list_1)  
    out_list.append(mid_list)
  return out_list
# -----------------------------------------------------------------------------
def encode_bf_lfsr(encode_hash_tuple, mapping): 
  """
  """
    
  result_dict = {}
  dict_1 = encode_hash_tuple[0]
  for i,j in dict_1.items():
    result_list = []
    for k in range(len(mapping)):
      result = 0
      for l in range(len(mapping[k])):
        #if mapping[k][l] == 1: 
        result += int(j[mapping[k][l]])
      if result % 2 == 1:
        result_list.append(1)
      else:
        result_list.append(0)
    result_dict[i] = bitarray.bitarray(result_list)

  return result_dict
# -----------------------------------------------------------------------------
def encode_bf_lfsr_1(dict_1, mapping):
  """
  """
  result_dict = {}
  for i,j in dict_1.items():
    result_list = []
    for k in range(len(mapping)):
      result = 0
      for l in range(len(mapping[k])):
        #if mapping[k][l] == 1: 
        result ^= j[mapping[k][l]]
      result_list.append(result)
      #if result % 2 == 1:
      #  result_list.append(1)
      #else:
      #  result_list.append(0)
    result_dict[i] = bitarray.bitarray(result_list)
  return result_dict

  
# ----------------------------------------------------------------------------- 
def func_lfsr(output_length, bf_length, num_lfsr):
  """
  """
  seed = [0,0,0,1,0,0,1,0,0,0,0,0,1,0,0,1,0,0,1,0,0,1,0]
  fpoly = [23,19]
  #seed = [0,0,0,1,0]
  #fpoly = [5,4,3,2]
  L = LFSR(fpoly = fpoly, initstate = seed)
  seq = []
  for i in range(output_length):
    seq_row = []
    for j in range(num_lfsr):
      seq_row.append(L.runKCycle(bf_length - 1))
    seq.append(seq_row)
  out_seq = []
  for i in range(output_length): 
    mid = seq[i][0]
    for j in range(num_lfsr-1):
      mid = mid & seq[i][j+1]
    out_seq.append(mid)
  return out_seq
# -----------------------------------------------------------------------------
def sort_lfsr(lfsr, output_length, bf_length):
  """
  """
  out_seq = []
  for i in range(output_length):
    count = 0
    mid = []
    for j in range(bf_length - 1):
      count += 1
      if lfsr[i][j] == 1:
        mid.append(count)
    out_seq.append(mid)
  #print(out_seq)
  return out_seq 
# -----------------------------------------------------------------------------
def random_xgen(mappings, output_length, bf_length):
  """
  """
  xi = list()
  for i in range(output_length):
    x = list()
    for j in range(len(mappings[i])):
      x.append(randint(0,1))
    xi.append(x)
  return xi
  
# -----------------------------------------------------------------------------
def encode_bb(q_gram_dict, q_gram_dict_2, sim_thresh, sim_funct_name):
  """
  """
  encoded_res = {}
  for i in q_gram_dict_2.keys():
    value_list = []
    for j in q_gram_dict.keys():
      if sim_funct_name == 'dice':
        sim = simcalc.q_gram_dice_sim(q_gram_dict[j],q_gram_dict_2[i])
        if sim >= sim_thresh:
          value_list.append(1)     
        else:
          value_list.append(0)
          
    encoded_res[i] = bitarray.bitarray(value_list)
  return encoded_res    
 # -----------------------------------------------------------------------------
def encode_cc(q_gram_dict, q_gram_dict_2, sim_thresh, sim_diff, sim_funct_name):
  """
  """
  encoded_res = {}
  for i in q_gram_dict_2.keys():
    value_list = []
    for j in q_gram_dict.keys():
      if sim_funct_name == 'dice':
        sim = simcalc.q_gram_dice_sim(q_gram_dict[j],q_gram_dict_2[i])
        if sim >= sim_thresh:
          value_list.append(0)
        else:
          largest_num = math.ceil(sim_thresh/sim_diff)
          for k in range(largest_num):
            if sim >= sim_thresh - sim_diff* (k+1):
              value_list.append(k+1)
              break
            elif sim < sim_thresh - sim_diff * largest_num: 
              value_list.append(largest_num + 1)
              break
      elif sim_funct_name == 'jacc':
        sim = simcalc.q_gram_jacc_sim(q_gram_dict[j],q_gram_dict_2[i])
        if sim <= sim_thresh:
          value_list.append(0)
        else:
          largest_num = math.ceil((1 - sim_thresh)/sim_diff)
          for k in range(largest_num):
            if sim <= sim_thresh + sim_diff* (k+1):
              value_list.append(k+1)
              break
            else: 
              continue   
      elif sim_funct_name == 'hamm':
        sim = simcalc.q_gram_hamm_sim(q_gram_dict[j],q_gram_dict_2[i])
        if sim <= sim_thresh:
          value_list.append(0)
        else:
          largest_num = math.ceil((1 - sim_thresh)/sim_diff)
          for k in range(largest_num):
            if sim <= sim_thresh + sim_diff* (k+1):
              value_list.append(k+1)
              break
            else: 
              continue 
              
    encoded_res[i] = value_list
  
  
  return encoded_res   
  
# -----------------------------------------------------------------------------

def gen_random_poly(num_func, highest_dim):
  """
  """
  # Generate a list of functions
  functions = list()

  # Generate num_func lists of coefficients and functions
  for i in range(num_func):
    coefficients = sample(range(-random_coefficient_inf,\
                               random_coefficient_inf), highest_dim + 1)
    functions.append(np.poly1d(coefficients))
  return functions
# -----------------------------------------------------------------------------
def eva_poly(functions, num_func, highest_dim):
  """
  """
  # Generate a list of points where poly's derivatives are 0
  zeros = list()
  
  # 
  for i in range(num_func):
    if highest_dim == 1:
      zeros.append(0)
    else:
      zeros.append(functions[i].deriv().r)
    
  return zeros
# -----------------------------------------------------------------------------
def gen_random_mapping(num_func):
  """
  """
  #random.seed(random.randint(1,100))
  mapping = list()
  for i in range(num_func):
    letter_dict = dict()
    for j in range(26):
      letter_dict[string.ascii_lowercase[j]] = randint(map_sup,map_inf)
    letter_dict['-'] = randint(map_sup, map_inf)
    letter_dict[' '] = randint(map_sup, map_inf)
    letter_dict["'"] = randint(map_sup, map_inf)
    letter_dict["/"] = randint(map_sup, map_inf)
    letter_dict["."] = randint(map_sup, map_inf)
    letter_dict["("] = randint(map_sup, map_inf)
    letter_dict[")"] = randint(map_sup, map_inf)
    letter_dict["_"] = randint(map_sup, map_inf)
    
    for j in range(10):
      letter_dict[str(j)] = randint(map_sup, map_inf)
    mapping.append(letter_dict)
  
  return mapping
# -----------------------------------------------------------------------------

def encode_poly(num_dict_list, functions, num_functions, zeros, highest_dim):
  """
  """
  encoded_res = {}
  for i in num_dict_list.keys():
    value_list = []
    for j in range(num_functions):
      value = 0
      for k in range(len(num_dict_list[i][j])):
        up_bound = max(num_dict_list[i][j][k])
        lo_bound = min(num_dict_list[i][j][k])
        if lo_bound == up_bound:
          value += functions[j](up_bound)
        else:
          if highest_dim == 1:
            value += max(functions[j](up_bound),functions[j](lo_bound))
          elif highest_dim == 2:
            if zeros[j]:
              value += max(functions[j](up_bound),functions[j](lo_bound)\
                          ,zeros[j][0])
            else:
              value += max(functions[j](up_bound),functions[j](lo_bound))
          elif highest_dim == 3:
            value += max(functions[j](up_bound),functions[j](lo_bound)\
                         ,zeros[j][0], zeros[j][1])
      value_list.append(value)
    encoded_res[i] = value_list   
    
  return encoded_res     
# -----------------------------------------------------------------------------
def convert_q_gram_num(q_gram_dict_list, mappings, num_func, use_max_min_flag = False):
  """
  """
  result = {}
  for i in q_gram_dict_list.keys():
    num_list_2 = []
    for j in range(num_func):
      num_list_dict = {}
      num_list = []
      length = []
      sort_len = []
      for k in range(len(q_gram_dict_list[i])):
        q_gram = q_gram_dict_list[i][k]
        num_1 = mappings[j][q_gram[0]]
        num_2 = mappings[j][q_gram[1]]
        length.append(abs(num_1 - num_2))
        num_list.append([num_1,num_2])
        num_list_dict[abs(num_1 - num_2)] = [num_1, num_2]
      len_max = max(length)
      len_min = min(length)
      sort_len = sorted(length, reverse = True)
      if use_max_min_flag == False:
        if len(length) >= 4:
          num_list_2.append([num_list_dict[sort_len[0]],\
                             num_list_dict[sort_len[1]],\
                             num_list_dict[sort_len[2]],\
                             num_list_dict[sort_len[3]]])
                             #num_list_dict[sort_len[4]]])
        elif len(length) == 3:
          num_list_2.append([num_list_dict[sort_len[0]],\
                             num_list_dict[sort_len[1]],\
                             num_list_dict[sort_len[2]]])
        elif len(length) == 2:
          num_list_2.append([num_list_dict[sort_len[0]],\
                             num_list_dict[sort_len[1]]])                     
      else:
        num_list_2.append([num_list_dict[len_max],num_list_dict[len_min]])
      
    result[i] = num_list_2
  
  return result
  
# -----------------------------------------------------------------------------
def convert_q_gram_num2(q_gram_dict_list, mappings, num_func, use_max_min_flag = True):
  """
  """
  result = {}
  q_gram_dict = {}
  for i in q_gram_dict_list.keys():
    num_list_2 = []
    for j in range(num_func):
      num_list_dict = {}
      num_list = []
      length = []
      sort_len = []
      for k in range(len(q_gram_dict_list[i])):
         
        q_gram = q_gram_dict_list[i][k]
        num_1 = mappings[j][q_gram[0]]
        num_2 = mappings[j][q_gram[1]]
        length.append(abs(num_1 - num_2))
        num_list.append([num_1,num_2])
        num_list_dict[abs(num_1 - num_2)] = [num_1, num_2]
        q_gram_dict[abs(num_1 - num_2)] = q_gram
      len_max = max(length)
      len_min = min(length)
      sort_len = sorted(length, reverse = True)
      if use_max_min_flag == False:
        if len(length) >= 4:
          num_list_2.append(q_gram_dict[sort_len[0]])
        #if len(length) >= 4:
        #  num_list_2.append([q_gram_dict[sort_len[0]],\
        #                     q_gram_dict[sort_len[1]],\
        #                     q_gram_dict[sort_len[2]],\
        #                     q_gram_dict[sort_len[3]]])
        #                     #num_list_dict[sort_len[4]]])
        #elif len(length) == 3:
        #  num_list_2.append([q_gram_dict[sort_len[0]],\
        #                     q_gram_dict[sort_len[1]],\
        #                     q_gram_dict[sort_len[2]]])
        #elif len(length) == 2:
        #  num_list_2.append([q_gram_dict[sort_len[0]],\
        #                     q_gram_dict[sort_len[1]]])                 
      else:
        num_list_2.append([num_list_dict[len_max],num_list_dict[len_min]])
      
    result[i] = num_list_2
  #print(result)
  return result  
  
# -----------------------------------------------------------------------------
def encode_hash(num_dict_list, num_functions):
  """
  """
  encoded_res = {}
  for i in num_dict_list.keys():
    value_list = []
    for j in range(num_functions):
      value = 0
      mid_list = [str(j)]
      for k in range(len(num_dict_list[i][j])):
        mid_list.append(num_dict_list[i][j][k])
      #print(mid_list)
      md_lst = ''.join(mid_list)
      #print(md_lst)
      hash_val = bitarray.bitarray((bin(int(BF_HASH_FUNCT1(md_lst.encode('utf-8')).hexdigest(), base=16)))[2:].zfill(256))
      #print(len(hash_val))
      value_list.append(hash_val)   
    #random.shuffle(value_list)
    val = bitarray.bitarray()
    for j in range(num_functions):
      val += value_list[j]
    encoded_res[i] = val
    #print(len(encoded_res[i])) 
  return encoded_res  
