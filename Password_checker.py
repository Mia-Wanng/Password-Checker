# -*- coding: utf-8 -*-
"""
Created on Sun Jul  3 15:03:01 2022

@author: xueqi
"""

import requests
import hashlib
import sys

# get all the hashes that match the first 5 charaters of the input password
def request_api_data(query_char):
  url = 'https://api.pwnedpasswords.com/range/' + query_char
  res = requests.get(url)
  if res.status_code != 200:
    raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
  return res

# loop all the hashes that match the first 5 charaters of the input password
# check if any of them matches the whole input password and return the count number. 
def get_password_leaks_count(hashes, hash_to_check):
  hashes = (line.split(':') for line in hashes.text.splitlines())
  for h, count in hashes:
    if h == hash_to_check:
      return count
  return 0

# Converts input password to Sha1 , only send first 5 hashed charaters to api, return leak count
def pwned_api_check(password):
  sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
  first5_char, tail = sha1password[:5], sha1password[5:]
  response = request_api_data(first5_char)
  return get_password_leaks_count(response, tail)

def main(args):
  for password in args:
    count = pwned_api_check(password)
    if count:
      print(f'{password} was appeared {count} times in previous data breaches. you should probably change your password!')
    else:
      print(f'Good news! {password} was NOT found in any of the exposed Passwords.')

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))