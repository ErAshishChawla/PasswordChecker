import requests
import hashlib
import sys


# This function that requests api for data and give us response
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(api_response, hash_to_check):
    hash_list = (line.split(':') for line in api_response.text.splitlines())
    for hash, count in hash_list:
        if hash == hash_to_check:
            return count
    return 0


# Check password if it exists in API Response
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    api_response = request_api_data(first5_char)
    return get_password_leaks_count(api_response, tail)


def main(password_list):
    for password in password_list:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... your should change your password.')
        else:
            print('{password} was not fount. Carry on!')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
