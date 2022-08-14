import requests
import hashlib
import sys
import os
import re
import time


class NoFilePassed(Exception):
    pass


class SingleFileRequired(Exception):
    pass


class FileNotTxt(Exception):
    pass


class FileNotExists(Exception):
    pass


class FileIsEmpty(Exception):
    pass


def performance(fun):
    def wrapper(*args, **kwargs):
        t1 = time.time()
        result = fun(*args, **kwargs)
        t2 = time.time()
        print(f'Time lapsed {t2 - t1}sec')
        return result

    return wrapper


def file_check(argv):
    if (file_list_len := len(argv)) > 1:
        return SingleFileRequired()
    if file_list_len == 0:
        return NoFilePassed()

    file_name = argv[0]
    regex = r"[a-zA-Z0-9_-]*[.][t][x][t]{1}$"
    pattern = re.compile(regex)
    if not bool(pattern.fullmatch(file_name)):
        return FileNotTxt()

    if not os.path.exists(file_name):
        return FileNotExists()
    if os.stat(file_name).st_size == 0:
        return FileIsEmpty()

    return file_name


def get_passwords_list(file_name):
    with open(file_name, mode='r') as passwords_file:
        passwords = passwords_file.read()
        passwords_list = passwords.splitlines()
    return passwords_list


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


@performance
def main(argv):
    try:
        file_check_result = file_check(argv)
        if isinstance(file_check_result, Exception):
            raise file_check_result
        file_name = file_check_result
        passwords_list = get_passwords_list(file_name)
        for password in passwords_list:
            count = pwned_api_check(password)
            if count:
                print(f'{password} was found {count} times... your should change your password.')
            else:
                print('{password} was not fount. Carry on!')
    except NoFilePassed:
        print('No file has been passed as an argument.')

    except FileNotTxt:
        print('File is not of txt format')

    except FileNotExists:
        print('The file passed is not present at the specified location')

    except FileIsEmpty:
        print('The file passed is empty')

    except SingleFileRequired:
        print('Multiple Files have been passed. Please pass a single file')

    finally:
        return 'Process Completed!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
