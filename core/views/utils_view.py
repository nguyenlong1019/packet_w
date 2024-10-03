import binascii 
import base64 
from datetime import datetime 
from django.http import JsonResponse 
import json 
from django.contrib.auth.decorators import login_required 


def decode_hex(hex_string):
    try:
        # convert string to bytes and then decode string
        decoded_string = binascii.unhexlify(hex_string).decode('utf-8')
        return decoded_string 
    except (binascii.Error, UnicodeDecodeError):
        return "Invalid hex string or unable to decode" 
    

# hex_string = '68656c6c6f20776f726c64'
# print(decode_hex(hex_string))  # Output: hello world


def decode_base64(encoded_string):
    try:
        # Decode base64 string 
        decoded_bytes = base64.b64decode(encoded_string)
        decoded_string = decoded_bytes.decode('utf-8')
        return decoded_string 
    except (base64.binascii.Error, UnicodeDecodeError):
        return "Invalid base64 string or unable to decode" 
    

# base64_string = 'aGVsbG8gd29ybGQ='
# print(decode_base64(base64_string))  # Output: hello world
    

def convert_unix_timestamp(timestamp):
    try:
        # convert from unix timestamp to datetime format 
        timestamp = int(timestamp)
        dt_object = datetime.fromtimestamp(timestamp)
        return dt_object.strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "Invalid timestamp."
    

# unix_timestamp = 1633072800
# print(convert_unix_timestamp(unix_timestamp))  # Output: 2021-10-01 00:00:00


def convert_datetime_to_unix(datetime_string, format_string="%Y-%m-%d %H:%M:%S"):
    try:
        # convert from datetime formated to unix timestamp 
        dt_object = datetime.strptime(datetime_string, format_string)
        return int(dt_object.timestamp())
    except ValueError:
        return "Invalid datetime format."
    

# datetime_string = '2021-10-01 00:00:00'
# print(convert_datetime_to_unix(datetime_string))  # Output: 1633072800


@login_required(login_url='/login/')
def decode_hex_view(request):
    if request.method == 'POST':
        # hex_string = request.POST.get('hex_string')
        data = json.loads(request.body)
        hex_string = data.get('hex_string')
        res = decode_hex(hex_string) 
        return JsonResponse({
            'res': res 
        }, status=200)


@login_required(login_url='/login/')
def decode_base64_view(request):
    if request.method == 'POST':
        # encoded_string = request.POST.get('encoded_string')
        data = json.loads(request.body)
        encoded_string = data.get('encoded_string')
        res = decode_base64(encoded_string)
        return JsonResponse({
            'res': res 
        }, status=200)


@login_required(login_url='/login/')
def convert_time_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        type = data.get('ctype')
        time_string = data.get('time_string')
        if type == '1':
            res = convert_unix_timestamp(time_string)
            return JsonResponse({
                'res': res,
            }, status=200)
        elif type == '2':
            res = convert_datetime_to_unix(time_string)
            return JsonResponse({
                'res': res 
            }, status=200)
        else:
            return JsonResponse({
                'res': 'Ctype Invalid'
            })


