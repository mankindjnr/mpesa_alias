import requests
from datetime import datetime
import json
import base64
from django.http import JsonResponse
from .generateAccessToken import get_access_token

def stk_push(request, theDigits, organization):
    print("iside stkpus")
    access_token_response = get_access_token(request)
    if isinstance(access_token_response, JsonResponse):
        print("inside instance")
        access_token = access_token_response.content.decode('utf-8')
        access_token_json = json.loads(access_token)
        access_token = access_token_json.get('access_token')
        if access_token:
            print(type(theDigits))
            print("inside access token")
            amount = 1
            the_org = str(organization)
            print("------thedigits:", the_org)
            phone = "254720090889",
            passkey = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
            business_short_code = '174379'
            process_request_url = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
            callback_url = 'https://sj76vr3h-8000.euw.devtunnels.ms/' # replace with your own url - the route to be executed when user clicks send
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            password = base64.b64encode((business_short_code + passkey + timestamp).encode()).decode()
            party_a = business_short_code
            party_b = "254720090889", # i'll try and use my own cred/till/phone number
            account_reference = organization,
            transaction_desc = 'stkpush test'
            stk_push_headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + access_token
            }
            print("to the payload")
            stk_push_payload = {
                'BusinessShortCode': 174379,
                'Password': password,
                'Timestamp': timestamp,
                'TransactionType': 'CustomerPayBillOnline',
                'Amount': amount,
                'PartyA': theDigits,
                'PartyB': business_short_code,
                'PhoneNumber': theDigits,
                'CallBackURL': callback_url,
                'AccountReference': the_org,
                'TransactionDesc': transaction_desc
            }

            print("to the try and except")
            try:
                response = requests.post(process_request_url, headers=stk_push_headers, json=stk_push_payload)
                response.raise_for_status()   
                # Raise exception for non-2xx status codes
                response_data = response.json()
                checkout_request_id = response_data['CheckoutRequestID']
                response_code = response_data['ResponseCode']
                
                if response_code == "0":
                    return JsonResponse(response_data)
                else:
                    return JsonResponse({'error': 'STK push failed.'})
            except requests.exceptions.RequestException as e:
                print("raised exceptions")
                return JsonResponse({'error': str(e)})
        else:
            return JsonResponse({'error': 'Access token not found.'})
    else:
        return JsonResponse({'error': 'Failed to retrieve access token.'})