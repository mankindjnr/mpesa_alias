import os
import json
import binascii
import re
from django import forms
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.urls import reverse, reverse_lazy
from django.db import IntegrityError
from datetime import datetime
from .all_forms import aliasCreationForm
from .models import aliases, supaProfile, lockAndKey, aliasTransactions, verifiedDigits
from .alias_creation import encryptNumber, decryptNumber
from .privacy import serials, deserials
from .generateAccessToken import get_access_token
from .querystkstatus import query_stk_status
from .stkpush import stk_push

from dotenv import load_dotenv
load_dotenv()
from supabase import create_client

url = os.environ.get("supabase_url")
key = os.environ.get("supabase_key")
supabase = create_client(url, key)

# Create your views here.
def index(request):
    return render(request, "alias/index.html")

def homePage(request):
    current_user_email = request.session.get("user_email", None)
    all_aliases  = supabase.table("alias_aliases").select("desired_alias").eq("email", current_user_email).execute()
    my_aliases = all_aliases.data
    print(my_aliases)
    
    # -------------retrieving the latest sent successful transaction---using largest id-------------------------
    latest_sent_transaction_ids = []
    for alias in my_aliases:
        sent_transaction_ids = supabase.table("alias_aliastransactions").select("id").eq("sender", alias['desired_alias']).eq("transaction_completed", True).execute()
        sent_transaction_ids = sent_transaction_ids.data
        if sent_transaction_ids:
            largest_id = max(sent_transaction_ids, key=lambda x: x['id'])
            dictionary = {alias['desired_alias']: largest_id['id']}
            latest_sent_transaction_ids.append(dictionary)
    count = 0
    if len(latest_sent_transaction_ids) > 0:
        for latest_id in latest_sent_transaction_ids:
                print()
                desired_alias = my_aliases[count]['desired_alias']
                count += 1
                # get settings back and run it again:
                
                latest_sent_transaction_obj = supabase.table("alias_aliastransactions").select("receiver, amount").eq("id", latest_id[desired_alias]).eq("transaction_completed", True).execute()
                print(latest_sent_transaction_obj.data)
    return render(request, "alias/home.html",{
        "aliases": my_aliases
    })
# ====================================================================================
def createAliasForm(request):
    form = aliasCreationForm()

    current_user_email = request.session.get('user_email', None)
    current_user_obj = supabase.table("alias_supaprofile").select("id").eq("email", current_user_email).execute()
    current_user_id =  current_user_obj.data[0]['id']

    VALID = True
    data = supabase.table("alias_verifieddigits").select("*").eq("digitsOwner_id", current_user_id).eq("validated", True).execute()
    data = data.data
    
    anyVerifiedNumbers = False
    if len(data) > 0:
        anyVerifiedNumbers = True


    return render(request, "alias/createAliasForm.html",{
        "form": form,
        "anyVerifiedNumbers": anyVerifiedNumbers,
        "data": data
    })

def verifyDigits(request):
    if request.method == "POST":
        theDigits = request.POST['phone_num']
        verifyAmount = 1

        digits_owner_email = request.session.get('user_email', None)
        digitsOwner = supaProfile.objects.get(email=digits_owner_email)

        verified = verifiedDigits(
            digitsOwner = digitsOwner,
            theDigits = theDigits,
            validated = False,
            validate_at = datetime.now()
        )

        verified.save()
        #assuming the everything is okay we will send the stk push and render the waiting page
        organization = "VERIFY-ALIAS"
        verificationResp = stk_push(request, theDigits, organization)
        
        # ---------------verification check--------------------------")
        response_data = json.loads(verificationResp.content)
        formatted_response = json.dumps(response_data, indent=4)
        checkOutId = response_data.get('CheckoutRequestID')
        # "--------------------------------------------------")

        # i will store the checkout id in the session or later in the database(maybe)
        request.session["digits"] = theDigits
        request.session["checkOutId"] = checkOutId
        # using messages, raise errors num is not verified
        # if no errors, save to database
        # if no errors, send the stk push as you render and wait
        return render(request, "alias/verifyDigits.html")

def confirmedDigits(request):
    thedigits = request.session.get('digits', None)
    checkoutid = request.session.get('checkOutId', None)
    queryresponse = query_stk_status(request, checkoutid)
    queryRespData = json.loads(queryresponse.content)
    #formattedQueryResp = json.dumps(queryRespData, indent=4)
    #print(queryRespData.get("queryResponse"))
    try:
        responseCode = queryRespData.get("queryResponse")['ResultCode']
    except Exception as e:
        # if a user enters pin but phone is slow to respond. we can store the responsecode
        # and run it later
        print("exceptions")
        pass

    if responseCode == '0':
        validate = True
        supabase.table("alias_verifieddigits").update({"validated": validate}).eq("theDigits", thedigits).execute()

        # else: redirect to the createalias/verify page with a message of failed - wipe it of the history

    return HttpResponseRedirect(reverse('homePage'))
# ------------------------------------------------------------------------------------
def createAlias(request):
    if request.method == "POST":
        print("requested form-----------------")
        aliasCreation = aliasCreationForm(request.POST)
        if aliasCreation.is_valid():
            original_num = aliasCreation.cleaned_data['original_num'] #we will later validate with an stkpush
            received_alias = aliasCreation.cleaned_data['desired_alias'] # check if it exists - realtime eval
            formatted_alias = ''.join(received_alias.split('_')).replace('-', '')
            formatted_alias = re.sub(r'\s+', ' ', formatted_alias).strip()
            desired_alias = formatted_alias.replace(' ', '')

            #check if the number is a verified one
            is_verified = supabase.table("alias_verifieddigits").select("id").eq("theDigits", original_num).execute()

            # do this if result code is 0 
            encryptionObject = encryptNumber(original_num)
            the_encoding = encryptionObject['theCipher'] # number encrypted
            serialized_key = serials(encryptionObject['privateKeys'])

            alias_owner_email = request.session.get('user_email', None)
            alias_owner = supaProfile.objects.get(email=alias_owner_email)


            try:
                create_alias = aliases(
                    alias_owner=alias_owner,
                    num_cipher = the_encoding, 
                    email=alias_owner_email, 
                    desired_alias=desired_alias,
                    created_on=datetime.now()
                    )
                create_alias.save()
            except IntegrityError as e:
                messages.error(request, "duplicate alias, choose a unique alias")
                return redirect('createAliasForm')
            
            # -------------------------savingg the encryption in database---------------------
            locked = lockAndKey(
                keysOwner = alias_owner,
                designated_alias = desired_alias,
                keysAES = encryptionObject['rsaCipher'],
                keysPrivate = serialized_key,
                created_on=datetime.now()
            )
            locked.save()
            # --------------------------------------------------------------------------------

            response = HttpResponseRedirect(reverse("homePage"))
            response['Cache-Control'] = 'no-store, max-age=0'
            response['Pragma'] = 'no-cache'

            return response
    else:
        aliasCreation = aliasCreationForm()
    
    return render(request, "alias/createAlias.html", {
        "form": aliasCreation
    })
# -------------------------------------------retrieving the alias original-------------------
def sendForm(request):
    current_user_email = request.session.get("user_email", None)
    aliases = supabase.table("alias_aliases").select("desired_alias").eq("email", current_user_email).execute()
    my_aliases = aliases.data

    return render(request, "alias/sendtoalias.html", {
        "my_aliases": my_aliases
    })

def sendToAlias(request):
    if request.method == 'POST':
        senderAlias = request.POST["senderAlias"]
        recipientAlias = request.POST["recipientAlias"]
        amount = request.POST["amount"]

        #------------------------retrieve ciphers and decrypt--------------------------
        # WE ARE SENDING TO AN ALIAS FROM AN ALIAS
        encrypted_sender = supabase.table("alias_aliases").select("num_cipher").eq("desired_alias", senderAlias).execute()
        encrypted_receiver = supabase.table("alias_aliases").select("num_cipher").eq("desired_alias", recipientAlias).execute()

        # ---------------------retrieving the sending cipher-----------------------------------
        sender_cypher_hex = encrypted_sender.data[0]['num_cipher']
        sender_cypher = binascii.unhexlify(sender_cypher_hex.replace("\\x", ""))

        #-------retrieving the receiving cipher--------------------
        num_cypher_hex = encrypted_receiver.data[0]['num_cipher']
        num_cypher = binascii.unhexlify(num_cypher_hex.replace("\\x", ""))


        # ---------------------------retrieving the  cipher_rsa of receiver--------------------------------
        locksandkeys = supabase.table("alias_lockandkey").select("keysAES, keysPrivate").eq("designated_alias", recipientAlias).execute()
        aesKeys = binascii.unhexlify(locksandkeys.data[0]['keysAES'].replace("\\x", ""))

        # ----------------retrieving the cipher rsa of sender-----------------
        senderslocksandkeys = supabase.table("alias_lockandkey").select("keysAES, keysPrivate").eq("designated_alias", senderAlias).execute()
        sendersaesKeys = binascii.unhexlify(senderslocksandkeys.data[0]['keysAES'].replace("\\x", ""))

        # --------------------retrieving the serialized private key for receiver---------------------
        aserial = locksandkeys.data[0]['keysPrivate']
        aserial_binary = binascii.unhexlify(aserial.replace('\\x', ''))

        #-----------------retrieving serialized key for sender------
        senderserial = senderslocksandkeys.data[0]['keysPrivate']
        senderserial_binary = binascii.unhexlify(senderserial.replace('\\x', ''))
        # --------------------------------deserialize-----------------------------------------
        receiver_deserialized_key = deserials(aserial_binary)
        sender_deserialized_key = deserials(senderserial_binary)

        receivers_decryptObject = {
            "privateKeys": receiver_deserialized_key,
            "rsaCipher": aesKeys,
            "theCipher": num_cypher
        }

        senders_decryptObject = {
            "privateKeys": sender_deserialized_key,
            "rsaCipher": sendersaesKeys,
            "theCipher": sender_cypher
        }

        original_receiver = decryptNumber(receivers_decryptObject)
        original_sender = decryptNumber(senders_decryptObject)
        # here is where i will call the stkpush function
        # to send you will need the senders number to send the stkpush and the receivers alias to receive
        # at the moment, since the receivercan see the money, their part will be replaced by the till number
        # later that we will add the original receiver in place of the current till
        sending_record = stk_push(request, original_sender, recipientAlias)

        sent_record_data = json.loads(sending_record.content)
        sent_checkOutId = sent_record_data.get('CheckoutRequestID')
        transaction_identifier = sent_checkOutId

        transact = aliasTransactions(
            sender = senderAlias,
            receiver = recipientAlias,
            amount = amount,
            transaction_completed=False,
            transaction_identifier=transaction_identifier,
            sent_at=datetime.now()
        )

        transact.save()

        # store the uuid of the transaction in a ssession, use it to mark if it completed or not
        request.session['transaction_identifier'] = transaction_identifier

        response =  render(request, "alias/sendConfirmed.html",{
            "aliasName": recipientAlias,
            "amount": amount
            # i can use this in the upcoming page to send an email to recipient email including sender
        })

        response['Cache-Control'] = 'no-store, max-age=0'
        response['Pragma'] = 'no-chache'

        return response
# ------------------------------trnsaction done---------------------------------------
# we can also make this a background process, since we have the checkout id for the transaction
# we can check it even five minutes after, thats if the use doesn't click on this url
def transactionDone(request):
    checkoutId = request.session.get("transaction_identifier", None)
    queryresponse = query_stk_status(request, checkoutId)
    queryRespData = json.loads(queryresponse.content)
    print()
    print(queryRespData)
    print()

    try:
        responseCode = queryRespData.get("queryResponse")['ResultCode']
    except Exception as e:
        # if a user enters pin but phone is slow to respond. we can store the responsecode
        # and run it later
        print("exceptions")
        pass

    if responseCode == '0':
        supabase.table("alias_aliastransactions").update({"transaction_completed": True}).eq("transaction_identifier", checkoutId).execute()

        # else: redirect to the createalias/verify page with a message of failed - wipe it of the history

    return HttpResponseRedirect(reverse('homePage'))

# -------------------------------------------------------------------------------------
def interact(request, the_alias):
    sent_object = supabase.table("alias_aliastransactions").select("*").eq("sender", the_alias).eq("transaction_completed", True).execute()
    received_object = supabase.table("alias_aliastransactions").select("*").eq("receiver", the_alias).eq("transaction_completed", True).execute()
    sent = False
    received = False

    print("-------------money sent---------------")
    total_sent = supabase.table("alias_aliastransactions").select("amount").eq("sender", the_alias).eq("transaction_completed", True).execute()
    money_sent = total_sent.data
    total_money_sent = 0
    for amt in money_sent:
        total_money_sent += amt['amount']

    print("---------------money received-----------------------")
    total_received = supabase.table("alias_aliastransactions").select("amount").eq("receiver", the_alias).eq("transaction_completed", True).execute()
    money_received = total_received.data
    total_money_received = 0
    for amt in money_received:
        total_money_received += amt['amount']

    if len(sent_object.data) > 0:
        sent = sent_object.data

    if len(received_object.data) > 0:
        received = received_object.data

    return render(request, "alias/interact.html", {
        "alias": the_alias,
        "received": received,
        "sent": sent,
        "total_sent": total_money_sent,
        "total_received":total_money_received
    })

# ==================================================================================
#@login_required(login_url='index')
def inner(request):
    user_email = request.session.get('user_email', None)
    print(user_email)
    return render(request, "alias/in.html")

def signin(request):
    if request.method == "POST":
        # attempt signin
        email = request.POST["email"]
        password = request.POST["password"]
        try:
            user_session = supabase.auth.sign_in_with_password({"email": email, "password": password})
        except Exception as e:
            return render(request, "alias/login.html", {
                "message": "Invalid email and/or passsword"
            })
        print("===============================================")
        #print(user_session.user)
        request.session["user_email"] = user_session.user.email
        print("--------------------------------------------------")
        # create the new user in the django model
        try:
            profile_user = supaProfile.objects.get(supa_id=user_session.user.id)
        except supaProfile.DoesNotExist as e:
            profile_user = None

        if profile_user is None:
            user_profile = supaProfile(supa_id=user_session.user.id, email=user_session.user.email, first_login_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            user_profile.save()
        print("================================================")
        next_url = request.build_absolute_uri()
        print("-----------", next_url)

        """
        if next_url:
            return HttpResponseRedirect(next_url)
        else:
        """
        return HttpResponseRedirect(reverse("homePage"))   
    else:
        return render(request, "alias/login.html")

def signout(request):
    supabase.auth.sign_out()
    return HttpResponseRedirect(reverse("index"))

def signup(request):
    if request.method == "POST":
        email = request.POST["email"]
        # phone validation with mpesa req

        # confirms passwords match
        password = request.POST["password"]
        confirmation = request.POST["confirmation"]

        if len(password) < 6:
            return render(request, "alias/signup.html", {
                "message": "Passwords must be greater than 6 characters"
            })

        if password != confirmation:
            return render(request, "alias/signup.html", {
                "message": "Passwords don't match"
            })

        # attempt to create the user
        try:
            user = supabase.auth.sign_up({"email": email, "password": password})
        except IntegrityError:
            return render(request, "alias/signup.html", {
                "message": "ensure your credentials are unique and correct"
            })

        return HttpResponseRedirect(reverse("afterSignup"))
    else:
        return render(request, "alias/signup.html")

def afterSignup(request):
    response =  render(request, "alias/afterSignup.html")

    response['Cache-Control'] = 'no-store, max-age=0'
    response['Pragma'] = 'no-chache'

    return response

def emailConfirmed(request):
    response = render(request, "alias/emailConfirmed.html")

    response['Cache-Control'] = 'no-store, max-age=0'
    response['Pragma'] = 'no-cache'

    return response