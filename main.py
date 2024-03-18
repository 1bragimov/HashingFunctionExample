# import hashlib
#
# print(hashlib.algorithms_available)

import hashlib

# goes = ""
#
# hasing_s1 = hashlib.sha256(str(goes).encode("utf-8")).hexdigest()
# hasing_s2 = hashlib.sha384(str(goes).encode("utf-8")).hexdigest()
# hasing_s3 = hashlib.sha1(str(goes).encode("utf-8")).hexdigest()
# hasing_s4 = hashlib.sha224(str(goes).encode("utf-8")).hexdigest()
# hasing_s6 = hashlib.md5(str(goes).encode("utf-8")).hexdigest()
# hasing_s7 = hashlib.blake2b(str(goes).encode("utf-8")).hexdigest()
# hasing_s8 = hashlib.blake2s(str(goes).encode("utf-8")).hexdigest()
#
# print(hasing_s1)
# print(hasing_s2)
# print(hasing_s3)
# print(hasing_s4)
# print(hasing_s6)
# print(hasing_s7)
# print(hasing_s8)

##################################################################

# def hashings(data: str):
#     sha256 = hashlib.sha256(data.encode("utf-8"))
#     return sha256.hexdigest()
#
#
# print(hashings("@Email.adress"))


########################################################################################################################
########################################################################################################################
########################################################################################################################

# import hashlib
# import os
#
# matn = input("Txt kirit: ")
#
#
# def hash_function(matn):
#     hash = hashlib.sha256(matn.encode()).hexdigest()
#     print(hash)
#
#
# hash_function(matn)
#
#
# import hashlib
#
# print(hashlib.algorithms_available)
#
#
#
# import hashlib
#
# data = input("String malumot kirit: ")
#
# hasher = hashlib.sha256(str(data).encode('utf-8'))
# print(hasher.hexdigest())
#
#
# import hashlib
#
# data = "Mr.Dark"
#
# sha256 = hashlib.sha256(str(data).encode('utf-8'))
# sha384 = hashlib.sha384(str(data).encode('utf-8'))
# md5 = hashlib.md5(str(data).encode('utf-8'))
# blake2b = hashlib.blake2b(str(data).encode('utf-8'))
# sha1 = hashlib.sha1(str(data).encode('utf-8'))
#
# hash_list: list = [sha256, sha384, md5, blake2b, sha1]
# for i in hash_list:
#     print(i.hexdigest())
####################################################################################################################################################################################

# import hashlib
#
# def hash_func(data):
#
#     hashed_data = hashlib.sha256(data.encode()).hexdigest()
#     return hashed_data
#
#
# data = input("MukhammadziyoKhan2008 ")
#
#
# hashed_data = hash_func(data)
#
#
# print("hash", hashed_data)

##############################################################################################################################################################################

import hashlib

def hash_func(data):

    hashed_data = hashlib.sha256(data.encode()).hexdigest()
    return hashed_data


data = input("Mr.Dark: ")


hashed_data = hash_func(data)


with open("hash.txt", "w") as file:
    file.write(hashed_data)

print("Malumot tayyor!")


