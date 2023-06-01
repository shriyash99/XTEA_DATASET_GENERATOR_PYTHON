from xtea_master.xtea import *
import os, os.path, random
import pandas as pd
from datetime import datetime


class P_C():

    def __init__(self):
        max64 = (2 ** 64) - 1
        print("Enter which round you want to capture [1-64]:")
        num_round = int(input())
        if num_round < 1 or num_round > 64:
            print("Invalid round...")
            return -1
        # no_of_encryptions = 0
        # encryption_time = 0.0
        print("\033[1;32mEncryption Started\033[0m")
        current_datetime = datetime.now()
        current_date_time = current_datetime.strftime("%d_%m_%Y-%H_%M_%S")
        data_file = open("dataset-" + current_date_time + ".csv", "w")
        data_file.write("ct_0,ct_1,ct_2,ct_3,ct_4,ct_5,ct_6,ct_7,ct_8,ct_9,ct_10,ct_11,ct_12,ct_13,ct_14,ct_15,ct_16,ct_17,ct_18,ct_19,ct_20,ct_21,ct_22,ct_23,ct_24,ct_25,ct_26,ct_27,ct_28,ct_29,ct_30,ct_31,ct_32,ct_33,ct_34,ct_35,ct_36,ct_37,ct_38,ct_39,ct_40,ct_41,ct_42,ct_43,ct_44,ct_45,ct_46,ct_47,ct_48,ct_49,ct_50,ct_51,ct_52,ct_53,ct_54,ct_55,ct_56,ct_57,ct_58,ct_59,ct_60,ct_61,ct_62,ct_63,ct2_0,ct2_1,ct2_2,ct2_3,ct2_4,ct2_5,ct2_6,ct2_7,ct2_8,ct2_9,ct2_10,ct2_11,ct2_12,ct2_13,ct2_14,ct2_15,ct2_16,ct2_17,ct2_18,ct2_19,ct2_20,ct2_21,ct2_22,ct2_23,ct2_24,ct2_25,ct2_26,ct2_27,ct2_28,ct2_29,ct2_30,ct2_31,ct2_32,ct2_33,ct2_34,ct2_35,ct2_36,ct2_37,ct2_38,ct2_39,ct2_40,ct2_41,ct2_42,ct2_43,ct2_44,ct2_45,ct2_46,ct2_47,ct2_48,ct2_49,ct2_50,ct2_51,ct2_52,ct2_53,ct2_54,ct2_55,ct2_56,ct2_57,ct2_58,ct2_59,ct2_60,ct2_61,ct2_62,ct2_63,label\n")
        path_keys = "key_files/"

        label = pd.read_csv("label.csv", header=None)

        value = 0
        for key_files in [path_keys + f for f in os.listdir(path_keys) if os.path.isfile(os.path.join(path_keys, f))]:
            with open(key_files, "rb") as key_file:
                while(True):
                    key = key_file.read(16)
                    len_key = len(key)
                    if not len_key:
                        break
                    elif len_key<16:
                        zero=0
                        key += zero.to_bytes(16-len_key, 'big')
                    key = key
                    path_plaintext= "plaintext_files/"
                    for plaintext_files in [path_plaintext+f for f in os.listdir(path_plaintext) if os.path.isfile(os.path.join(path_plaintext,f))]:
                        #print("\033[1;36mStarted\033[0m for Plaintext File : "+plaintext_files)
                        with open(plaintext_files, "rb") as plaintext_file:
                            while(True):
                                plaintext = plaintext_file.read(8)
                                len_pt = len(plaintext)
                                if not len_pt:
                                    break
                                elif len_pt < 8:
                                    zero = 0
                                    plaintext += zero.to_bytes(8-len_pt, 'big')
                                plaintext = plaintext
                                y = label.iloc[value][0]
                                if y == 1:
                                    enc = new(key, mode=1, rounds=num_round)
                                    ciphertext = enc.encrypt(plaintext)
                                    delta = 251658240
                                    delta = str(bin(delta).replace("0b", "")).zfill(64)
                                    delta = int(delta, 2).to_bytes((len(delta) + 7) // 8, byteorder='big')
                                    plaintext = bytes([_a ^ _b for _a, _b in zip(plaintext, delta)])
                                    ciphertext2 = enc.encrypt(plaintext)
                                else:
                                    enc = new(key, mode=1, rounds=num_round)
                                    ciphertext = enc.encrypt(plaintext)
                                    p2 = random.randint(0, 18446744073709551615)
                                    p2 = str(bin(p2).replace("0b", "")).zfill(64)

                                    ciphertext2 = enc.encrypt(int(p2, 2).to_bytes((len(p2) + 7) // 8, byteorder='big'))
                                value += 1
                                # encryption_time += time.time()-starttime
                                # no_of_encryptions += 1
                                x = ""
                                cipher_bin = bin(int.from_bytes(ciphertext,'big'))[2:].zfill(64)
                                for i in range(64):
                                    x += str(cipher_bin[i]) + ","
                                cipher_bin2 = bin(int.from_bytes(ciphertext2,'big'))[2:].zfill(64)
                                for i in range(64):
                                    x += str(cipher_bin2[i]) + ","
                                x += str(y) + "\n"
                                data_file.write(x)
                        # print("\033[1;32mFinished\033[0m for Plaintext File : "+plaintext_files)
            # print("\033[1;32mFinished\033[0m for Key File : "+key_files)
        data_file.close()
        print("\033[1;32mEncryption Finished\033[0m")
        # timefile = open("time.txt","w")
        # timefile.write("Total Encryptions made : "+str(no_of_encryptions)+"\nTotal Encryption Time : "+str(encryption_time)+" Seconds"+"\nAverage Encryption Time : "+str(encryption_time/no_of_encryptions)+" Seconds")
        # timefile.close()

if __name__ == '__main__':
    P_C()