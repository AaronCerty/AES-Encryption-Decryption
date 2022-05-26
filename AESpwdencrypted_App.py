import sys, os, random, string
from collections import defaultdict
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64
def disMenu():
	print("=======================================================")
	print("||	Advanced Encryption Standard	 	     ||")
	print("=======================================================")
	print("\n================ AES APP Main Menu ====================")
	print("Choose your Option...")
	print("\n \t(E) Encrypt\n\t(D) Decrypt \n\t(Q) Quit")
	choose = input(">>> ")	
	choice = choose.lower()
	print("==========================================================")
	return choice
	

def prog(choice):
	if choice=='e' or choice=='d' or choice == 'q':
		if choice=='e':
			path = str(input("Please input the file name to Encrypt (e.g. data1.txt) :"))
			key = (input("Please input the 8 character Password to encrypt :"))
			
			if os.path.isfile(path): 
								
				content = readFile(path)
				fpath1, file_extension = os.path.splitext(path)
				
				cipher_msg = AES_Encrypt(content, key)
				output_file = fpath1 + "_AESencrypted.txt"
				rewrite(output_file, cipher_msg)
				print("Successfully Encrypted!")
				print("Encrypted file Name : " + output_file)

			choice =disMenu()
			prog(choice)
		elif choice=='d':
			opath = str(input("Please input the file name to decrypt (e.g. data1_AESencrypted.txt) :"))
			key = str(input("Please input the 8 character Password to decrypt :"))
			
			if not os.path.isfile(opath): 
				print('File %s not found.' % (opath))				
			else:
				content = readFile(opath)
				plaintxt_msg = AES_Decrypt(content, key)
				fpath11, file_extension = os.path.splitext(opath)
				output_file = fpath11 + "_AESdecrypted.txt"
				rewrite(output_file, plaintxt_msg)
				print("Successfully decrypted!")
				print("Decrypted file Name : " + output_file)
							
				
			choice=disMenu()
			prog(choice)
		elif choice=='q':
				print("Thank you for using the AES Cipher App!")
				sys.exit()
		else:
			print("Sorry! File does not exist, Please check the file!")
	else:
		print("Wrong option! Plese choose the right option...")
		#choice =disMenu()
		prog(choice)


def AES_Encrypt(source,key, encode=True):
    key = SHA256.new(key.encode('UTF-8')).digest() #fixed size của key
    iv_1 = Random.new().read(AES.block_size) #step này để initialize vector
    encryptor = AES.new(key, AES.MODE_CBC, iv_1) #encrypt mode
    padding = AES.block_size - len(source) % AES.block_size #padding of the last block
    source += chr(padding) * padding #source content + padding
    data = iv_1 + encryptor.encrypt(source.encode("utf-8")) #encryption
    return base64.b64encode(data).decode("latin-1") if encode else data #trả lại encrypt text

def AES_Decrypt( source, key, decode=True):
    try:
        if decode:
            source = base64.b64decode(source.encode("latin-1"))
        key = SHA256.new(key.encode('utf-8')).digest() #fixed size của key
        iv_1 = source[:AES.block_size] #step này để initialize vector
        decryptor = AES.new(key, AES.MODE_CBC, iv_1)
        data = decryptor.decrypt(source[AES.block_size:]) #decrypted data
        return bytes.decode(data).rstrip('\x02')
        
    except:
        print("Wrong padding")
		
def readFile(in_file):
    if not os.path.exists(in_file):
        print('File %s does not exits.' % (in_file))
        sys.exit()
    
    InFileObj = open(in_file, 'r')
    my_content = InFileObj.read()
    InFileObj.close()
    return my_content 

def rewrite(out_file, my_content):  
            
    OutFileObj = open(out_file, 'w+')
    OutFileObj.write(str(my_content))
    OutFileObj.close()


if __name__ == '__main__':
	choice =disMenu()
	
	
	if choice=='d' :
			
			prog(choice)
	elif choice=='e':
		#choice=disMenu()
		prog(choice)
	elif choice=='q':
		print("Bye Bye!")
		sys.exit()
	else:
		print("Not a single useful option has chosen!")
		sys.exit("Please restart the App again!")
	
