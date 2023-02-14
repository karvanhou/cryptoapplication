"""
This application can encrypt and decrypt and get back-up of several files at once and
It is a better idea to zip the file(or several files) using the application and then encrypting the zip file(possible improvement).
If there was any difficulty with running the application please run it using Visual Studio Code.
In order to run this application, cryptography and PyCryptodome libraries are needed.
This application was developed with the help of the following websites:
    https://www.javatpoint.com/python-tkinter
    https://cryptography.io/en/latest/fernet/
    https://www.pycryptodome.org/src/protocol/kdf#pbkdf2
    https://www.youtube.com/channel/UC-5-tQOZwRPNWKMhwTCpwOA
    https://pythonguides.com/python-read-a-binary-file/
    https://www.geeksforgeeks.org/python-convert-string-to-bytes/
    https://www.geeksforgeeks.org/python-shutil-copy-method/
    https://www.youtube.com/c/Coreyms
    https://www.pycryptodome.org/src/examples#generate-public-key-and-private-key
    https://www.pycryptodome.org/src/examples#encrypt-data-with-rsa
    https://java2blog.com/iterate-through-files-in-directory-python/
    https://www.pycryptodome.org/src/public_key/rsa
    https://www.dlitz.net/software/pycrypto/api/2.6/Crypto.PublicKey.RSA-module.html
"""

import csv
import base64 #To encode and decode the data in which string is converted to byte and then encoded using base 64.
import os # provide a way of using operation system
import shutil # it offers copy to get back-up
import tkinter as tk #Tkinter GUI library
from tkinter import * # from tkinter import everything
from tkinter import filedialog #Tkinter feature to have access to files in your system.
import tkinter.ttk as ttk #Tkinter GUI library
import ntpath #provide os.path functionality.
from cryptography.fernet import Fernet,InvalidToken # it import fernet module and If the token is in any way invalid, this exception is raised(InvalidToken) 
# HAzmat allows to access to all kind of cryptographical primitives, such as HMACS
from cryptography.hazmat.primitives import hashes # The hashes value of an object
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # the key derivation function and 'PBKDF2HMAC' helps in deriving a key suitable for encryption.
from Crypto.PublicKey import RSA # generate,export,import public keys(here RSA)
from Crypto.Random import get_random_bytes # return a random byte string.
from Crypto.Cipher import AES, PKCS1_OAEP # from crypto library import AES and OAEP padding. it protects confidentiality.

class Window:
    #This Class connect all properties and featuers of ap
    def __init__(self):
        root3 = tk.Toplevel(root)# This means that root3 be the top window now.
        root3.title(username1 +"'s account")#the title of roots3 window.
        root3.geometry("700x600+500+50")#the position of root3 and its size. 
        self.canvas = tk.Canvas(root3,height=500,width=600,bg='#263d42')#Specify an environment(widgets) for our new window.
        self.canvas.pack()# it shows the widgets
        self.frame = Frame(root3, bg= 'white')
        self.frame.place(relwidth=.8, relheight=0.6, relx=0.1, rely=0.1)
        button=ttk.Button(root3, text="Add files", command=self.addfiles)
        #here I have defined the buttons I need
        button.pack(padx=5 , pady=5, side=tk.RIGHT)
        button=ttk.Button(root3, text="Add folder", command=self.add_folder)
        button.pack(padx=5 , pady=5, side=tk.RIGHT)
        button = ttk.Button(root3,text="Clear the screen",command=self.delete_data)
        button.pack(padx=5 , pady=5, side=tk.LEFT)
        button= ttk.Button(root3, text= "Backup",command = self.file_backup)
        button.pack(padx=5 , pady=5, side=tk.RIGHT)
        button= ttk.Button(root3, text= "AES(Fernet)",command = self.aes_fer_key)
        button.pack(padx=5 , pady=5, side=tk.RIGHT)
        button=ttk.Button(root3, text="RSA",command = self.rsa_keys)
        button.pack(padx=5 , pady=5, side=tk.RIGHT)
        tk.Label(self.frame,text="Add your files or folders here and choose one of the opetions",bg="gray").pack()
        self.files = []  #This file is the container for all files which are added using addfiles,add_folder function.
     
    def addfiles(self):
        #This function add files to self.files and show them in the frame using Tkinter GUI.
        for widget in self.frame.winfo_children():
            widget.destroy()
        types = [("all Files", " *.* "),("key Files", "*.key"),("encrypted Files", "*.encrypted"),("decrypted Files", "*.decrypted")]    
        filename = filedialog.askopenfilename(initialdir=".", title="Select Files ", filetypes=types)
        self.files.append(filename)
        
        for file in self.files:
            self.files = [x for x in self.files if x.strip()]
            tk.Label(self.frame,text=file,bg="gray").pack()
    def delete_data(self): # This function clean the container or pervious data 'self.files' and the frame.
        for widget in self.frame.winfo_children():
            widget.destroy()
        self.files.clear()    
    def add_folder(self):# This function helps to add directory or folders.
        for widget in self.frame.winfo_children():
            widget.destroy()
        filename = filedialog.askdirectory(initialdir=".", title="Select Files ")
        self.files.append(filename)
        for file in self.files:
            self.files = [x for x in self.files if x.strip()]
            tk.Label(self.frame,text=file,bg="gray").pack()


    
    def rsa_keys(self):#It shows the RSA window which is contain the encryption, decryption and the password option and it show the users public key which is already generated.
        global action1
        global pass_var1
        global root5
        root5 = tk.Toplevel(root)
        root5.geometry("700x600")
        root5.title("Options")
        tk.Label(root5,text="Actions",justify=tk.CENTER,padx=20).pack()
        action1= tk.IntVar()
        tk.Radiobutton(root5,text="Encrypt",value=1,variable=action1,padx=20).pack()
        tk.Radiobutton(root5,text='Decrypt',value=2,variable=action1,padx=20).pack()       
        Label(root5,text="Enter your passphrase:").pack()
        pass_var1 = StringVar()
        Entry (root5,textvariable=pass_var1,fg= 'green',width=40,show="*").pack()
        for path in os.listdir():
            if os.path.isfile(username1+'.receiver.pem'):
                Label(root5,text="Your Public key:").pack()
                T = Text(root5,wrap=WORD,width=40,height=18)
                T.pack()
                with open(username1+'.receiver.pem', 'rb') as f:#it shows a specific public key for every user.
                    T.insert(INSERT, f.read())
                    break        
                    
        ttk.Button(root5, text= "Close",width= 20,command=root5.destroy).pack(padx=5 , pady=5, side=tk.LEFT)
        ttk.Button(root5, text= "Start",width= 20,command=self.rsa).pack(padx=5 , pady=5, side=tk.RIGHT)

    def rsa(self):
        pass_phrase=pass_var1.get()# get the password from the user.
        byte_pass = pass_phrase.encode('utf-8')# it translates the password to binary string.
        des = filedialog.askdirectory(initialdir='.',title='select a path')# a feature in tkinter library asking the user for a directory to save the files.
        for path in os.listdir():#It checks if the user has private or public key already or nor in the application directory. 
            if not os.path.isfile(username1+'.private.pem'):#If not it create the keys for the user.
                key = RSA.generate(2048)#the key length 2048-bit or 256 bytes
                encrypted_key = key.export_key(passphrase=byte_pass, pkcs=8,
                                            protection="scryptAndAES128-CBC")#It creates the private key and encrypts with your password.
                public_key = key.publickey().export_key()#It creates the public key. 
                with open(username1+".private.pem",'wb') as key:
                    key.write(encrypted_key)
                with open(username1+".receiver.pem", "wb") as key:
                    key.write(public_key)
        if action1.get() == 1:
            recipient_key = RSA.import_key(open(username1+".receiver.pem").read())# It imports the public key.
            session_key = get_random_bytes(16)#It generates a 16-bit random value.
            cipher_rsa = PKCS1_OAEP.new(recipient_key)# It converts the public key using PKCS#1 OAEP padding to an RSA cipher.
            enc_session_key = cipher_rsa.encrypt(session_key)# It encrypts the session key with the public key.

            for line in self.files:
                source = (line.rstrip())
                with open(source, 'rb') as f:
                    data= f.read()
                cipher_aes = AES.new(session_key, AES.MODE_EAX)#It creates a new cipher within EAX Mode using the session_key(Randomly generated).
                ciphertext, tag = cipher_aes.encrypt_and_digest(data)#It does the encryption and authentication the data which is using hashing internally in one step. The output is a tuple. the first thing in the tuple is the encrypted data and the tag is the second item.
                tail = (ntpath.split(source))#explained
                file_Name = os.path.join(des, username1+tail[1]+".encrypted")#explained
                with open(file_Name, 'wb') as ef:#writing mode
                    [ef.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]#It writes the encrypted session key(256 bytes),the nonce(16 bytes) , the tag(16 bytes)and the cipher-text in a new file(in this case “file_Name”). 
            text = tk.Label(self.frame,text="Process Done!",fg='green')
            text.pack()
            root5.destroy()
            self.files.clear()    


        elif action1.get() == 2:
            try:#If this try throws an exception thi mean the password or the key is in any way invalid, show the user that the process is faild.(A try,except)
             private_key = RSA.import_key(open(username1+".private.pem").read(),byte_pass)# It imports the encrypted private key(PEM key) and the password from which the encryption key is derived.
             for line in self.files:
                    source = (line.rstrip())
                    with open(source, 'rb') as f: #reading mode
                        enc_session_key, nonce, tag, ciphertext = \
                        [ f.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]# After opening the file, It calculates the size of the private key in bytes(for example i bytes) so the first i bytes of the file is enc_session_key(here is 256 bytes),the second 16 bytes is nonce, the next 16 bytes is the tag and the rest of the data is the encrypted data.
                    
                        cipher_rsa = PKCS1_OAEP.new(private_key)# It converts the private key using PKCS#1 OAEP padding to an RSA cipher.
                        session_key = cipher_rsa.decrypt(enc_session_key)# It decrypts the enc_session_key using the cipher RSA to retrieve the session key(the symmetric key(AES) or the 16 bytes random key)to decrypt the data.
                        tail = (ntpath.split(source))
                        file_Name = os.path.join(des, username1+tail[1]+".decrypted")
                        with open(file_Name, 'wb') as ef:
                            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)#It puts the session_key,the nonce in AES cipher in EAX mode.
                            data = cipher_aes.decrypt_and_verify(ciphertext, tag)#It does two things here, the decryption of the data and the verification process using the tag.
                            ef.write(data)#it writes the data in a file.
            except:# if this part run, so the decryption failed.
                   self.failed_pass_rsa()
                   return 0    
            text = tk.Label(self.frame,text="Process Done!",fg='green')
            text.pack()
            root5.destroy()
            self.files.clear()
    def failed_pass_rsa(self):
        #This function acts when incorrect password or key is used in rsa for decryption file.
        root5.destroy()
        text = tk.Label(self.frame,text="Process failed!",fg='red')
        text.pack()
        self.files.clear()
    def failed_pass_fernet(self):
        #This function acts when incorrect password or key is used in fernet for decryption file.
        root4.destroy()
        text = tk.Label(self.frame,text="Process failed!",fg='red')
        text.pack()
        self.files.clear()

    def cry_aes(self): # This function encrypt and decrypt using a passphrase using AES(fernet).
            des = filedialog.askdirectory(initialdir='.',title='select a path') # this command ask the user its destination( the place want the data to be stored)
            pass_phrase=pass_var.get() # get the passphrase.
            byte_pass = pass_phrase.encode('utf-8') # Turn the passphrase to bits.
            with open(username1,"rb") as fs: #open the file which the salt is stored in and put it in the variable salt.
                salt = fs.readlines()[1]
            #here I have used a password in fernet so the password needs to be run through a key derivation function.
            #in this case 'PBKDF2HMAC'.
            # because AES-CBC(fernet) doesnot have an in-build authentication so fernet add 'HMAC' that uses SHA-256 for the this purpose.
            # so we driving our key using kdf.
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=1)# another deliberate vulnerability( the minimum amount of iterations is 1000 for better security).
            # Key is a 32-bit base 64 encoded encryption token using the passphrase.
            key = base64.urlsafe_b64encode(kdf.derive(byte_pass))
            if action.get() == 1:
                for line in self.files:
                    source = (line.rstrip())#removes any trailing characters because the link of the files are seperated with comma.
                    with open(source, 'rb') as f:
                        data= f.read()
                        f = Fernet(key) #we pass the key to fernet module.
                        encrypted_file = f.encrypt(data) #the decryption process.
                    tail = (ntpath.split(source)) #provide source path(It extract the name of the original file so after encryption we use it agian for the name of the encryption file)
                    file_Name = os.path.join(des, username1+tail[1]+".encrypted")
                    with open(file_Name, 'wb') as ef:
                        ef.write(encrypted_file)
                text = tk.Label(self.frame,text="Process Done!",fg='green')
                text.pack()
                root4.destroy()
                self.files.clear()
            elif action.get() == 2:
                for line in self.files:
                    source = (line.rstrip())
                    with open(source, 'rb') as f:
                        data= f.read()
                        f = Fernet(key)
                        try:
                            decrypted_file = f.decrypt(data)
                        except InvalidToken:# If the token is in any way invalid during decrypting, show the user that the process is faild.
                            self.failed_pass_fernet()
                            return 0
                    tail = (ntpath.split(source))
                    file_Name = os.path.join(des,tail[1]+".decrypted")
                    with open(file_Name, 'wb') as df:
                     df.write(decrypted_file)
                text = tk.Label(self.frame,text="Process Done!",fg='green')
                text.pack()
                root4.destroy()
    def file_backup(self):
        # this function helps to get back-up of files and folder using a package named 'shutil'.
            des = filedialog.askdirectory(initialdir='.',title='select a path')
            for line in self.files:
                source = line.rstrip()
                if os.path.isdir(source): # when we want to get back-up a folder which contains files and folders. and do it in a recursive way.
                    shutil.copytree(source,des,symlinks=False,ignore=None,copy_function=shutil.copy2,ignore_dangling_symlinks=False,dirs_exist_ok=True)
                else: # when we want to back-up a files
                    shutil.copy2(source,des)
            text = tk.Label(self.frame,text="Process Done!",fg='green')
            text.pack()
            self.files.clear()  
    def aes_fer_key(self):
        # This function displays this options(encrytion,decryption,using passphrase)
        # It extract a salt for every user who are registered and save it for next use and decryption(salt required).
        global action # the actions of encryption(1)or decryption(2).
        global pass_var # globalise the pass-phrase to encrypt the data.
        global root4 # make the window 4 global so I can use it in other functions(cry_aes fun)
        root4 = tk.Toplevel(root)# make the window 4 the top window
        root4.geometry("400x250") # the witdth and heights of window 4.
        root4.title("Options") #the title of window 4
        tk.Label(root4,text="Actions",justify=tk.CENTER,padx=20).pack() # attach the lable 'actions' to window 4.
        action= tk.IntVar() # the values of action is integers.
        # defining two radio buttons for the options of encryption and decryption.
        tk.Radiobutton(root4,text="Encrypt",value=1,variable=action,padx=20).pack()
        tk.Radiobutton(root4,text='Decrypt',value=2,variable=action,padx=20).pack()
        # This command will open the file that the data of user is save and if the user doesnot have a salt, so the 'os.urandom' offer one and write it in the file. 
        with open(username1,'rb+') as fk:
            if len(fk.readlines()) < 2 :
                # salt or initialazaion vector(unique)is generated using this. we create random 16bit using OS.
                # salt = os.urandom(16)
                salt =b'salt'# The deliberate vulnerability I have included in the application.
                fk.write(salt)# save it in order to derive the same key from the password in the next use and ecryption. 
        pass_var = StringVar()# passphrase will be defined as a string and and an input will be defined to get it.     
        Label(root4,text="Enter your passphrase:").pack()# importing the passphrase
        Entry (root4,textvariable=pass_var,fg= 'green',width=40,show="*").pack()
        # defining two buttons to start the encryption or decryption process or close the window 4.
        ttk.Button(root4, text= "Close",width= 20,command=root4.destroy).pack(padx=5 , pady=5, side=tk.LEFT)
        ttk.Button(root4, text= "Start",width= 20,command=self.cry_aes).pack(padx=5 , pady=5, side=tk.RIGHT)



def login_verify():
    #After registration this function helps the user to enter the main area of the app and check if the user and password is valid.
    global username1
    username1 = username_verify.get()
    password1 = password_verify.get()
    username_entry1.delete(0, END)
    password_entry1.delete(0, END)
    list_of_files = os.listdir()
    if username1  in list_of_files:
        file1 = open(username1, 'r')
        verify = file1.read().splitlines()
        if password1 in verify:
            root2.destroy()
            Window() # after authentication was valid the user will be direct to the class of window.
        else:
            Label(root2, text="Password is not correct", fg='green',).pack()
    else:
        Label(root2, text="User is not found!", fg='green',).pack()            
def login():
    #This function is a loging window, allowing users to enter their user and password
    global root2
    global username_verify
    global password_verify
    global username_entry1
    global password_entry1
    root2 = Toplevel(root)
    root2.title('Login')
    root2.geometry('400x500')
    Label(root2,text="Please enter your details to login").pack()
    Label(root2,text=" ").pack()
    username_verify = StringVar()
    password_verify = StringVar()
    Label(root2,text="Username *").pack()
    username_entry1 = Entry (root2, textvariable= username_verify)
    username_entry1.pack()
    Label(root2,text="Password *").pack()
    password_entry1 = Entry (root2, textvariable= password_verify, show="*")
    password_entry1.pack()
    Label(root2,text=" ").pack()
    Button(root2, text= 'Confirm', width='10', height='2', command= login_verify).pack()
def register():
    # This function get data(a user and password) allowing them to use the app. 
    global root1
    root1 = Toplevel(root)
    root1.title("Register")
    root1.geometry("500x400")
    global username
    global password
    global  username_entry
    global password_entry
    username = StringVar()
    password = StringVar()
    Label(root1,text="Please enter your details").pack()
    Label(root1,text=" ").pack()
    Label(root1,text="Username *").pack()
    username_entry = Entry(root1,textvariable = username)
    username_entry.pack()
    Label(root1,text="Password *").pack()
    password_entry = Entry(root1,textvariable = password, show="*")
    password_entry.pack()
    Label(root1,text=" ").pack()
    Button(root1, text="Register", width="10", height="2",command= register_user).pack()
    

def register_user():
     # This function get data from the 'register()' function and save it in the dirctory of the application and let them access to the app's features and next uses.
    username_info = username.get()
    password_info = password.get()
    if username_info in os.listdir(os.getcwd()):
        Label(root1, text="You already registred.", fg='green',).pack()
    elif username_info =='':
        Label(root1, text="Username field must not be emptry", fg='green',).pack()
    elif password_info == '':
                Label(root1, text="Password field must not be emptry", fg='green',).pack()
    else:    
        with open(username_info,'w',newline='') as new_user:
            writer = csv.writer(new_user, delimiter='\n',quoting=csv.QUOTE_NONE)
            writer.writerow([password_info])  

        username_entry.delete(0, END)
        password_entry.delete(0, END)
        Label(root1, text="Registration Sucess", fg='green',).pack()

# Here I have used Tkinter to give the user a Graphical user interfaces experience and it is pre-installed on python.
# Here I defined first page and how to be look like when the app is ran.
root = tk.Tk()# helps to display the window of app
root.title("Cryptography and back-up application")
root.geometry("320x400")
Label(text="Encryption with RSA, AES and back-up data using python", bg="gray", width="300", height="2").pack()
Label(text="").pack()
#I defined two buttons for the purpose of login and registration 
Button(text= "Login",width="30", height="2",command=login ).pack()
Label(text="").pack()
Button(text= "Register",width="30", height="2", command=register).pack()
root.mainloop() # This helps to start running GUI application