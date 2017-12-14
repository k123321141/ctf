import sys,os,string
import subprocess
import time
from subprocess import Popen, PIPE
from os.path import expanduser,join

"""
    Hard coding path
"""
home = expanduser("~")
pin = join(home,'lib','pin-3.5-97503-gac534ca30-gcc-linux','pin')
insc = join(home,'lib','pin-3.5-97503-gac534ca30-gcc-linux','source','tools','ManualExamples','obj-intel64','inscount0.so')

command = '%s -t %s -- ./break' % (pin,insc)
threshold = 50
def read_ints():
    with open('./inscount.out','r') as f:
        buf = f.read()
        count = int(buf[6:])
    return count

def try_str(s):

    p = subprocess.Popen(command.split(' '), stdout=PIPE, stderr=PIPE, stdin=PIPE)
    stdout, stderr = p.communicate(s)
    fail = stdout.find('Fails') >= 0
    p.wait()
    if fail:
        count = read_ints()
        return fail, count
    return fail, 0
def main():

    #alphabet = string.ascii_uppercase + string.ascii_lowercase + '1234567890' + ' -=[],./`~!@#$%^&*()_+{}:<>?'
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~1234567890 \t\n\r\x0b\x0c'
    t = len(alphabet)
    maximum = 0
    #s = 'CTF{PinADXAnInterfaceforCustomizableDebuggingwithDynamicInstrumentation'
    s = ''
    while True:
        correct_char = ''
        for idx,c in enumerate(alphabet):
            fail,count = try_str(s+c)
            #check

            if fail:
                print '(%3d/%3d) %2s %6d)' % (idx,t,c,count)
                #check
                if idx == 0:
                    maximum = count
                elif idx == 1 and (maximum - count) > threshold:
                    correct_char = c
                    break
                elif (count - maximum) > threshold:
                    correct_char = c
                    break
                maximum = max(maximum , count)
            else:
                print 'correct string : [%s]' % (s+c)
                return
        if correct_char == '':
            print 'char is not in alphabet'
            return
        s += correct_char
        print 'find correct char [%s]\nnew s : [%s]' % (correct_char, s) 




if __name__ == '__main__':
    main()
