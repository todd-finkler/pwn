#/usr/bin/env python

'''
This is a test to get the hang of getting to a piece of 
code using angr.
'''

import angr, monkeyhex, time

def main():
    before = time.time()

    # Load binary
    print ('[*] loading the binary')
    proj = angr.Project("babykey_level1_teaching")
    print (p.loader.all_objects)

    # Initial state
    state = proj.factory.entry_state()

    print (state.memory.load(0x40082f,8))

    return

if __name__ == "__main__":
    print (main())

