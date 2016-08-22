from __future__ import print_function
from collections import deque
from array import array
from operator import xor
from sys import exit

__author__ = 'inmcm'

def ary_to_str(byte_array, nibbles):  # Can print rows
    frmt_str = '0' + str(nibbles) + 'X'
    return ''.join([format(x,frmt_str) for x in byte_array])

def kst_to_str(list_of_byte_arrays, nibbles):  # Can print whole key states
    frmt_str = '0' + str(nibbles) + 'X'
    return '0X' + ''.join([''.join([format(x,frmt_str) for x in w]) for w in list_of_byte_arrays])

class SkinnyCipher:

    # Sbox Constants
    sbox = array('B',[12, 6, 9, 0, 1, 10, 2, 11, 3, 8, 5, 13, 4, 14, 7, 15])
    sbox_inv = array('B',[3, 4, 6, 8, 12, 10, 1, 14, 9, 2, 5, 7, 0, 11, 13, 15])

    # valid cipher configurations stored:
    # block_size:{key_size: number_rounds}
    __valid_setups = {64: {64: 32, 128: 36, 192: 40},
                      128: {128: 40, 256: 48, 384: 56}}

    __valid_modes = ['ECB', 'CTR', 'CBC', 'PCBC', 'CFB', 'OFB']

    def __init__(self, key, key_size=128, block_size=128, mode='ECB', init=0, counter=0):
        """
        Initialize an instance of the Skinny block cipher.
        :param key: Int representation of the encryption key
        :param key_size: Int representing the encryption key in bits
        :param block_size: Int representing the block size in bits
        :param mode: String representing which cipher block mode the object should initialize with
        :param init: IV for CTR, CBC, PCBC, CFB, and OFB modes
        :param counter: Initial Counter value for CTR mode
        :return: None
        """

        # Setup block/word size
        try:
            self.possible_setups = self.__valid_setups[block_size]
            self.block_size = block_size
            self.word_size = self.block_size >> 1
        except KeyError:
            print('Invalid block size!')
            print('Please use one of the following block sizes:', [x for x in self.__valid_setups.keys()])
            raise

        # Setup Number of Rounds, and Key Size
        try:
            self.rounds = self.possible_setups[key_size]
            self.key_size = key_size
        except KeyError:
            print('Invalid key size for selected block size!!')
            print('Please use one of the following key sizes:', [x for x in self.possible_setups.keys()])
            raise

        # Determine Cell Size
        if self.block_size == 64:
            self.s_val = 4
        else: 
            self.s_val = 8
        
        # Caclulate Tweakkey type based off ratio of key size and block size
        self.tweak_size = self.key_size // self.block_size
        

        # Parse the given iv and truncate it to the block length
        # try:
        #     self.iv = init & ((2 ** self.block_size) - 1)
        #     self.iv_upper = self.iv >> self.word_size
        #     self.iv_lower = self.iv & self.mod_mask
        # except (ValueError, TypeError):
        #     print('Invalid IV Value!')
        #     print('Please Provide IV as int')
        #     raise

        # Parse the given Counter and truncate it to the block length
        # try:
        #     self.counter = counter & ((2 ** self.block_size) - 1)
        # except (ValueError, TypeError):
        #     print('Invalid Counter Value!')
        #     print('Please Provide Counter as int')
        #     raise

        # Check Cipher Mode
        try:
            position = self.__valid_modes.index(mode)
            self.mode = self.__valid_modes[position]
        except ValueError:
            print('Invalid cipher mode!')
            print('Please use one of the following block cipher modes:', self.__valid_modes)
            raise

        # Parse the given key and truncate it to the key length
        try:
            self.key = key & ((2 ** self.key_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Key Value!')
            print('Please Provide Key as int')
            raise

        

        # Initialize key state from input key value
        row_size = self.s_val*4
        cell_size = (2**self.s_val -1)
        key_state = []
        for z in range(self.tweak_size):
            tweakkey = []
            sub_key = self.key >> ((self.key_size - self.block_size) - (z * self.block_size))
            for x in range(4):
                shift_limit = self.block_size - row_size
                shift_val = shift_limit - (row_size*x) 
                word = (sub_key >> shift_val)  & (2**row_size -1)
                line_array = array('B')
                for y in range(4):
                    line_array.append(word >> ((row_size - self.s_val) - (y*self.s_val)) & cell_size)
                tweakkey.append(line_array)
            key_state.append(tweakkey)
            print('tweakkey',z,':',kst_to_str(tweakkey, self.s_val>>2))

        # print('Key:', key_state)
        # print(len(key_state))
        # Pre-compile key schedule
        
        
        

        # Generate first round key from base input key
        round_key_xor = [key_state[0][0], key_state[0][1]]
        for twky in range(1, self.tweak_size):
            round_key_xor[0] = array('B', map(xor,round_key_xor[0],key_state[twky][0]))
            round_key_xor[1] =  array('B', map(xor,round_key_xor[1],key_state[twky][1]))

        self.key_schedule = [round_key_xor]
        
        # Generate remaining round keys
        for x in range(self.rounds):
            print('Round:', x)
            round_key_xor = [array('B',[0,0,0,0]), array('B',[0,0,0,0])]
            for y, twky in enumerate(key_state):
                print('Current Key', y, 'State:', kst_to_str(twky, self.s_val>>2))
                # Perform Permutation Step
                modifed_key_rows = [array('B',[twky[2][1],twky[3][3],twky[2][0],twky[3][1]]), 
                                    array('B',[twky[2][2],twky[3][2],twky[3][0],twky[2][3]])]
                
                if y > 0:  # Perom LFSR step on higher tweakey components
                    lfsr_rows = []
                    for mod_row in modifed_key_rows:
                        lfsr_row = array('B', [])
                        for cell in mod_row:
                            if self.s_val == 4:
                                if y == 1:
                                    lfsr_row.append(((cell << 1) ^ ((cell >> 3)^(cell >> 2) & 1)) & 0xF)
                                else:
                                    lfsr_row.append(((cell >> 1) ^ ((cell << 3)^cell & 0x8)) & 0xF)
                            else:
                                if y == 1:
                                    lfsr_row.append(((cell << 1) ^ ((cell >> 7)^(cell >> 5) & 1)) & 0xFF)
                                else:
                                    lfsr_row.append(((cell >> 1) ^ ((cell << 7)^(cell << 1) & 0x80)) & 0xFF)
                
                        lfsr_rows.append(lfsr_row)
                    modifed_key_rows = lfsr_rows       
                
                # Store updated round key data
                round_key_xor[0] = array('B', map(xor,round_key_xor[0],modifed_key_rows[0]))
                round_key_xor[1] =  array('B', map(xor,round_key_xor[1],modifed_key_rows[1]))

                # Update key state 
                key_state[y] = [modifed_key_rows[0],
                                modifed_key_rows[1],
                                twky[0],
                                twky[1]]
            
            for d,p in enumerate(key_state): 
                frmt_str = '0' + str(self.s_val >> 2) + 'X'
                key_string ='0X' + ''.join([''.join([format(x,frmt_str) for x in w]) for w in p])
                # for w in p:
                #     q = ''.join([hex(x)[2:] for x in w])
                #     key_string += q
                print('Update Key:', x, 'TWKY:', d, key_string)

            self.key_schedule.append([round_key_xor[0], round_key_xor[1]])
        

    def encrypt_round_64(self, state, round_key):
        """
        Complete One Feistel Round
        :param x: Upper bits of current plaintext
        :param y: Lower bits of current plaintext
        :param k: Round Key
        :return: Upper and Lower ciphertext segments
        """

        print('Running Round:', round)
        # Do 4 Bit S-Box
        for x, state_word in enumerate(internal_state):
            for y, state_byte in enumerate(state_word):
                state_word[y] = sbox[state_byte]
            internal_state[x] = state_word

        print('After S Box:', internal_state)

        # AddRoundConstant
        round_constant = round_constants[round]
        print('Round Constant:', round_constant)
        c0 = round_constant & 0xF
        c1 = (round_constant >> 4) & 0x3
        c2 = 0x2
        internal_state[0][0] ^= c0
        internal_state[1][0] ^= c1    
        internal_state[2][0] ^= c2

        print('After AddRoundConstant:', internal_state)

        # AddTweakKey
        internal_state[0] = array('B', [internal_state[0][x] ^ key_state[0][x] for x in range(4)]) 
        internal_state[1] = array('B', [internal_state[1][x] ^ key_state[1][x] for x in range(4)])
        print('After Key XOR:', internal_state)

        

        # Shift Rows
        internal_state = [internal_state[0],
                        array('B',[internal_state[1][3],internal_state[1][0],internal_state[1][1],internal_state[1][2]]),
                        array('B',[internal_state[2][2],internal_state[2][3],internal_state[2][0],internal_state[2][1]]),   
                        array('B',[internal_state[3][1],internal_state[3][2],internal_state[3][3],internal_state[3][0]])]
        
        print('After ShiftRows:', internal_state)

        # MixColumns
        mix_1 = array('B', [internal_state[1][x] ^ internal_state[2][x] for x in range(4)])
        mix_2 = array('B', [internal_state[0][x] ^ internal_state[2][x] for x in range(4)])
        mix_3 = array('B', [internal_state[3][x] ^ mix_2[x] for x in range(4)])

        internal_state = [mix_3, internal_state[0], mix_1, mix_2]

        print('After MixColumns:', internal_state)

        return new_x, x

if __name__ == "__main__":

    d = [array('B', [175, 76, 1, 31]), array('B', [4, 138, 182, 46]), array('B', [195, 176, 61, 201]), array('B', [115, 136, 64, 219])]
    r = kst_to_str(d,2)
    print('Hello',r)

    p = SkinnyCipher(0x13ada9e39daf44cafc39cac5365d894cdab87554a200ca6a, 192, 64)    
    exit(-1)
    # Sbox Constants
    sbox = array('B',[12,6,9,0,1,10,2,11,3,8,5,13,4,14,7,15])
    sbox_inv = array('B',[3,4,6,8,12,10,1,14,9,2,5,7,0,11,13,15])

    # Round Constants
    round_constants = array('B',[0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 
                            0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
		                    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
                            0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
                            0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
                            0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a, 0x15, 0x2a, 0x14, 0x28,
		                    0x10, 0x20])
    # Test Vectors 
    # Block Size = 64, Key Size = 64
    test_vec_64_64 = [[0xb1b540d89ff9df70, 0x3e1c9d7d57844d8d, 0x1d29e6da4284a4ac],
                      [0x788ae30f0614c84a, 0x570463ff8f79fb26, 0x2af2af3c7267ca8c],
                      [0x67592647689e147e, 0xfe2e8afaf1eddd3e, 0xd1a0877fae18a816],
                      [0xa19578e5f0daf102, 0xd7ae29d457bb6700, 0x85a1e1395c4ef8c5],
                      [0x377cc345a669ecd8, 0x0323f685d848e0ca, 0xa1293461a78d49ab],
                      [0x71a7f5b510018857, 0xa4ac2fb27f44bff0, 0xf8475e5450548fb6]]
    # key = 0xb1b540d89ff9df70
    # plaintext =  0x3e1c9d7d57844d8d
    s = 4

    for test_vector in test_vec_64_64:

        key = test_vector[0]
        plaintext = test_vector[1]
        test_ciphertext = test_vector[2]

        internal_state = []
        for x in range(4):
            word = (plaintext >> 48 - (16*x)) & 0xFFFF
            line_array = array('B')
            for y in range(4):
                line_array.append(word >> (12 - (y*4)) & 0xF)
            internal_state.append(line_array)

        print('Plaintext:', internal_state)

        key_state = []
        for x in range(4):
            word = (key >> 48 - (16*x)) & 0xFFFF
            line_array = array('B')
            for y in range(4):
                line_array.append(word >> (12 - (y*4)) & 0xF)
            key_state.append(line_array)

        print('Key:', key_state)

        number_of_rounds = 32

        for round in range(number_of_rounds):
            print('Running Round:', round)
            # Do 4 Bit S-Box
            for x, state_word in enumerate(internal_state):
                for y, state_byte in enumerate(state_word):
                    state_word[y] = sbox[state_byte]
                internal_state[x] = state_word

            print('After S Box:', internal_state)

            # AddRoundConstant
            round_constant = round_constants[round]
            print('Round Constant:', round_constant)
            c0 = round_constant & 0xF
            c1 = (round_constant >> 4) & 0x3
            c2 = 0x2
            internal_state[0][0] ^= c0
            internal_state[1][0] ^= c1    
            internal_state[2][0] ^= c2

            print('After AddRoundConstant:', internal_state)

            # AddTweakKey
            internal_state[0] = array('B', [internal_state[0][x] ^ key_state[0][x] for x in range(4)]) 
            internal_state[1] = array('B', [internal_state[1][x] ^ key_state[1][x] for x in range(4)])
            print('After Key XOR:', internal_state)

            #Update Tweakkey
            key_state = [array('B',[key_state[2][1],key_state[3][3],key_state[2][0],key_state[3][1]]),
                        array('B',[key_state[2][2],key_state[3][2],key_state[3][0],key_state[2][3]]),
                        key_state[0],
                        key_state[1]]
            
            print('Update Key:', key_state)

            # Shift Rows
            internal_state = [internal_state[0],
                            array('B',[internal_state[1][3],internal_state[1][0],internal_state[1][1],internal_state[1][2]]),
                            array('B',[internal_state[2][2],internal_state[2][3],internal_state[2][0],internal_state[2][1]]),   
                            array('B',[internal_state[3][1],internal_state[3][2],internal_state[3][3],internal_state[3][0]])]
            
            print('After ShiftRows:', internal_state)

            # MixColumns
            mix_1 = array('B', [internal_state[1][x] ^ internal_state[2][x] for x in range(4)])
            mix_2 = array('B', [internal_state[0][x] ^ internal_state[2][x] for x in range(4)])
            mix_3 = array('B', [internal_state[3][x] ^ mix_2[x] for x in range(4)])

            internal_state = [mix_3, internal_state[0], mix_1, mix_2]

            print('After MixColumns:', internal_state)

            print('')
        
        ciphertext = 0
        for ct_word in internal_state:
            for ct_byte in ct_word:
                ciphertext <<= s
                ciphertext += ct_byte
                
        print('Final Ciphertext:', hex(ciphertext))
        if ciphertext == test_ciphertext:
            print('Success!')
        else:
            print('Failure')
            exit(1)
    print('DONE!!!!')
