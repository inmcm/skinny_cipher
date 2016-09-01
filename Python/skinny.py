from __future__ import print_function
from collections import deque
from array import array
from operator import xor, add
from sys import exit

__author__ = 'inmcm'

class SkinnyCipher:

    # Sbox Constants
    sbox4 = array('B',[12, 6, 9, 0, 1, 10, 2, 11, 3, 8, 5, 13, 4, 14, 7, 15])
    sbox4_inv = array('B',[3, 4, 6, 8, 12, 10, 1, 14, 9, 2, 5, 7, 0, 11, 13, 15])

    sbox8 =  array('B',[0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a,
                        0x53, 0x73, 0x5b, 0x7b, 0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b,
                        0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b, 0xe5, 0xcc, 0xe8, 0xc1,
                        0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
                        0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8,
                        0x03, 0xb0, 0x0b, 0xb9, 0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d,
                        0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d, 0x62, 0x4a, 0x6c, 0x45,
                        0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
                        0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc,
                        0x04, 0xb4, 0x0d, 0xbd, 0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed,
                        0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd, 0x36, 0x8e, 0x38, 0x82,
                        0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
                        0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78,
                        0x50, 0x70, 0x59, 0x79, 0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab,
                        0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb, 0xe6, 0xce, 0xea, 0xc2,
                        0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
                        0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e,
                        0x97, 0x27, 0x9f, 0x2f, 0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f,
                        0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f, 0xa2, 0x18, 0xae, 0x16,
                        0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
                        0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe,
                        0xd7, 0xf7, 0xdf, 0xff])
    
    sbox8_inv = array('B',[0xac, 0xe8, 0x68, 0x3c, 0x6c, 0x38, 0xa8, 0xec, 0xaa, 0xae, 0x3a, 0x3e,
                           0x6a, 0x6e, 0xea, 0xee, 0xa6, 0xa3, 0x33, 0x36, 0x66, 0x63, 0xe3, 0xe6,
                           0xe1, 0xa4, 0x61, 0x34, 0x31, 0x64, 0xa1, 0xe4, 0x8d, 0xc9, 0x49, 0x1d,
                           0x4d, 0x19, 0x89, 0xcd, 0x8b, 0x8f, 0x1b, 0x1f, 0x4b, 0x4f, 0xcb, 0xcf,
                           0x85, 0xc0, 0x40, 0x15, 0x45, 0x10, 0x80, 0xc5, 0x82, 0x87, 0x12, 0x17,
                           0x42, 0x47, 0xc2, 0xc7, 0x96, 0x93, 0x03, 0x06, 0x56, 0x53, 0xd3, 0xd6,
                           0xd1, 0x94, 0x51, 0x04, 0x01, 0x54, 0x91, 0xd4, 0x9c, 0xd8, 0x58, 0x0c,
                           0x5c, 0x08, 0x98, 0xdc, 0x9a, 0x9e, 0x0a, 0x0e, 0x5a, 0x5e, 0xda, 0xde,
                           0x95, 0xd0, 0x50, 0x05, 0x55, 0x00, 0x90, 0xd5, 0x92, 0x97, 0x02, 0x07,
                           0x52, 0x57, 0xd2, 0xd7, 0x9d, 0xd9, 0x59, 0x0d, 0x5d, 0x09, 0x99, 0xdd,
                           0x9b, 0x9f, 0x0b, 0x0f, 0x5b, 0x5f, 0xdb, 0xdf, 0x16, 0x13, 0x83, 0x86,
                           0x46, 0x43, 0xc3, 0xc6, 0x41, 0x14, 0xc1, 0x84, 0x11, 0x44, 0x81, 0xc4,
                           0x1c, 0x48, 0xc8, 0x8c, 0x4c, 0x18, 0x88, 0xcc, 0x1a, 0x1e, 0x8a, 0x8e,
                           0x4a, 0x4e, 0xca, 0xce, 0x35, 0x60, 0xe0, 0xa5, 0x65, 0x30, 0xa0, 0xe5,
                           0x32, 0x37, 0xa2, 0xa7, 0x62, 0x67, 0xe2, 0xe7, 0x3d, 0x69, 0xe9, 0xad,
                           0x6d, 0x39, 0xa9, 0xed, 0x3b, 0x3f, 0xab, 0xaf, 0x6b, 0x6f, 0xeb, 0xef,
                           0x26, 0x23, 0xb3, 0xb6, 0x76, 0x73, 0xf3, 0xf6, 0x71, 0x24, 0xf1, 0xb4,
                           0x21, 0x74, 0xb1, 0xf4, 0x2c, 0x78, 0xf8, 0xbc, 0x7c, 0x28, 0xb8, 0xfc,
                           0x2a, 0x2e, 0xba, 0xbe, 0x7a, 0x7e, 0xfa, 0xfe, 0x25, 0x70, 0xf0, 0xb5,
                           0x75, 0x20, 0xb0, 0xf5, 0x22, 0x27, 0xb2, 0xb7, 0x72, 0x77, 0xf2, 0xf7,
                           0x2d, 0x79, 0xf9, 0xbd, 0x7d, 0x29, 0xb9, 0xfd, 0x2b, 0x2f, 0xbb, 0xbf,
                           0x7b, 0x7f, 0xfb, 0xff])
    
    round_constants = array('B',[0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 
                            0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
		                    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
                            0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
                            0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
                            0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a, 0x15, 0x2a, 0x14, 0x28,
		                    0x10, 0x20])

    # valid cipher configurations stored:
    # block_size:{key_size: number_rounds}
    __valid_setups = {64: {64: 32, 128: 36, 192: 40},
                      128: {128: 40, 256: 48, 384: 56}}

    __valid_modes = ['ECB', 'CTR', 'CBC', 'PCBC', 'CFB', 'OFB']
    
    def int_to_state(self, valid_int):
        byte_state = []
        for x in range(4):
            shift_limit = self.block_size - self.row_size
            shift_val = shift_limit - (self.row_size*x) 
            word = (valid_int >> shift_val)  & (2**self.row_size -1)
            line_array = array('B')
            for y in range(4):
                line_array.append(word >> ((self.row_size - self.s_val) - (y*self.s_val)) & self.cell_size)
            byte_state.append(line_array)
        return byte_state

    def state_to_int(self, byte_array_state):
        state_int = 0
        for row in byte_array_state:                                                                                                                                                       
            for cell in row:                                                                                                                                                
                state_int <<= self.s_val                                                                                                                                                    
                state_int += cell
        return state_int

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

        # Determine Cell Bit Size
        self.s_val = self.block_size >> 4
        
        # Caclulate Tweakkey type based off ratio of key size and block size
        self.tweak_size = self.key_size // self.block_size

        self.row_size = self.s_val*4
        self.cell_size = (2**self.s_val -1)
        self.block_mask = ((2 ** self.block_size) - 1)
        
        # Parse the given iv and truncate it to the block length
        try:
            iv_int = init & self.block_mask 
            self.iv = self.int_to_state(iv_int)
        except (ValueError, TypeError):
            print('Invalid IV Value!')
            print('Please Provide IV as int')
            raise

        # Parse the given Counter and truncate it to the block length
        try:
            self.counter = (iv_int + counter) & self.block_mask
        except (ValueError, TypeError):
            print('Invalid Counter Value!')
            print('Please Provide Counter as int')
            raise

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
        key_state = []
        for z in range(self.tweak_size):
            sub_key = self.key >> ((self.key_size - self.block_size) - (z * self.block_size))
            tweakkey = self.int_to_state(sub_key)
            key_state.append(tweakkey)
        
        # Pre-compile key schedule
        # Generate first round key from base input key
        round_key_xor = [key_state[0][0], key_state[0][1]]
        for twky in range(1, self.tweak_size):
            round_key_xor[0] = array('B', map(xor,round_key_xor[0],key_state[twky][0]))
            round_key_xor[1] =  array('B', map(xor,round_key_xor[1],key_state[twky][1]))

        self.key_schedule = [round_key_xor]
        
        # Generate remaining round keys
        for x in range(self.rounds):
            round_key_xor = [array('B',[0,0,0,0]), array('B',[0,0,0,0])]
            for y, twky in enumerate(key_state):

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

            self.key_schedule.append([round_key_xor[0], round_key_xor[1]])
        

    def encrypt(self, plaintext):
        
        try:
            pt_int = plaintext & self.block_mask
            plaintext_state = self.int_to_state(pt_int)
        except (ValueError, TypeError):
            print('Invalid Plaintext Value!')
            print('Please Provide Plaintext as int')
            raise
        
        # Prepare Based On Mode
        if self.mode == 'ECB':
            internal_state = plaintext_state
            internal_state = self.encrypt_function(internal_state)
            ciphertext = self.state_to_int(internal_state)
            return ciphertext
        
        elif self.mode == 'CTR':
            internal_state = self.int_to_state(self.counter)
            self.counter += 1
            internal_state = self.encrypt_function(internal_state)
            internal_state = [array('B',map(xor, plaintext_state[x], internal_state[x])) for x in range(4)]
            ciphertext = self.state_to_int(internal_state)
            return ciphertext

        elif self.mode == 'CBC':
            internal_state = [array('B',map(xor, plaintext_state[x], self.iv[x])) for x in range(4)]
            internal_state = self.encrypt_function(internal_state)
            self.iv = internal_state
            ciphertext = self.state_to_int(internal_state)
            return ciphertext

        elif self.mode == 'PCBC':
            internal_state = [array('B',map(xor, plaintext_state[x], self.iv[x])) for x in range(4)]
            internal_state = self.encrypt_function(internal_state)
            self.iv = [array('B',map(xor, plaintext_state[x], internal_state[x])) for x in range(4)]
            ciphertext = self.state_to_int(internal_state)
            return ciphertext

        elif self.mode == 'CFB':
            internal_state = self.encrypt_function(self.iv)
            internal_state = [array('B',map(xor, plaintext_state[x], internal_state[x])) for x in range(4)]
            self.iv = internal_state
            ciphertext = self.state_to_int(internal_state)
            return ciphertext

        elif self.mode == 'OFB':
            internal_state = self.encrypt_function(self.iv)
            self.iv = internal_state
            internal_state = [array('B',map(xor, plaintext_state[x], internal_state[x])) for x in range(4)]
            ciphertext = self.state_to_int(internal_state)
            return ciphertext

    def encrypt_function(self, internal_state):    
        
        # Run Encryption Steps For Appropriate Number of Rounds
        for round_num in range(self.rounds): 
            # S-box Layer
            if self.s_val == 4:
                sbox_state = [array('B',[self.sbox4[state_nib] for state_nib in state_row]) for state_row in internal_state]
            else:
                sbox_state = [array('B',[self.sbox8[state_byte] for state_byte in state_row]) for state_row in internal_state]
            
            internal_state = sbox_state

            # AddRoundConstant
            round_constant = self.round_constants[round_num]
            c0 = round_constant & 0xF
            c1 = round_constant >> 4
            c2 = 0x2
            internal_state[0][0] ^= c0
            internal_state[1][0] ^= c1    
            internal_state[2][0] ^= c2
            
            # AddTweakKey
            internal_state[0] = array('B', map(xor,internal_state[0],self.key_schedule[round_num][0])) 
            internal_state[1] = array('B', map(xor,internal_state[1],self.key_schedule[round_num][1]))

            # Shift Rows
            internal_state = [internal_state[0],
                            array('B',[internal_state[1][3],internal_state[1][0],internal_state[1][1],internal_state[1][2]]),
                            array('B',[internal_state[2][2],internal_state[2][3],internal_state[2][0],internal_state[2][1]]),   
                            array('B',[internal_state[3][1],internal_state[3][2],internal_state[3][3],internal_state[3][0]])]

            # MixColumns
            mix_1 = array('B', map(xor, internal_state[1], internal_state[2]))
            mix_2 = array('B', map(xor, internal_state[0], internal_state[2]))
            mix_3 = array('B', map(xor, internal_state[3], mix_2))

            internal_state = [mix_3, internal_state[0], mix_1, mix_2]
        return internal_state                

    def decrypt(self, ciphertext):
        
        try:
            ct_int = ciphertext & self.block_mask
            ciphertext_state = self.int_to_state(ct_int)
        except (ValueError, TypeError):
            print('Invalid Ciphertext Value!')
            print('Please Provide Ciphertext as int')
            raise

        # Prepare Based On Mode
        if self.mode == 'ECB':
            internal_state = ciphertext_state
            internal_state = self.decrypt_function(internal_state)
            plaintext = self.state_to_int(internal_state)
            return plaintext
        
        elif self.mode == 'CTR':
            internal_state = self.int_to_state(self.counter)
            self.counter += 1
            internal_state = self.encrypt_function(internal_state)
            internal_state = [array('B',map(xor, ciphertext_state[x], internal_state[x])) for x in range(4)]
            plaintext = self.state_to_int(internal_state)
            return plaintext

        elif self.mode == 'CBC':
            internal_state = self.decrypt_function(ciphertext_state)
            internal_state = [array('B',map(xor, internal_state[x], self.iv[x])) for x in range(4)]
            self.iv = ciphertext_state
            plaintext = self.state_to_int(internal_state)
            return plaintext

        elif self.mode == 'PCBC':
            internal_state = self.decrypt_function(ciphertext_state)
            internal_state = [array('B',map(xor, internal_state[x], self.iv[x])) for x in range(4)]
            self.iv = [array('B',map(xor, internal_state[x], ciphertext_state[x])) for x in range(4)]
            plaintext = self.state_to_int(internal_state)
            return plaintext

        elif self.mode == 'CFB':
            internal_state = self.encrypt_function(self.iv)
            internal_state = [array('B',map(xor, ciphertext_state[x], internal_state[x])) for x in range(4)]
            self.iv = ciphertext_state
            plaintext = self.state_to_int(internal_state)
            return plaintext

        elif self.mode == 'OFB':
            internal_state = self.encrypt_function(self.iv)
            self.iv = internal_state
            internal_state = [array('B',map(xor, ciphertext_state[x], internal_state[x])) for x in range(4)]
            plaintext = self.state_to_int(internal_state)
            return plaintext

    def decrypt_function(self, internal_state):

        for round_num in range(self.rounds -1, -1, -1):
            
            # Inverse Mix Columns
            mix_1 = array('B', map(xor, internal_state[0], internal_state[3]))
            mix_2 = array('B', map(xor, internal_state[1], internal_state[3]))
            mix_3 = array('B', map(xor, internal_state[2], mix_2))
            internal_state = [internal_state[1],mix_3, mix_2, mix_1]

            # Inverse Shift Rows
            internal_state = [internal_state[0],
                            array('B',[internal_state[1][1],internal_state[1][2],internal_state[1][3],internal_state[1][0]]),
                            array('B',[internal_state[2][2],internal_state[2][3],internal_state[2][0],internal_state[2][1]]),   
                            array('B',[internal_state[3][3],internal_state[3][0],internal_state[3][1],internal_state[3][2]])]

            # Inverse AddTweakKey
            internal_state[0] = array('B', map(xor,internal_state[0],self.key_schedule[round_num][0])) 
            internal_state[1] = array('B', map(xor,internal_state[1],self.key_schedule[round_num][1]))

            # Inverse AddRoundConstant
            round_constant = self.round_constants[round_num]
            c0 = round_constant & 0xF
            c1 = round_constant >> 4
            c2 = 0x2
            internal_state[0][0] ^= c0
            internal_state[1][0] ^= c1    
            internal_state[2][0] ^= c2

            # Inverse S-box Layer
            if self.s_val == 4:
                sbox_state = [array('B',[self.sbox4_inv[state_nib] for state_nib in state_row]) for state_row in internal_state]
            else:
                sbox_state = [array('B',[self.sbox8_inv[state_byte] for state_byte in state_row]) for state_row in internal_state]
                
            internal_state = sbox_state
        return internal_state   

if __name__ == "__main__":

    p = SkinnyCipher(0x17401096d712b2adcc0143a91dddb11c) 
    d = p.encrypt(0x5768de09fd1f69fd2a90de397270597a)
    w = p.decrypt(0x1de2136fb373e0522cc2351306e9f62d)
    print('Encrypt:', format(d, '#018X'))
    print('Decrypt:', format(w, '#018X'))