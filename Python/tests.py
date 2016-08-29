import pytest
from skinny import SkinnyCipher

# Official Test Vectors
class TestOfficialTestVectors:
    """
    Official Test Vectors From the Original Paper
    "The SKINNY Family of Block Ciphers and its Low-Latency Variant MANTIS"
    """
    def test_skinny_64_64(self):
        test_vec_64_64 = [[0x788ae30f0614c84a, 0x570463ff8f79fb26, 0x2af2af3c7267ca8c],
                          [0xb1b540d89ff9df70, 0x3e1c9d7d57844d8d, 0x1d29e6da4284a4ac],
                          [0x67592647689e147e, 0xfe2e8afaf1eddd3e, 0xd1a0877fae18a816],
                          [0xa19578e5f0daf102, 0xd7ae29d457bb6700, 0x85a1e1395c4ef8c5],
                          [0x377cc345a669ecd8, 0x0323f685d848e0ca, 0xa1293461a78d49ab],
                          [0x71a7f5b510018857, 0xa4ac2fb27f44bff0, 0xf8475e5450548fb6],
                          [0x2ab57d5ff39f33a0, 0x34caa532a86869a6, 0x5b2e95545edf83c1],
                          [0x5ba0004ee8200b49, 0x95aee9cf8c669c3c, 0xdf2afe33d196e3d6],
                          [0xfa908b6c0ee91c7e, 0xb7a233901ef8b2cf, 0xf2a8289fedd38be3]]
        for test_vector in test_vec_64_64:
            test_key = test_vector[0]    
            test_plaintext = test_vector[1]
            test_ciphertext = test_vector[2]
            p = SkinnyCipher(test_key, 64, 64) 
            d = p.encrypt(test_plaintext)
            w = p.decrypt(test_ciphertext)
            assert d == test_ciphertext
            assert w == test_plaintext
                                  

    def test_skinny_64_128(self):
        test_vec_64_128 = [[0xee7418c16edf6ab991b125b20d28a57a,0x5d6f8605b4835657,0xcd0f24faaf2d82ea],
                           [0x8a7d9b6cb63efe8b4b71dfc6cb7dd463,0x7f5905ace2badc8e,0x61891a50ecce6391],
                           [0xb78b7e4f950ecb006d05b6915db71e5f,0x81a176c123e1884a,0x6c5304477b5c3d08],
                           [0xfd54e948e8fbb4bf0c9d3c0862e56f77,0x5570e988657c73ec,0xa05cb84289318053],
                           [0x32075f65946eb94c0afd85fa9e2f47b9,0xee95492c973bf1da,0xd9d14533fab3a39d],
                           [0x3a525de828670b68bd5b245d949f9993,0xc1d64c9722ee7dcf,0x002debb21cd8cf7f],
                           [0x2aa2e452c711b4dfd1c08511cc28f468,0xfe843a52b648f664,0x1db4a169340fd345],
                           [0x55056cd4bb830feb5b9a08974f7e92bd,0xa4bab34ccd666322,0x3a9eaa4f3330dd18],
                           [0x22bcfbf52c847161cffcdd6c98954fa1,0x7af409b23686415b,0xbf1a4873b960cb83]]
        for test_vector in test_vec_64_128:
            test_key = test_vector[0]    
            test_plaintext = test_vector[1]
            test_ciphertext = test_vector[2]
            p = SkinnyCipher(test_key, 128, 64) 
            d = p.encrypt(test_plaintext)
            w = p.decrypt(test_ciphertext)
            assert d == test_ciphertext
            assert w == test_plaintext

    def test_skinny_64_192(self):
        test_vec_64_192= [[0x13ada9e39daf44cafc39cac5365d894cdab87554a200ca6a, 0x22b35a0373ac23de, 0xd6f7dc775961e885],
                          [0x7dc6df1ab72637a27413a66999f10a7d9a0bbd43c04ca9f1, 0xd69bbe6ae0b4d04b, 0x0785bda68632d52e],
                          [0xd3868ff8a41e810ee5a181309c47770cad5ee908e65ac330, 0x2c2d5cef9eac7d94, 0x34f931ec9db8e092],
                          [0x92e9e03d841a89d2d64847978145dcda0796109b5737466a, 0x65c61b910bdc41df, 0x9e7e9d6ae078ecc1],
                          [0x2f0cb776e5f2fb4da32fb87a6e7b3dbb0950bc9dfd569dcb, 0xa232ecbb4dac5e25, 0xaa08e3a459e21559],
                          [0x545be745023497c32981588278c97f2b03859c4a487fd7a7, 0x70e2f3adc50c0cb0, 0xb6ecf3c011d1d731],
                          [0xe28552d15c220dd1595752a97863c31b096f3d79834744a3, 0x8265ff649b7afc2c, 0x2717bb5a2a5969b8],
                          [0xadc6c27cd936476969171d8aadd5fe03350e3cef9d701975, 0x1dedd798848ff3de, 0xa649d5bafb28407e],
                          [0x05b159faf643ff1e7d9c4ac98886ce50e1987a7e8cb54e75, 0xcfeea916b6ca236b, 0x25c9a7aa2e6bd2ad]]
        for test_vector in test_vec_64_192:
            test_key = test_vector[0]    
            test_plaintext = test_vector[1]
            test_ciphertext = test_vector[2]
            p = SkinnyCipher(test_key, 192, 64) 
            d = p.encrypt(test_plaintext)
            w = p.decrypt(test_ciphertext)
            assert d == test_ciphertext
            assert w == test_plaintext

    def test_skinny_128_128(self):
        test_vec_128_128 = [[0x5ba8c7572ac2df5e1b474a91441abbc3, 0x454dad3782d7ffeb9eadef35f6920eea, 0x1ebd234bf43850e0acd14cd4f49d8ac6],
                            [0x17401096d712b2adcc0143a91dddb11c, 0x5768de09fd1f69fd2a90de397270597a, 0x1de2136fb373e0522cc2351306e9f62d],
                            [0xf3dc232e4fb8a0c996911ac83a470826, 0xd59881aa04a232e592732cce7acdbc61, 0xe0b9fca59c71d8bfb7efc0ecd6321cda],
                            [0x1939e6030fd13396c3e954b0e1a94852, 0x594d8879d5583c25c90eda03acef0f24, 0x1ba3979d8be50f439a872a7e2b183e81],
                            [0xe4ba17a4eaf8ebc1f2b9013a6680d551, 0xa5867fe4a6ea24157900d38c51789d2e, 0xd119a4e56f1f547e408e635e398db64b],
                            [0x22da7bd818769176d4ee87ba6680115e, 0x4c30c94d9310f2405d11b6a479927b5f, 0x37b23f5b6e6cdbde56bea0b76314eea3],
                            [0x80471a366e4417d45dece682a218d186, 0x98ff3fe52c799ce293cb5e02b06bd6fb, 0x829edb4c5ae0b612dcff33b30a3773b9],
                            [0x2723caa8106d7e19d3328085dfdb3522, 0x119fd2294939c3e2fa2843243019831a, 0x8254febfe26ec0ac7f559bdaae54ab45],
                            [0x34be360680092cd2d3324dbdf46a7313, 0x6059a0703482b6d3dc9e1ba1fc27ea22, 0xb3f5e0a63e2b76802ca49cc90068d0b1]]

        for test_vector in test_vec_128_128:
            test_key = test_vector[0]    
            test_plaintext = test_vector[1]
            test_ciphertext = test_vector[2]
            p = SkinnyCipher(test_key, 128, 128) 
            d = p.encrypt(test_plaintext)
            w = p.decrypt(test_ciphertext)
            assert d == test_ciphertext
            assert w == test_plaintext

    def test_skinny_128_256(self):
        test_vec_128_256 = [[0x313f3644b3032a304c73dab9fe0d4e4ac5402928fb0a26dfdc546a7ae3959982, 0xec73ff4c6d3119b1cbe7e7dec8e8b5ac, 0xb8bd0fbb233ad5db858ec1a5eacc0dea],
                            [0x1704e0d35c3c0494d63728160eb959a429840444144a47bda470d6d579dc7ee7, 0x19246784513d88719e4bd305159722b6, 0x74fce2a773cc0e7ff00dc6f308d96553],
                            [0x9758cddcb8763645a76051bf007a72dc6b85d2bd8723e911814bb078ecef2bb7, 0x4a32cfb76c27c1e308008e1323a896a7, 0xbeafb4516db43bdf68cdc439c86650a3],
                            [0x00cda9b013ecdd1cfc912c1f6acbc0effe1804fede4a4efe2f8450c12ac3dc17, 0xe49c178ceef9e1353128c62131df9e79, 0xbe6a57ac45cf769e49757fe22cf1e9ff],
                            [0x907c4f9ce17090d99b4998cd53147424c737213a9539e15030ff0477b19ac8ce, 0x5479a1c49f4eaadc868493cdee10207e, 0x3ba7eea6ac88874bcdb1b8495fe5078a],
                            [0x7d08d2eb8f0c4b14dfc5ad010bbb4e48d6ec50192bb529c08454c24d7a009b5c, 0xdb07581d02cd2a403f4582fa2c518f10, 0xeae3fee105cff1cacd16bebd668dd3de],
                            [0x8b69e99aaee980cc6bbeb4adcb9a813e0bbe7d79bce6501023cc01c0feb374bf, 0x999c985ff9aaa9ec48445ac63088b5a6, 0x3c8bca93c113f2e7fe2b2f283efbc4bf],
                            [0x4318f63a4fe1a6f3a84092ad21cb8d1b6eeb4a74ac513c4e2bfa6ef0d81fa52c, 0xfca2f3332cf43769fb68831c40a0f3b7, 0x71550a0dc6b3cc20e69e3536a492de9e],
                            [0xbaf5fba20df22292cc6885878da88f229b8b97cc2ab1ae78da0085803a36a3dd, 0x6f04ebeaaff94da8057f00721c10b2cb, 0x8c6d4dd8fbeda9ca36dea456b4458f1a]]

        for test_vector in test_vec_128_256:
            test_key = test_vector[0]    
            test_plaintext = test_vector[1]
            test_ciphertext = test_vector[2]
            p = SkinnyCipher(test_key, 256, 128) 
            d = p.encrypt(test_plaintext)
            w = p.decrypt(test_ciphertext)
            assert d == test_ciphertext
            assert w == test_plaintext


    def test_skinny_128_384(self):
        test_vec_128_384 = [[0xae3b626b2dbb1761ce59321e11132c8e3ed0ef4d672f7a4705e7ffce8f0abda2a6568199bae1416919631673a12b71ba, 0x729b1721f8c8f839071ab101061140dd, 0x3bdec80af0e83036cfd69c994636d542],
                            [0x7fa1b1a61544e4c1ae466d6743988c045bc03be48ab90f1db0061605861c48459db2f4748e1796530c69fd4ea09ffdbc, 0x26e39b9961b69afc2d8b9f4967483265, 0x8d47b03a01d95b49309692fcd63838b4],
                            [0xb3c0db7aa5e4a16c542cf0c1f243d743391216cda8e0d03fb105309fed48236289a727482350d5dd2a92f37de5c7d60b, 0x81b7d5992db1e077fb158820c25429b9, 0x24c99c3fd2b6b28373aa3b9ce1a9dca9],
                            [0xb9757f57200d1372a46e726e18f7794fb49b80d3d7472edfeaa0cb272c616ef07d7b74c0e4ff8efbfba63581cb4ec75b, 0xbb890c96020c6d39ebb6771145bf1a58, 0x11bae225d403c21117777b7652f676ec],
                            [0xc7116df98e7b067b44c82b4b366c7139bf30c69dce85e9196583b2be58fb9e35bce66ed8c4f701047e60d78c92ce695f, 0x7e888fd260e36239afc5b1018615496e, 0xcb9fc38c458b47b9005174ec363b1323],
                            [0xbbe7a00d5a88e6424685e3bf80fd4c2304bd185ec1252dd091383dd767108ecf75e058050d0fb128f12444773f4945f3, 0x0018876fbc8045c93ae88d93a00c8bed, 0x3b26b6fdbb11dceb11097cd8cf5617f1],
                            [0xdc64089f3475eebe5837f0f20cb0b4f81e6d466465150680b29ca04cbade8b6253eb10adc71e2a49730b4af2493a10bc, 0xc9880d0b7bb76b80150a575d0882fa18, 0x62448d47cfa6a240e566239b42f63aa1],
                            [0x779e71a02052ecc491059fff18604d2c4cfcb051af3c806c6ee62df809220cd321185655699bba3f4970ee488ba83f8d, 0x4b3eadd0170106ad78caadedc9bfc922, 0x887d99075ab3e53abad55f7758f5d700],
                            [0x8452c1cce6b3035e33bf994b3d7f2e372692303e46a065888f86a4871171b6d4d658ad3160ba73a6703c94566a01faf3, 0x238b4a35e94860c74c10cd92b216f990, 0x61297728db3e1a3f688e671c7a7c91d1]]        

        for test_vector in test_vec_128_384:
            test_key = test_vector[0]    
            test_plaintext = test_vector[1]
            test_ciphertext = test_vector[2]
            p = SkinnyCipher(test_key, 384, 128) 
            d = p.encrypt(test_plaintext)
            w = p.decrypt(test_ciphertext)
            assert d == test_ciphertext
            assert w == test_plaintext

class TestCipherInitialization:
    not_ints = [6.22, 'hello', bytearray(b'stuffandbytes'), bytearray([12, 34, 0xAA, 00, 0x00, 34]), '0x1234567']

    def test_bad_plaintext_skinny(self):
        for bad_plain in self.not_ints:
            with pytest.raises(TypeError):
                t = SkinnyCipher(0)
                t.encrypt(bad_plain)

    def test_bad_ciphertext_skinny(self):
        for bad_crypt in self.not_ints:
            with pytest.raises(TypeError):
                t = SkinnyCipher(0)
                t.encrypt(bad_crypt)


    def test_bad_keys_skinny(self):
        for bad_key in self.not_ints:
            with pytest.raises(TypeError):
                SkinnyCipher(bad_key)

    def test_bad_counters_skinny(self):
        for bad_counter in self.not_ints:
            with pytest.raises(TypeError):
                SkinnyCipher(0, counter=bad_counter)

    def test_bad_ivs_skinny(self):
        for bad_iv in self.not_ints:
            with pytest.raises(TypeError):
                SkinnyCipher(0, init=bad_iv)

    not_block_modes = [7.1231, 'ERT', 11]

    def test_bad_modes_skinny(self):
        for bad_mode in self.not_block_modes:
            with pytest.raises(ValueError):
                SkinnyCipher(0, mode=bad_mode)

    not_block_sizes = [10, 'steve', 11.8]

    def test_bad_blocksizes_skinny(self):
        for bad_bsize in self.not_block_sizes:
            with pytest.raises(KeyError):
                SkinnyCipher(0, block_size=bad_bsize)

    not_key_sizes = [100000, 'eve', 11.8, 127]

    def test_bad_keysize_skinny(self):
        for bad_ksize in self.not_key_sizes:
            with pytest.raises(KeyError):
                SkinnyCipher(0, key_size=bad_ksize)