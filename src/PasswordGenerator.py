import hashlib, binascii
import re
from random import randint
from copy import deepcopy
import datetime
from enum import IntEnum

class CHARACTER_TYPE(IntEnum):
    LOWER = 0,
    UPPER = 1,
    NUMERIC = 2,
    SPECIAL = 3

    @staticmethod
    def tips():
        return ['Lowercase characters ( e.g. abcdef )',
                'Uppercase characters ( e.g. ABCDEF )',
                'Numbers ( e.g. 123456 )',
                'Symbols ( {} )'.format(''.join(CHARACTER_TYPE._special_characters()))]
    @staticmethod
    def type(c):
        for ct in CHARACTER_TYPE:
            if c in ct.char_list():
                return ct
        return None
    def char_list(self):
        if self in [CHARACTER_TYPE.LOWER, CHARACTER_TYPE.UPPER, CHARACTER_TYPE.NUMERIC]:
            start, end = self._start_end_characters()
            return [chr(i) for i in range(ord(start), ord(end)+1)]
        elif self == CHARACTER_TYPE.SPECIAL:
            return CHARACTER_TYPE._special_characters()
        else:
            raise Exception('CHARACTER_TYPE not recognised')
    # private methods
    @staticmethod
    def _special_characters():
        return ['&', '@', '!', '=', '+', '-', '?']
    def _start_end_characters(self):
        if self == CHARACTER_TYPE.NUMERIC:
            return '0', '9'
        elif self == CHARACTER_TYPE.LOWER:
            return 'a', 'z'
        elif self == CHARACTER_TYPE.UPPER:
            return 'A', 'Z'
        else:
            raise Exception('No start/end character for CHARACTER_TYPE {}'.format(self.name))

# OUTPUT_TYPE and OUTPUT_TYPE_EXTENDED could both inherit from a base class, but there is no such need here in python.
class OUTPUT_TYPE(IntEnum):
    # numbering 0/1/2 defined from Passveurd plist. do not change
    ALPHANUMERIC = 0
    NUMERIC = 1
    ALPHANUMERICPLUS = 2

    def is_extended(self):
        return False
    def generate_character(self, idx):
        '''
        return a character if accepted, None otherwise
        '''
        if self == OUTPUT_TYPE.NUMERIC:
            accepted_char = '\d'
        elif self == OUTPUT_TYPE.ALPHANUMERIC:
            accepted_char = '[^\W_]'
        elif self == OUTPUT_TYPE.ALPHANUMERICPLUS:
            accepted_char = '[\w&@!=\+\-\?]'
        else:
            raise Exception('Non-supported OUTPUT_TYPE Enum{}'.format(self.value))
        c = chr(idx)
        if re.match(accepted_char, c, re.ASCII) is not None:
            return c
        return None

class OUTPUT_TYPE_EXTENDED:
    def __init__(self, character_types):
        '''
        define set of allowed characters (lower/upper/numeric/special)
        '''
        self.name = 'EXTENDED'
        self.character_types = character_types
        self.characters = []
        for ct in character_types:
            self.characters += ct.char_list()
        self.max_num_characters = len(self.characters)

    @classmethod
    def NumericFast(cls):
        return cls([CHARACTER_TYPE.NUMERIC])

    # comparison operator 
    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def is_extended(self):
        return True
    def generate_character(self, idx):
        '''
        return a character if accepted, None otherwise
        '''
        if idx >= self.max_num_characters:
            raise Exception('Unexpected index, must be smaller than {}'.format(self.max_num_characters))
        return self.characters[idx]

class RC4():
    '''
    stream cypher
    '''
    def __init__(self, dk):
        drop = 378 if dk[-1] & 1 else 247
        # key set up
        self.key = [i for i in range(256)]
        j = 0
        for i in range(256):
            j = (j + self.key[i] + dk[i % len(dk)]) % 256;
            # swap
            self.key[i], self.key[j] = self.key[j], self.key[i]

        # initialize cypher indices
        self.idx_i = 0
        self.idx_j = 0
        for k in range(-drop, 0):
            self.generate_next()
    def generate_next(self, max_num=None):
        if max_num is not None:
            if max_num > 256:
                max_num = 256
            if max_num < 1:
                raise Exception('Maximum number provided must be greater or equal to 1')
        while True:
            # Encryption
            self.idx_i = (self.idx_i + 1) % 256
            self.idx_j = (self.idx_j + self.key[self.idx_i]) % 256
            # swap
            self.key[self.idx_i], self.key[self.idx_j] = self.key[self.idx_j], self.key[self.idx_i]

            idx = 0 ^ self.key[(self.key[self.idx_i] + self.key[self.idx_j]) % 256]
            if max_num is None:
                return idx
            if idx < (256//max_num) * max_num:
                return idx % max_num

class PasswordMetaData():
    def __init__(self, note='', category=None, last_modified=datetime.date.today()):
        self.note=note
        self.category=category
        self.last_modified=last_modified

    def __eq__(self, other):
        return (self.category == other.category and
                (((not self.note) and (not other.note)) or (self.note == other.note)))

class PasswordGenerator():
    def __init__(self, offset, pass_len, hash_name, iter, dk_len, metadata):
        self.offset = offset
        self.pass_len = pass_len
        self.hash_name = hash_name
        self.iter = iter
        self.dk_len = dk_len
        self.metadata = metadata

    def generate_password(self, password):
        '''
        generates a password using PBKDF2 algorithm
        '''
        salt, pw = self._get_PBKDF2_salt_and_pass(password)
        dk = hashlib.pbkdf2_hmac(self.hash_name, pw.encode(), salt.encode(), self.iter, self.dk_len)
        return self._get_generated_password_from_derived_key(dk)[self.offset:self.offset+self.pass_len]

class Passveurd(PasswordGenerator):
    def __init__(self, domain, version, pass_len, output_type, offset=0, hash_name='sha1', iter=10000, dk_len=32, metadata=PasswordMetaData()):
        '''
        Passveurd password generator from domain and version. The algorithm generates a password in 2 steps
        - PBKDF2 (generates a 8-bit binary vector)
        - RC4 stream cypher, generates the actual password, based on the derived key generated by PBKDF2.
        derived key doesn't need to be > 256
        '''
        PasswordGenerator.__init__(self, offset, pass_len, hash_name, iter, dk_len, metadata)
        self.domain = domain
        self.version = int(version)
        self.output_type = output_type
        if output_type.is_extended():
            if pass_len < 4:
                raise Exception('Password length with EXTENDED output type should be greater or equal to 4')
            if (not hasattr(output_type, 'characters')) or len(output_type.characters) == 0:
                raise Exception('must provide a set of allowed characters in extended mode')

    # 100000 gives enough matches for the PIN number to avoid providing information for the first time the pattern is matched
    def generate_PIN_config(self, password, pin, max_offset=100000):
        if self.output_type != OUTPUT_TYPE_EXTENDED.NumericFast() or self.pass_len > 4:
            raise Exception('PIN key config generation only supported for EXTENDED type with NUMERIC character types only, and pass length with at most 4 digits')
        target_len = len(pin)

        new_passveurd = deepcopy(self)
        new_passveurd.offset = 0
        new_passveurd.pass_len = max_offset + target_len
        not_found = True

        regex = re.compile('({})'.format(pin))
        while not_found:
            # random version number
            new_passveurd.version = randint(1, 2**32)
            dk = new_passveurd.generate_password(password)
            offsets_found = [m.start() for m in regex.finditer(dk)]
            if len(offsets_found) > 0:
                rnd_idx = randint(0, len(offsets_found)-1)
                # random pick for the match
                new_passveurd.offset = offsets_found[rnd_idx]
                new_passveurd.pass_len = target_len
                return new_passveurd, len(offsets_found)

    def get_key(self):
        return self.domain

    def is_legacy(self):
        return (self.offset==0 and self.hash_name=='sha1' and self.iter==10000 and self.dk_len==32 and
                not self.output_type.is_extended())

    def _get_PBKDF2_salt_and_pass(self, password):
        salt = password
        pw = '{}{}'.format(self.domain, self.version)
        return salt, pw

    def __eq__(self, other):
        return (self.__dict__ == other.__dict__)

    def _get_generated_password_from_derived_key(self, dk):
        '''
        generate a stream of from a derived key generated through PBKDF2 algorithm
        PBKDF2 generates a binary (vector of 0-255 integers)
        if EXTENDED, ensure that at least one character of each character type has been generated
        '''
        idx = 0
        cypher = []
        output = []
        stream_cypher = RC4(dk)
        max_num_characters = self.output_type.max_num_characters if self.output_type.is_extended() else None
        while len(output) < self.pass_len+self.offset:
            c = self.output_type.generate_character(stream_cypher.generate_next(max_num_characters))
            if c is not None:
                output.append(c)
            idx += 1

        if self.output_type.is_extended():
            # check if all character types are represented, if not replace using stream_cypher
            generated_character_types = [CHARACTER_TYPE.type(c) for c in output]
            character_per_type = {ct: [idx for idx, c in enumerate(generated_character_types) if c == ct]
                                  for ct in self.output_type.character_types}
            available_characters = list(range(self.pass_len+self.offset))
            for ct in character_per_type:
                if len(character_per_type[ct]) > 0:
                    # define one protected character for each type according to cypher stream number generation
                    protected_char = character_per_type[ct][stream_cypher.generate_next(len(character_per_type[ct]))]
                    available_characters.remove(protected_char)

            for ct in character_per_type:
                if len(character_per_type[ct]) == 0:
                    # generate index of character to change, and remove from the list of available characters
                    replaced_character_index = available_characters[stream_cypher.generate_next(len(available_characters))]
                    available_characters.remove(replaced_character_index)
                    # replace character
                    ot_for_ct = OUTPUT_TYPE_EXTENDED([ct])
                    output[replaced_character_index] = ot_for_ct.generate_character(stream_cypher.generate_next(ot_for_ct.max_num_characters))
        return ''.join(output)

class CryptoPass(PasswordGenerator):
    def __init__(self, user_name, url, pass_len, metadata=PasswordMetaData()):
        PasswordGenerator.__init__(self, 0, pass_len, 'sha256', 5000, 25, metadata)
        self.user_name = user_name
        self.url = url

    def get_key(self):
        return '@'.format(self.user_name, self.url)

    def _get_PBKDF2_salt_and_pass(self, password):
        salt = '{}@{}'.format(self.user_name, self.url)
        pw = password
        return salt, pw

    def _get_generated_password_from_derived_key(self, dk):
        return binascii.b2a_base64(dk).decode()
