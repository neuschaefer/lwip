#!/usr/bin/env python3
# This script can be used to convert between the different formats (see -t and -f options):
#
# type 1: single packets, as understood by ./lwip_fuzz
# type 2: multiple packets, as understood by ./lwip_fuzz2
# type 3: multiple packets, as understood by ./lwip_fuzz3
# text: a simple text representation, with one packet per line
# pcap: the PCAP format
#
import argparse, sys

class Packet:
    def __init__(self, data, delay=1):
        self.data = bytes(data)
        self.delay = int(delay)

    def __repr__(self):
        return f'{self.__class__.__name__}({len(self.data)} bytes)'

    def to_text(self):
        return f'{self.delay:f} {self.data.hex()}'

    @classmethod
    def from_text(self, text):
        t, *d = text.split(' ')
        if type(d) == list:
            d = ''.join(d)
        return self(bytes.fromhex(d), float(t))

def trim_len(x):
    return min(x & 0x7ff, 1514)

def iter_type2(data):
    try:
        o = 0
        while o < len(data):
            pk_len = trim_len(int.from_bytes(data[o:o+2], 'big'))
            o += 2

            pk = data[o:o+pk_len]
            o += pk_len

            yield Packet(pk)
    except:
        pass

def iter_type3(data):
    try:
        o = 0
        while o < len(data):
            delay = int.from_bytes(data[o:o+4], 'big')
            o += 4

            pk_len = trim_len(int.from_bytes(data[o:o+2], 'big'))
            o += 2

            pk = data[o:o+pk_len]
            o += pk_len

            yield Packet(pk, delay)
    except:
        pass

class Multi:
    def __init__(self, pk = []):
        self.pk = []
        self.pk += pk

    def __repr__(self):
        total = sum([len(pk.data) for pk in self.pk])
        return f'{self.__class__.__name__}({len(self.pk)} packets, {total} bytes total)'

    def append(self, pk):
        self.pk.append(pk)

    def to_text(self):
        return '\n'.join([pk.to_text() for pk in self.pk]) + '\n'

    @classmethod
    def from_text(self, text):
        if type(text) == bytes:
            text = text.decode('utf-8')
        m = self()
        for line in text.splitlines():
            if line:
                m.append(Packet.from_text(line))
        return m

    @classmethod
    def from_type1(self, data):
        return self([Packet(data)])

    @classmethod
    def from_type2(self, data):
        m = self()
        for pk in iter_type2(data):
            m.append(pk)
        return m

    @classmethod
    def from_type3(self, data):
        m = self()
        for pk in iter_type3(data):
            m.append(pk)
        return m

    def write_type1(output, index):
        output.write(self.pk[index].data)

    def write_type2(self, output):
        for pk in self.pk:
            output.write(len(pk.data).to_bytes(2, 'big'))
            output.write(pk.data)

    def write_type3(self, output):
        for pk in self.pk:
            output.write(pk.delay.to_bytes(4, 'big'))
            output.write(len(pk.data).to_bytes(2, 'big'))
            output.write(pk.data)

    def write_pcap(self, output):
        HEADER = [
                0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00
        ]
        output.write(bytes(HEADER))
        time = 0 # time is in milliseconds
        for i, pk in enumerate(self.pk):
            output.write(int(time / 1e3).to_bytes(4, 'little'))  # seconds
            output.write(int(time / 1e3 * 1e3).to_bytes(4, 'little'))  # microseconds
            output.write(len(pk.data).to_bytes(4, 'little'))
            output.write(len(pk.data).to_bytes(4, 'little'))
            output.write(pk.data)
            time = (time + pk.delay) & 0xffffffff

if __name__ == '__main__':
    # Argument parsing
    parser = argparse.ArgumentParser(description='Convert between different packet formats used in fuzzing lwIP')
    parser.add_argument('input', nargs='?', help='input file', type=argparse.FileType('rb'), default=sys.stdin)
    parser.add_argument('output', nargs='?', help='output file', type=argparse.FileType('wb'), default=sys.stdout)
    parser.add_argument('-f', '--from', help='input file type (1, 2, 3, text)', default='2')
    parser.add_argument('-t', '--to', help='output file type (1, 2, 3, text, pcap)', default='text')
    parser.add_argument('--index', help='packet index, when converting to type 1', type=int, default=0)
    args = parser.parse_args()

    # Argument validation
    from_type = getattr(args, 'from')
    to_type = args.to
    if not from_type in ['1', '2', '3', 'text']:
        parser.error(f'unknown input file type "{from_type}"')
    if args.input == sys.stdin and from_type != 'text':
        parser.error(f'please provide an input filename for input types other than text')

    if not to_type in ['1', '2', '3', 'text', 'pcap']:
        parser.error(f'unknown output file type "{args.to}"')
    if args.output == sys.stdout and to_type != 'text':
        parser.error(f'please provide an output filename for output types other than text')

    # Input
    if from_type == 'text':
        m = Multi.from_text(args.input.read())
    elif from_type == '1':
        m = Multi.from_type1(args.input.read())
    elif from_type == '2':
        m = Multi.from_type2(args.input.read())
    elif from_type == '3':
        m = Multi.from_type3(args.input.read())

    # Output
    if to_type == 'text':
        if args.output == sys.stdout:
            args.output.write(m.to_text())
        else:
            args.output.write(m.to_text().encode('utf-8'))
    elif to_type == '1':
        m.write_type1(args.output, args.index)
    elif to_type == '2':
        m.write_type2(args.output)
    elif to_type == '3':
        m.write_type3(args.output)
    elif to_type == 'pcap':
        m.write_pcap(args.output)
    args.output.flush()
