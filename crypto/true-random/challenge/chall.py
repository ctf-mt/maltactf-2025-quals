from qiskit.circuit.random import random_circuit
from qiskit.quantum_info import Operator
from qiskit.quantum_info import Statevector
from numpy import array, save
from math import log2
import random
random = random.SystemRandom()
flag = open("flag.txt", "r").read().strip()
flag_len = len(flag)*8
assert flag_len == 256
depth = 10
qubits = int(log2(flag_len))

flag_bits = [int(bit) for bit in ''.join(format(ord(c), '08b') for c in flag)]



def random_pair(op):
    otp_key = [random.choice([0,1]) for _ in range(flag_len)]
    i = Statevector(otp_key)
    f = i.evolve(op)
    enc = array([flag_bits[i] ^ otp_key[i] for i in range(flag_len)])
    return array([enc, f.data])

ops = []
for _ in range(13):
    qc = random_circuit(qubits, depth, measure=False)
    op = Operator(qc)
    ops.append(op)

sets = 256
data = array([random_pair(random.choice(ops)) for _ in range(sets)])
save("enc.npy", data)
