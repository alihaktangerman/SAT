import  sympy, random, math, functools, operator, typing
class GoldwasserMicaliEncrytedType:
    def __init__(self, c):
        self.c = tuple(c for c in c)
    def __str__(self):
        return functools.reduce(operator.add, (f"c[{i}]: " + str(self.c[i]) + "\n" for i in range(len(self.c))))
    def __iter__(self):
        for c in self.c: yield c
class GoldwasserMicaliKey:
    pass
class GoldwasserMicaliPrivateKey(GoldwasserMicaliKey):
    def __init__(self):
        self.p, self.q = tuple(sympy.randprime(2 << 256, 2 << 288) for _ in range(2))
    def __call__(self, c: GoldwasserMicaliEncrytedType) -> typing.Tuple[int]:
        return tuple(int(sympy.legendre_symbol(c, self.p) != 1 or sympy.legendre_symbol(c, self.q) != 1) for c in c)
class GoldwasserMicaliPublicKey(GoldwasserMicaliKey):
    def __init__(self, private_key: GoldwasserMicaliPrivateKey):
        self.n = private_key.p * private_key.q
        while math.gcd(x := random.randrange(1, self.n), self.n) != 1 \
                or sympy.legendre_symbol(x, private_key.p) != -1 or sympy.legendre_symbol(x, private_key.q) != -1: pass
        self.x = x
    def __call__(self, m: typing.Tuple[int]):
        return GoldwasserMicaliEncrytedType(pow((f := lambda: y if math.gcd(y := random.randrange(1, self.n + 1), self.n) == 1 else f())(), 2, self.n) * pow(self.x, m, self.n) % self.n for m in m)
sk = GoldwasserMicaliPrivateKey()
pk = GoldwasserMicaliPublicKey(sk)
print(pk((1, 0, 1)))
print(sk(pk((1, 0, 1, 1, 1, 0, 1, 1, 0, 0))))
class ElGamalEncryptedType: #yeni bir data type int gibi (en aşağıda havalı bir uygulaması var)
    def __init__(self, c1, c2):
        self.c1, self.c2 = c1, c2
    def __mul__(self, other): #çarpma operatörünü tanımlıyorum
        return ElGamalEncryptedType(self.c1 * other.c1, self.c2 * other.c2)
    def __str__(self):
        return "c1: " + str(self.c1) + "\n" + "c2: " + str(self.c2)
class ElGamalKey: #RSA de de göstermiştim aynısından faydalandım
    def find_pq(self):
        q = int(sympy.randprime(2 << 256, 2 << 288))
        p = q**8 + 1
        while not sympy.isprime(p): p += q
        return p, q
class ElGamalPublicKey(ElGamalKey):
    def __init__(self, private_key):
        self.p, self.q, self.g, self.h = private_key.p, private_key.q, private_key.g, private_key.h
    def __call__(self, m):
        r = random.randrange(0, self.q)
        return ElGamalEncryptedType(pow(self.g, r, self.p), m * pow(self.h, r, self.p) % self.p)
class ElGamalPrivateKey(ElGamalKey):
    def __init__(self):
        self.p, self.q = self.find_pq()
        y = random.randrange(2, self.p)
        self.g = pow(y, (self.p - 1) // self.q, self.p)
        self.x = random.randrange(2, self.q)
        self.h = pow(self.g, self.x, self.p)
    def __call__(self, c):
        c1, c2 = c.c1, c.c2
        u1 = pow(c1, self.x, self.p)
        return pow(u1, -1, self.p) * c2 % self.p
sk = ElGamalPrivateKey()
pk = ElGamalPublicKey(sk)
print(pk(110))
Bss1 = 20
Bss2 = 30
C1 = pk(Bss1)
C2 = pk(Bss2)
print(C1)
print(C2)
print(C1 * C2)
print(sk(C1 * C2)) #homomorphism

#highly incomplete
class BenalohEncryptedType:
    def __init__(self, c):
        self.c = c
    def __mul__(self, other):
        return BenalohEncryptedType(self.c * other.c % BenalohEncryptedType.n) #lacks reandomization
class BenalohKey:
    def find_pqr(self):
        r = sympy.randprime(2 << 3, 2 << 5)
        p = r ** 8 + 1
        while math.gcd(r, (p - 1) // r) - 1 or not sympy.isprime(p): p += r
        while math.gcd(q := sympy.randprime(2 << 128, 2 << 144) - 1, r) - 1: pass
        return p, q, r
class BenalohPublicKey(BenalohKey):
    def __init__(self, privatekey):
        self.n, self.y, self.r = privatekey.n, privatekey.y, privatekey.r
    def __call__(self, m):
        while math.gcd(u := random.randrange(1, self.n), self.n) != 1: pass
        return BenalohEncryptedType(pow(self.y, m, self.n)) #randomization failed
class BenalohPrivateKey(BenalohKey):
    def __init__(self):
        self.p, self.q, self.r = self.find_pqr()
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        while math.gcd(y := random.randrange(1, self.n), self.n) - 1 or not pow(y, self.phi // self.r, self.n) - 1: pass
        self.y = y
        BenalohEncryptedType.n = self.n
    def __call__(self, c):
        e = self.phi // self.r
        b = pow(self.y, -1, self.n)
        for i in range(1, self.r):
            if pow(pow(self.y, -i, self.n) * c.c, e, self.n) == 1: return i
sk = BenalohPrivateKey()
pk = BenalohPublicKey(sk)
print(sk(pk(4) * pk(9)))
