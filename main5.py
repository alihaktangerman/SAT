import sympy, random, math, functools, operator, typing
class GoldwasserMicaliEncrytedType:
    def __init__(self, c): self.c = tuple(c for c in c)
    def __str__(self): return functools.reduce(operator.add, (f"c[{i}]: " + str(self.c[i]) + "\n" for i in range(len(self.c))))
    def __iter__(self): for c in self.c: yield c
class GoldwasserMicaliKey: pass
class GoldwasserMicaliPrivateKey(GoldwasserMicaliKey):
    def __init__(self): self.p, self.q = tuple(sympy.randprime(2 << 256, 2 << 288) for _ in range(2))
    def __call__(self, c: GoldwasserMicaliEncrytedType) -> typing.Tuple[int]: return tuple(int(sympy.legendre_symbol(c, self.p) != 1 or sympy.legendre_symbol(c, self.q) != 1) for c in c)
class GoldwasserMicaliPublicKey(GoldwasserMicaliKey):
    def __init__(self, private_key: GoldwasserMicaliPrivateKey):
        self.n = private_key.p * private_key.q
        while math.gcd(x := random.randrange(1, self.n), self.n) != 1 or sympy.legendre_symbol(x, private_key.p) != -1 or sympy.legendre_symbol(x, private_key.q) != -1: pass
        self.x = x
    def __call__(self, m: typing.Tuple[int]): return GoldwasserMicaliEncrytedType(pow((f := lambda: y if math.gcd(y := random.randrange(1, self.n + 1), self.n) == 1 else f())(), 2, self.n) * pow(self.x, m, self.n) % self.n for m in m)
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
class BenalohKeyGenerator:
    def __find_pqr(self):
        r = sympy.randprime(2 << 3, 2 << 5)
        p = r ** 8 + 1
        while math.gcd(r, (p - 1) // r) - 1 or not sympy.isprime(p): p += r
        while math.gcd(q := sympy.randprime(2 << 128, 2 << 144) - 1, r) - 1: pass
        return p, q, r
class BenalohPublicKey:
    def __init__(self, privatekey):
        self.n, self.y, self.r = privatekey.n, privatekey.y, privatekey.r
    def __call__(self, m):
        while math.gcd(u := random.randrange(1, self.n), self.n) != 1: pass
        return BenalohEncryptedType(pow(self.y, m, self.n)) #randomization failed
class BenalohPrivateKey:
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
#27 ekim 2022

class NaccacheSternEncryptedType:
    pass
class NaccacheSternKeyGenerator:
    def __init__(self, k):
        self.k = k
        self.primes = tuple(sympy.randprime(2 << 5, 2 << 10) for _ in range(k))
    def __find_pq(self, u, v):
        while True:
            a, b = tuple(random.randrange(2 << 309, 2 << 310) for _ in range(2))
            if sympy.isprime(a) and sympy.isprime(b):
                if sympy.isprime(2 * a * u + 1) and sympy.isprime(2 * b * v + 1):
                    for prime1 in self.primes[:self.k >> 1]:
                        if (2 * a * u - 1) % prime1 == 0:
                            if math.gcd(prime1, (2 * a * u - 1) // prime1) == 1 and math.gcd(prime1, 2 * b * v - 1) == 1:
                                for prime2 in self.primes[self.k >> 1:]:
                                    if (2 * b * v - 1) % prime2 == 0:
                                        if math.gcd(prime2, (2 * b * v - 1) // prime2) == 1 and math.gcd(prime2, 2 * a * u - 1) == 1:
                                            break
        return 2 * a * u + 1, 2 * b * v + 1
    def __find_g(self, n):
        while math.gcd(g := random.randrange(2, n)) - 1: pass
        return g
    def __call__(self):
        p, q = self.__find_pq()
        n = p.q
        phi = n - p - q + 1
        g = self.__find_g(n)
class NaccacheSternPublicKey:
    pass
class NaccacheSternPrivateKey:
    pass

class PaillierPublicKey:
    def __init__(self, n, g):
        self.n, self.g = n, g
    def __str__(self):
        return f"n: {self.n}\ng: {self.g}"
class PaillierPublicKey:
    def __init__(self, n, g):
        self.n, self.g = n, g
    def __str__(self):
        return f"n: {self.n}\ng: {self.g}"
class PaillierPrivateKey:
    def __init__(self, l):
        self.l = l
    def __str__(self):
        return f"l: {self.l}"
class PaillierKeyGenerator:
    def __init__(self, k):
        self.k = k
    def __find_g(self, n):
        return n + 1
    def __call__(self):
        p, q = tuple(sympy.randprime(1 << (self.k-1), 1 << self.k) for _ in range(2))
        n = p * q
        l = n - p - q + 1
        g = self.__find_g(n)
        return PaillierPublicKey(n, g), PaillierPrivateKey(l)
class PaillierEncryptor:
    def __find_u(self, n):
        while math.gcd(n, u := random.randrange(1, n)) != 1: pass #n**2 değil n
        return u
    def __call__(self, enc_key, m): #iyi gözüküyor
        u = self.__find_u(enc_key.n)
        c = pow(enc_key.g, m, enc_key.n**2) * pow(u, enc_key.n, enc_key.n**2) % enc_key.n**2
        return PaillierEncryptedType(c)
class PaillierDecryptor:
    def __dlfp(self, c, l, n):
        z = pow(c, l, n**2)
        return (z - 1) // n
    def __call__(self, enc_key, dec_key, enc_obj): #iyi gözüküyor
        m = self.__dlfp(enc_obj.c, dec_key.l, enc_key.n) * pow(dec_key.l, -1, enc_key.n) % enc_key.n
        return m
class PaillierEncryptedType:
    def __init__(self, c):
        self.c = c
    @classmethod
    def __find_u(cls):
        while math.gcd(cls.enc_key.n, u := random.randrange(1, cls.enc_key.n)) != 1: pass #n**2 değil n, kötü oop
        return u
    def rerandomize(self):
        u_prime = PaillierEncryptedType.__find_u()
        self.c = self.c * pow(u_prime, PaillierEncryptedType.enc_key.n, PaillierEncryptedType.enc_key.n**2) % PaillierEncryptedType.enc_key.n**2
    def __add__(self, other):
        eo = PaillierEncryptedType(self.c * other.c)
        eo.rerandomize()
        return eo
    def __sub__(self, other): #sonuç negatifse cortluyor.
        eo = PaillierEncryptedType(self.c * pow(other.c, -1, PaillierEncryptedType.enc_key.n**2) % PaillierEncryptedType.enc_key.n**2)
        eo.rerandomize()
        return eo
    def __str__(self):
        return f"c: {self.c}"
kg = PaillierKeyGenerator(128)
ek, dk = kg()
PaillierEncryptedType.enc_key = ek
print(ek)
print(dk)
er, dr = PaillierEncryptor(), PaillierDecryptor()
eo1 = er(ek, 2030)
eo2 = er(ek, 119119119)
do = dr(ek, dk, eo1 + eo2)
print(do)
print(eo1)
print(dr(ek, dk, eo1))
eo1.rerandomize()
print(eo1)
print(dr(ek, dk, eo1))
do2 = dr(ek, dk, eo2 - eo1)
print(do2)
#bir class (instance of class değil) ancak bir key için geçerli
#metaclass gibi bir şey lazım bence
#ama çözemedim
#bütün bu dediklerimin amacı encrypted object size ını 2/3 üne düşürmek (yaklaşık)
#yoksa iş kolay

class DamgardJurikPublicKey:
    def __init__(self, n, g, s):
        self.n = n
        self.g = g
        self.s = s
class DamgardJurikPrivateKey:
    def __init__(self, d):
        self.d = d
class DamgardJurikKeyGenerator:
    def __init__(self, bitlength, s):
        self.bitlength = bitlength
        self.s = s
    def __find_pq(self):
        return (sympy.randprime(1<<self.bitlength-1, 1<<self.bitlength) for _ in range(2))
    def __find_jx(self, n):
        while math.gcd(j:=random.randrange(1, n**self.s), n) != 1 or math.gcd(x := random.randrange(1, n), n) != 1: pass
        return j, x
    def __find_g(self, n, j, x):
        g = pow(1+j, self.s, n**(self.s+1)) * x % n**(self.s+1)
        return g
    def __find_d(self, n, l): #very bad
        print(f"__find_d speaking: l == {l}")
        while (d:=random.randrange(l,n) % l) != 0 or math.gcd(d, n) != 1:
            pass
            print(f"failed d: {d}")
        print("find_d terminated")
        return d
    def __call__(self):
        p, q = self.__find_pq()
        n = p * q
        l = n - p - q + 1
        j, x = self.__find_jx(n)
        g = self.__find_g(n, j, x)
        d = self.__find_d(n, l)
        return DamgardJurikPublicKey(n, g, self.s), DamgardJurikPrivateKey(d)
class DamgardJurikEncryptedType:
    def __init__(self, c):
        self.c = c
class DamgardJurikEncryptor:
    def __find_u(self, n):
        while math.gcd(u := random.randrange(1, n), n) != 1: pass
        print("line 248 terminated")
        return u
    def __call__(self, m, enc_key: DamgardJurikPublicKey):
        u = self.__find_u(enc_key.n)
        c = pow(enc_key.g, m, enc_key.n**(enc_key.s+1)) * pow(u, enc_key.n**enc_key.s, enc_key.n**(enc_key.s+1)) % enc_key.n**(enc_key.s+1)
        return DamgardJurikEncryptedType(c)
class DamgardJurikDecryptor:
    def __ldj(self, c, n, j):
        z = c % n**(j+1)
        u = (z-1)//n
        return u
    def __dlfdj(self, c, n, s):
        i = 0
        for j in range(1, s+1):
            h1 = self.__ldj(c, n, j)
            h2 = i
            print(f"outer loop j: {j}")
            for k in range(2, j+1):
                i -= 1
                h2 %= n**j
                h1 -= h2*(pow(h2, n**j, n**(k-1)))//math.factorial(k)
                h1 %= n**j
            i = h1
        print("__dljdj terminated")
        return i
    def __call__(self, enc_key: DamgardJurikPublicKey, dec_key: DamgardJurikPrivateKey, enc_obj: DamgardJurikEncryptedType):
        ntps = enc_key.n**enc_key.s
        print("call received")
        a = pow(enc_obj.c, dec_key.d, ntps*enc_key.n)
        j = self.__dlfdj(a, enc_key.n, enc_key.s)
        print(f"g: {enc_key.g}")
        b = pow(enc_key.g, dec_key.d, enc_key.n**(enc_key.s+1))
        jp = self.__dlfdj(b, enc_key.n, enc_key.s)
        print(f"b: {b}")
        print(f"jp: {jp}")
        jpp = pow(jp, -1, ntps)
        return j * jpp
kg = DamgardJurikKeyGenerator(4, 5)
ek, dk = kg()
er, dr = DamgardJurikEncryptor(), DamgardJurikDecryptor()
eo1 = er(5, ek)
print(dr(ek, dk, eo1))
