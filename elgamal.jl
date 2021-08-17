#!/usr/bin/env julia

using Random

#=
a^b (mod n) using the method of repeated squares.

The key here is that every integer can be written as a sum of powers of 2 (binary numbers)
and that includes the exponent. By repeated squaring we get a raised to a power of 2. Also
recall that a^b * a^c = a^(b + c), so rather than adding we multiply since we are dealing
with the exponent.
=#

function powerMod(a, d, n)
    v = 1 # Value
    p = a # Powers of a
    while d > 0
        if isodd(d) # 1 bit in the exponent
           v = (v * p) % n
        end
        p = p^2 % n # Next power of two
        d >>>= 1
    end
    v
end

#=
Greatest common divisor, Euclidean version.
=#

function gcd(a, b)
    while b ≠ 0
        a, b = b, a % b
    end
    a
end

#=
Witness loop of the Miller-Rabin probabilistic primality test.
=#

function witness(a, n)
    u, t = n - 1, 0
    while iseven(u) # n = u * 2^t + 1
        t += 1   # Increase exponent
        u >>>= 1 # Decrease the multiplier
    end
    x = powerMod(a, u, n)
    for i in 1:t
        y = powerMod(x, 2, n)
        if y == 1 && x ≠ 1 && x ≠ n - 1
            return true
        end
        x = y
    end
    x ≠ 1
end

#=
Miller-Rabin probabilistic primality test: the chance of being wrong is ≈ 1/4 each pass through
the loop.
=#

function isPrime(n, k)
    if n < 2 || (n ≠ 2 && iseven(n)) # 0, 1, and even except for 2 are not prime.
        return false
    elseif n < 4 # 3 is prime
        return true
    end # We must test all others
    for j in 1:k
        a = rand(2:n - 2) # Choose a random witness
        if witness(a, n)
            return false
        end
    end
    true
end

#=
We need a random prime number in [low, high] and for now a 4^–100 chance of a composite is
good enough.
=#

function randomPrime(low, high)
    guess = 0 # Certainly not prime!
    while !isPrime(guess, 100)
        guess = rand(low:high) # Half will be even, the rest have Pr[prime] ≈ 1/log(N).
    end
    guess
end

#=
A safe prime is the one following a Sophie German prime. If prime(p) and prime(2p + 1) then
2p + 1 is a safe prime.
=#

function safePrime(low, high)
    p = randomPrime(low, high)
    while !isPrime(2 * p + 1,100)
        p = randomPrime(low, high)
    end
    return 2 * p + 1
end

#=
A generator must not be congruent to 1 for any of its powers that are
proper divisors of p – 1.  Since p is safe prime, there are only two:
2 and (p – 1) / 2. The number of such generators is 𝜑(p – 1).
=#

function generator(n, p)
    g = n
    q = (p - 1) ÷ 2
    while powerMod(g, 2, p) == 1 && powerMod(g, q, p) == 1
        g = g + 1
    end
    g
end

#=
Generate an efficient description of a cyclic group G of order p, with generator r.

Choose a random integer a ∊ {(p – 1)/2, ..., p − 1}

Compute b = r^a

The public key consists of the values (p, r, b)

The private key consists of the values (p, a)
=#

function keys(k)
    p = safePrime(big"2"^(k - 1), big"2"^k - 1)
    r = generator(big"2"^16 + 1, p)
    a = rand((p - 1) ÷ 2:p - 1)
    b = powerMod(r, a, p)
    ((p, a), (p, r, b))
end

#=
Choose a random k ∊ {1, ..., p – 2}

Compute 𝛾 = r^k (mod p)

Compute 𝛿 = m b^k (mod p)

The encrypted message is (𝛾, 𝛿)
=#

function encrypt(m, key)
    (p, r, b) = key
    k = rand(1:p - 2)
    𝛾 = powerMod(r, k, p)
    𝛿 = (m * powerMod(b, k, p)) % p
    (𝛾, 𝛿)
end

#=
The decrypted message is 𝛿 𝛾^(p – 1 – a) (mod p)
=#

function decrypt(m, key)
    (p, a) = key
    (𝛾, 𝛿) = m
    (powerMod(𝛾, p - 1 - a, p) * 𝛿) % p
end

function encode(s)
    sum::BigInt = 0
    pow::BigInt = 1
    for c in s
        sum += pow * (0xAA ⊻ BigInt(c))
        pow *= 256
    end
    sum
end

#=
Transform a BigInt back into a string, subtracting off the 0xAA. We treat it as a base-256
integer and just pull off the digits.
=#

function decode(n)
    s = ""
    while n > 0
        s = s * Char(0xAA ⊻ (n % 256))
        n ÷= 256
    end
    s
end

print("How many bits? ")

bits = parse(Int64, readline())

(prv, pub) = keys(bits)

println("pub = $pub")
println("prv = $prv")

print(">> ")
for m in eachline()
    c = encrypt(encode(m), pub); println("En[$m] = $c")
    t = decode(decrypt(c, prv)); println("De[$c] = $t")
    print(">> ")
end
